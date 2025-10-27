#!/usr/bin/env python3

# bcrypt_sim.py — Bcrypt Sim
# Bcrypt core wrapped in LiteX + Etherbone control.
#
# High-level:
# - Wishbone SRAM region (host-writable via Etherbone) stores all packets.
# - One AXI8 streamer reads from SRAM by (base,size) set over CSRs; 'start' kicks it.
# - AXI egress always-ready; bytes logged with Display (sync).
# - Packets can be built host-side (script) and written to SRAM.

import argparse

from migen import *

from litex.gen import *

from litex.build.generic_platform import *
from litex.build.sim              import SimPlatform
from litex.build.sim.config       import SimConfig
from litex.build.sim.verilator    import verilator_build_args, verilator_build_argdict

from litex.soc.integration.soc      import SoCRegion
from litex.soc.integration.soc_core import SoCMini
from litex.soc.integration.builder  import Builder
from litex.soc.integration.common   import get_mem_data
from litex.soc.interconnect         import stream, wishbone
from litex.soc.interconnect.csr     import CSRStorage, CSRStatus, AutoCSR

from liteeth.phy.model import LiteEthPHYModel

# IOs ----------------------------------------------------------------------------------------------

_io = [
    # Clk / Rst.
    ("sys_clk", 0, Pins(1)),
    ("sys_rst", 0, Pins(1)),

    # Ethernet (for Etherbone).
    ("eth_clocks", 0,
        Subsignal("tx", Pins(1)),
        Subsignal("rx", Pins(1)),
    ),
    ("eth", 0,
        Subsignal("source_valid", Pins(1)),
        Subsignal("source_ready", Pins(1)),
        Subsignal("source_data",  Pins(8)),

        Subsignal("sink_valid",   Pins(1)),
        Subsignal("sink_ready",   Pins(1)),
        Subsignal("sink_data",    Pins(8)),
    ),
]

# Platform -----------------------------------------------------------------------------------------

class Platform(SimPlatform):
    def __init__(self):
        SimPlatform.__init__(self, "SIM", _io)

# AXI8 Memory Streamer (WB SRAM-backed, range-driven) ----------------------------------------------

class AXI8WBStreamer(LiteXModule, AutoCSR):
    """
    Reads bytes from a 32-bit Wishbone SRAM (2nd async-read port) and streams on AXI-Stream(8).

    CSRs:
      - base  (RW, 32b): byte address
      - size  (RW, 32b): byte length
      - start (RW, 1b) : write 1 to arm; requires 0->1 edge to trigger
      - busy  (RO, 1b)
      - done  (RO, 1b): 1-cycle pulse at end (read to observe)

    Behavior:
      - Triggers once per rising edge on 'start'.
      - If software leaves start=1, it will NOT retrigger; write 0 then 1 next time.
    """
    def __init__(self, sram_mem, sram_size_bytes):
        # AXI-Stream OUT(8).
        self.source = stream.Endpoint([("data", 8)])

        # CSRs.
        self._base  = CSRStorage(32, name="base")
        self._size  = CSRStorage(32, name="size")
        self._start = CSRStorage(1,  name="start")  # SW writes 1 to request start
        self._busy  = CSRStatus (1,  name="busy")
        self._done  = CSRStatus (1,  name="done")   # pulse

        # 32-bit SRAM read port (async).
        rp = sram_mem.get_port(async_read=True)
        self.specials += rp

        # Byte addressing.
        addr_b  = Signal(32)
        end_b   = Signal(32)
        bsel    = Signal(2)
        data32  = Signal(32)
        is_last = Signal()

        self.comb += [
            rp.adr           .eq(addr_b[2:]),
            data32           .eq(rp.dat_r),
            bsel             .eq(addr_b[0:2]),
            is_last          .eq(addr_b == end_b),
        ]

        # Byte pick (LSB-first).
        byte_arr = Array([data32[8*i:8*(i+1)] for i in range(4)])
        self.comb += [
            self.source.data .eq(byte_arr[bsel]),
            self.source.last .eq(is_last),
        ]

        # Start edge detect.
        start_q = Signal(reset=0)
        start_p = Signal()  # 1 cycle on 0->1
        self.comb += start_p.eq(self._start.storage & ~start_q)
        self.sync += start_q.eq(self._start.storage)

        # Status.
        busy = Signal(reset=0)
        done = Signal(reset=0)
        self.comb += [
            self._busy.status.eq(busy),
            self._done.status.eq(done),
        ]

        # FSM.
        fsm = FSM(reset_state="IDLE")
        self.submodules += fsm

        fsm.act("IDLE",
            self.source.valid.eq(0),
            busy.eq(0),
            done.eq(0),
            If(start_p & (self._size.storage != 0),
                NextValue(addr_b, self._base.storage),
                NextValue(end_b,  self._base.storage + self._size.storage - 1),
                NextState("RUN")
            )
        )

        fsm.act("RUN",
            self.source.valid.eq(1),
            busy.eq(1),
            If(self.source.ready,
                If(is_last,
                    done.eq(1),
                    NextState("IDLE")
                ).Else(
                    NextValue(addr_b, addr_b + 1)
                )
            )
        )

# AXI8WBRecorder -----------------------------------------------------------------------------------

class AXI8WBRecorder(LiteXModule, AutoCSR):
    """
    Capture AXI-Stream(8) into a 32-bit Wishbone SRAM (.mem write port).

    CSRs:
      - base          (RW, 32b): byte address in capture SRAM.
      - size          (RW, 32b): byte limit (max bytes to write).
      - start         (RW, 1b) : 0->1 edge arms a capture run.
      - stop_on_last  (RW, 1b) : if 1, stop when s.last is observed (after writing the last byte).
      - busy          (RO, 1b) : 1 while capturing.
      - done          (RO, 1b) : 1-cycle pulse at end of a run.
      - count         (RO, 32b): number of bytes captured (latched at end).

    Notes:
      - Packs 4 bytes into a 32-bit word before write; also flushes partial word on stop.
      - For multiple packets, either pre-size "size" large enough OR capture per packet with stop_on_last=1.
    """
    def __init__(self, cap_mem, cap_size_bytes):
        # AXIS sink.
        self.sink = sink = stream.Endpoint([("data", 8)])

        # CSRs.
        self._base         = CSRStorage(32, name="base")
        self._size         = CSRStorage(32, name="size")
        self._start        = CSRStorage(1,  name="start")
        self._stop_on_last = CSRStorage(1,  name="stop_on_last", reset=1)
        self._busy         = CSRStatus (1,  name="busy")
        self._done         = CSRStatus (1,  name="done")
        self._count        = CSRStatus (32, name="count")

        # Write port (sync write) on 32-bit memory.
        wp = cap_mem.get_port(write_capable=True, we_granularity=0)  # whole-word write
        self.specials += wp

        # Latches/State.
        base_b   = Signal(32)
        size_b   = Signal(32)
        end_b    = Signal(32)
        addr_b   = Signal(32)   # current byte address
        count_b  = Signal(32)   # bytes written this run
        busy     = Signal(reset=0)
        done     = Signal(reset=0)

        # Byte packer.
        shreg    = Signal(32)
        bidx     = Signal(2)    # 0..3
        waddr    = Signal(32)   # word address (byte_addr >> 2)

        # Expose status.
        self.comb += [
            self._busy.status .eq(busy),
            self._done.status .eq(done),
            self._count.status.eq(count_b),
        ]

        # Start edge.
        start_q  = Signal(reset=0)
        start_p  = Signal()
        self.comb += start_p.eq(self._start.storage & ~start_q)
        self.sync += start_q.eq(self._start.storage)

        # Handshake.
        self.comb += sink.ready.eq(busy)  # accept while busy

        # Convenience.
        is_last_byte = Signal()
        self.comb += is_last_byte.eq(count_b == (size_b - 1))

        # Write helpers (registered one-cycle pulses).
        do_write = Signal()
        wdata    = Signal.like(shreg)
        waddr_n  = Signal.like(waddr)

        self.sync += [
            # Default write strobes low.
            do_write.eq(0),
            done.eq(0),

            If(~busy,
                # IDLE
                If(start_p & (self._size.storage != 0),
                    base_b .eq(self._base.storage),
                    size_b .eq(self._size.storage),
                    end_b  .eq(self._base.storage + self._size.storage - 1),
                    addr_b .eq(self._base.storage),
                    count_b.eq(0),
                    bidx   .eq(0),
                    waddr  .eq(self._base.storage[2:]),
                    shreg  .eq(0),
                    busy   .eq(1)
                )
            ).Else(
                # RUN
                If(sink.valid & sink.ready,
                    # Insert byte into shreg at position bidx (LSB-first).
                    shreg.eq(Cat(sink.data, shreg[8:32])),
                    bidx .eq(bidx + 1),
                    addr_b .eq(addr_b + 1),
                    count_b.eq(count_b + 1),

                    # Case A: packed 4 bytes -> write word.
                    If(bidx == 3,
                        do_write.eq(1),
                        wdata  .eq(Cat(sink.data, shreg[8:32])),
                        wp.dat_w.eq(Cat(sink.data, shreg[8:32])),
                        wp.adr  .eq(waddr),
                        waddr   .eq(waddr + 1)
                    ),

                    # Terminal conditions (after counting this byte):
                    If( is_last_byte | (self._stop_on_last.storage & sink.last),
                        # If not word-aligned, flush partial word too.
                        If(bidx != 3,
                            do_write.eq(1),
                            wdata  .eq(Cat(sink.data, shreg[8:32])),
                            wp.dat_w.eq(Cat(sink.data, shreg[8:32])),
                            wp.adr  .eq(waddr),
                            waddr   .eq(waddr + 1)
                        ),
                        busy.eq(0),
                        done.eq(1)
                    )
                )
            )
        ]


# Simulation SoC -----------------------------------------------------------------------------------

class SimSoC(SoCMini):
    def __init__(self, with_eth=True):
        platform     = Platform()
        sys_clk_freq = int(50e6)

        SoCMini.__init__(self, platform, sys_clk_freq,
            cpu_type  = None,
            uart_name = "sim",
        )
        self.comb += platform.trace.eq(1)
        self.crg = CRG(platform.request("sys_clk"))

        # --- Ethernet / Etherbone ---------------------------------------------------------------
        if with_eth:
            self.ethphy = LiteEthPHYModel(self.platform.request("eth"))
            self.add_etherbone(
                phy          = self.ethphy,
                ip_address   = "192.168.1.50",
                mac_address  = 0x10e2d5000001,
                buffer_depth = 255,
            )

        # --- Wishbone SRAM (host accessible over Etherbone) -------------------------------------
        # 64 KiB byte storage (but WB is 32-bit wide).
        sram_size = 64*1024
        self.stream_sram = wishbone.SRAM(sram_size)
        self.bus.add_region("stream_mem", SoCRegion(origin=0x4010_0000, size=sram_size, cached=False))
        self.bus.add_slave("stream_mem", self.stream_sram.bus)
        # Tap internal memory for a 2nd read port.
        mem = self.stream_sram.mem  # Memory(width=32, depth=sram_size//4)
        self.specials += mem

        # --- Bcrypt Wrapper ----------------------------------------------------------------------
        from gateware.bcrypt_wrapper import BcryptWrapper
        self.bcrypt = bcrypt = BcryptWrapper(self.platform,
            num_proxies     = 2,
            proxies_n_cores = [4, 4],
            proxies_dummy   = [0, 0],
            proxies_bitmap  = [0, 0],
        )
        self.platform.add_source("gateware/bcrypt_axis_8b.sv")
        self.bcrypt.add_sources()

        # --- AXI8 Streamer (CSR-controlled, reads from SRAM) ------------------------------------
        self.streamer = streamer = AXI8WBStreamer(mem, sram_size)
        self.add_csr("streamer")

        # AXI wiring: Streamer -> Wrapper IN; Wrapper OUT ready=1.
        self.comb += [
            bcrypt.sink.valid.eq(streamer.source.valid),
            bcrypt.sink.data .eq(streamer.source.data),
            bcrypt.sink.last .eq(streamer.source.last),
            streamer.source.ready.eq(bcrypt.sink.ready),
            bcrypt.source.ready.eq(1),
        ]

        # AXIS In Display (sync-only; ignored by synthesis).
        self.sync += If(bcrypt.sink.valid & bcrypt.sink.ready,
            Display("AXIS.In byte=0x%02x last=%d", bcrypt.sink.data, bcrypt.sink.last)
        )

        # AXIS Out Display (sync-only; ignored by synthesis).
        self.sync += If(bcrypt.source.valid & bcrypt.source.ready,
            Display("AXIS.Out byte=0x%02x last=%d", bcrypt.source.data, bcrypt.source.last)
        )

        # --- Capture SRAM (host-readable over Etherbone) ------------------------------------------
        cap_size = 64*1024
        self.cap_sram = wishbone.SRAM(cap_size)
        self.bus.add_region("cap_mem", SoCRegion(origin=0x4020_0000, size=cap_size, cached=False))
        self.bus.add_slave("cap_mem", self.cap_sram.bus)
        cap_mem = self.cap_sram.mem
        self.specials += cap_mem

        # --- AXI8 Recorder (bcrypt.source -> recorder) --------------------------------------------
        self.rec = rec = AXI8WBRecorder(cap_mem, cap_size)

        # Replace previous "wrapper OUT ready=1" with recorder hookup:
        self.comb += [
            rec.sink.valid.eq(self.bcrypt.source.valid),
            rec.sink.data .eq(self.bcrypt.source.data),
            rec.sink.last .eq(self.bcrypt.source.last),
            self.bcrypt.source.ready.eq(rec.sink.ready),
        ]

# Build / Main -------------------------------------------------------------------------------------

def sim_args(parser):
    verilator_build_args(parser)
    parser.add_argument("--no-eth", action="store_true", help="Disable Etherbone.")

def main():
    parser = argparse.ArgumentParser(description="Bcrypt Sim — Bcrypt core wrapped in LiteX (AXIS8, Etherbone).")
    sim_args(parser)
    args = parser.parse_args()
    verilator_kwargs = verilator_build_argdict(args)

    sim_config = SimConfig()
    sim_config.add_clocker("sys_clk", freq_hz=int(25e6))
    if not args.no_eth:
        # Enable UDP-based Ethernet model.
        sim_config.add_module("ethernet", "eth", args={"interface": "tap0", "ip": "192.168.1.100"})

    soc = SimSoC(with_eth=not args.no_eth)
    builder = Builder(soc, csr_csv="csr.csv", compile_software=False)
    builder.build(sim_config=sim_config, **verilator_kwargs)

if __name__ == "__main__":
    main()
