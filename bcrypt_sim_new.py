#!/usr/bin/env python3
# bcrypt_sim.py — Bcrypt Sim (simplified streamer / recorder)
#
#   • Wishbone SRAM (64 KiB) holds the *input* packet.
#   • SimpleAXI8Streamer streams the packet (kick → busy → done).
#   • SimpleAXI8Recorder captures the Bcrypt output (kick → busy → done, packs 4:1).
#   • Etherbone gives host access to SRAM and CSRs.
#
import argparse
from migen import *
from litex.gen import *
from litex.build.generic_platform import *
from litex.build.sim              import SimPlatform
from litex.build.sim.config       import SimConfig
from litex.build.sim.verilator import verilator_build_args, verilator_build_argdict
from litex.soc.integration.soc import SoCRegion
from litex.soc.integration.soc_core import SoCMini
from litex.soc.integration.builder import Builder
from litex.soc.interconnect import stream, wishbone
from litex.soc.interconnect.csr import CSRStorage, CSRStatus
from liteeth.phy.model import LiteEthPHYModel


# -------------------------------------------------------------------------
# Platform
# -------------------------------------------------------------------------
_io = [
    ("sys_clk", 0, Pins(1)),
    ("sys_rst", 0, Pins(1)),
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

class Platform(SimPlatform):
    def __init__(self):
        super().__init__("SIM", _io)


# -------------------------------------------------------------------------
# Simple AXI-8 Streamer (single-packet, kick-only)
# -------------------------------------------------------------------------
class SimpleAXI8Streamer(LiteXModule):
    def __init__(self, sram_mem, sram_size_bytes):
        self.source = stream.Endpoint([("data", 8)])

        # CSRs
        self.length = CSRStorage(32, reset=0)   # packet length in bytes
        self.kick   = CSRStorage(1, reset=0)
        self.busy   = CSRStatus(1)
        self.done   = CSRStatus(1)

        # Async read port
        rp = sram_mem.get_port(async_read=True)
        self.specials += rp

        addr     = Signal(32)  # byte address
        byte_sel = Signal(2)   # 0-3
        is_last  = Signal()

        self.comb += [
            rp.adr.eq(addr[2:]),
            byte_sel.eq(addr[0:2]),
            self.source.data.eq(rp.dat_r >> (8 * byte_sel)),
            Case(byte_sel, {
                0b00: self.source.data.eq(rp.dat_r[ 0: 8]),
                0b01: self.source.data.eq(rp.dat_r[ 8:16]),
                0b10: self.source.data.eq(rp.dat_r[16:24]),
                0b11: self.source.data.eq(rp.dat_r[24:32]),
            }),
            is_last.eq(addr == (self.length.storage - 1)),
            self.source.last.eq(is_last & self.source.valid),
        ]

        self.sync += If(self.source.valid, Display("0x%08x", rp.dat_r))

        # Kick edge detect
        kick_d = Signal()
        self.sync += kick_d.eq(self.kick.storage)
        start = self.kick.storage & ~kick_d

        # FSM
        fsm = FSM(reset_state="IDLE")
        self.submodules.fsm = fsm

        fsm.act("IDLE",
            self.source.valid.eq(0),
            self.busy.status.eq(0),
            If(start & (self.length.storage > 0),
                NextValue(addr, 0),
                NextState("RUN")
            )
        )
        fsm.act("RUN",
            self.source.valid.eq(1),
            self.busy.status.eq(1),
            If(self.source.ready,
                If(is_last,
                    self.done.status.eq(1),
                    NextState("IDLE")
                ).Else(
                    NextValue(addr, addr + 1)
                )
            )
        )
# -------------------------------------------------------------------------
# Simple AXI-8 Recorder – byte-write enable, fully synchronous status
# -------------------------------------------------------------------------
class SimpleAXI8Recorder(LiteXModule):
    """
    Captures an AXI-Stream(8) byte stream into a Wishbone SRAM.
    * One byte is written per valid cycle using the SRAM's byte-enable.
    * No packing, no flush, no Case() – the address and data are always
      driven; only the write-enable is gated.
    * count.status and done.status are updated with NextValue().
    """
    def __init__(self, cap_mem, cap_size_bytes):
        self.sink = stream.Endpoint([("data", 8)])

        # ---- CSRs -------------------------------------------------------
        self.kick  = CSRStorage(1, reset=0)
        self.busy  = CSRStatus (1)
        self.done  = CSRStatus (1)
        self.count = CSRStatus (32)

        # ---- SRAM write port (byte granularity) -------------------------
        wp = cap_mem.get_port(write_capable=True, we_granularity=8)
        self.specials += wp

        # ---- Internal state ---------------------------------------------
        byte_addr = Signal(32)   # current byte offset in the SRAM
        byte_cnt  = Signal(32)   # number of bytes captured this run

        # ---- Kick edge detection ----------------------------------------
        kick_d = Signal()
        self.sync += kick_d.eq(self.kick.storage)
        start = self.kick.storage & ~kick_d

        # ---- FSM --------------------------------------------------------
        fsm = FSM(reset_state="IDLE")
        self.submodules.fsm = fsm

        fsm.act("IDLE",
            self.sink.ready.eq(0),
            self.busy.status.eq(0),
            If(start,
                NextValue(self.done.status, 0),
                NextValue(byte_addr, 0),
                NextValue(byte_cnt,  0),
                NextState("RUN")
            )
        )
        self.comb += self.count.status.eq(byte_cnt)
        self.comb += wp.adr.eq(byte_addr[2:])

        fsm.act("RUN",
            self.sink.ready.eq(1),
            self.busy.status.eq(1),

            If(self.sink.valid,
                # ---- Write the incoming byte into the correct lane ----------
                Case(byte_addr[0:2], {
                    0b00 : [wp.dat_w[ 0: 8].eq(self.sink.data),  wp.we.eq(0b0001)],
                    0b01 : [wp.dat_w[ 8:16].eq(self.sink.data),  wp.we.eq(0b0010)],
                    0b10 : [wp.dat_w[16:24].eq(self.sink.data),  wp.we.eq(0b0100)],
                    0b11 : [wp.dat_w[24:32].eq(self.sink.data),  wp.we.eq(0b1000)],
                }),
                # ---- Advance counters ----------------------------------------
                NextValue(byte_addr, byte_addr + 1),
                NextValue(byte_cnt,  byte_cnt  + 1),

                # ---- End of packet -----------------------------------------
                If(self.sink.last,


                    NextValue(self.done.status,  1),
                    NextState("IDLE")
                )
            )
        )

# -------------------------------------------------------------------------
# Simulation SoC
# -------------------------------------------------------------------------
class SimSoC(SoCMini):
    def __init__(self, with_eth=True):
        platform = Platform()
        sys_clk_freq = int(50e6)
        super().__init__(platform, sys_clk_freq,
                         cpu_type=None, uart_name="sim")
        self.comb += platform.trace.eq(1)
        self.crg = CRG(platform.request("sys_clk"))

        # ------------------- Etherbone -------------------
        if with_eth:
            self.ethphy = LiteEthPHYModel(self.platform.request("eth"))
            self.add_etherbone(phy=self.ethphy,
                               ip_address="192.168.1.50",
                               mac_address=0x10e2d5000001,
                               buffer_depth=255)

        # ------------------- Input SRAM (host writes packet) -------------------
        sram_size = 64*1024
        self.stream_sram = wishbone.SRAM(sram_size)
        self.bus.add_region("stream_mem", SoCRegion(origin=0x4010_0000, size=sram_size))
        self.bus.add_slave("stream_mem",  self.stream_sram.bus)

        # ------------------- Bcrypt Wrapper -------------------
        from gateware.bcrypt_wrapper import BcryptWrapper
        self.bcrypt = BcryptWrapper(self.platform,
                                    num_proxies=2,
                                    proxies_n_cores=[4, 4],
                                    proxies_dummy=[0, 0],
                                    proxies_bitmap=[0, 0])
        self.platform.add_source("gateware/bcrypt_axis_8b.sv")
        self.bcrypt.add_sources()

        # ------------------- Streamer -------------------
        self.streamer = SimpleAXI8Streamer(self.stream_sram.mem, sram_size)

        # ------------------- Capture SRAM -------------------
        cap_size = 64*1024
        self.cap_sram = wishbone.SRAM(cap_size)
        self.bus.add_region("cap_mem", SoCRegion(origin=0x4020_0000, size=cap_size))
        self.bus.add_slave("cap_mem",  self.cap_sram.bus)

        # ------------------- Recorder -------------------
        self.recorder = SimpleAXI8Recorder(self.cap_sram.mem, cap_size)

        # ------------------- AXI-Stream wiring -------------------
        self.comb += [
            # Streamer → Bcrypt
            self.bcrypt.sink.valid.eq(self.streamer.source.valid),
            self.bcrypt.sink.data .eq(self.streamer.source.data),
            self.bcrypt.sink.last .eq(self.streamer.source.last),
            self.streamer.source.ready.eq(self.bcrypt.sink.ready),

            # Bcrypt → Recorder
            self.recorder.sink.valid.eq(self.bcrypt.source.valid),
            self.recorder.sink.data .eq(self.bcrypt.source.data),
            self.recorder.sink.last .eq(self.bcrypt.source.last),
            self.bcrypt.source.ready.eq(self.recorder.sink.ready),
        ]

        # ------------------- Debug prints (simulation only) -------------------
        self.sync += [
            If(self.bcrypt.sink.valid & self.bcrypt.sink.ready,
               Display("AXIS.In  0x%02x last=%d", self.bcrypt.sink.data, self.bcrypt.sink.last)),
            If(self.bcrypt.source.valid & self.bcrypt.source.ready,
               Display("AXIS.Out 0x%02x last=%d", self.bcrypt.source.data, self.bcrypt.source.last)),
        ]


# -------------------------------------------------------------------------
# Build / CLI
# -------------------------------------------------------------------------
def sim_args(parser):
    verilator_build_args(parser)
    parser.add_argument("--no-eth", action="store_true", help="Disable Etherbone.")

def main():
    parser = argparse.ArgumentParser(description="Bcrypt Sim — simplified streamer/recorder")
    sim_args(parser)
    args = parser.parse_args()
    verilator_kwargs = verilator_build_argdict(args)

    sim_config = SimConfig()
    sim_config.add_clocker("sys_clk", freq_hz=int(25e6))
    if not args.no_eth:
        sim_config.add_module("ethernet", "eth", args={"interface": "tap0", "ip": "192.168.1.100"})

    soc = SimSoC(with_eth=not args.no_eth)
    builder = Builder(soc, csr_csv="csr.csv", compile_software=False)
    builder.build(sim_config=sim_config, **verilator_kwargs)

if __name__ == "__main__":
    main()