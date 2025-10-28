#!/usr/bin/env python3

# bcrypt_sim.py — Bcrypt Sim
# Demonstrates LiteX Bcrypt Proof-of-Concept (PoC) for flexible hardware acceleration.
#
# High-level:
# - Two 64 KiB Wishbone SRAMs (host-accessible via Etherbone):
#   • streamer_mem  @ 0x40100000 : input packet buffer (written by host)
#   • recorder_mem  @ 0x40200000 : output capture buffer (read by host)
# - AXI8Streamer streams packet from streamer_mem (kick + length).
# - AXI8Recorder captures Bcrypt output into recorder_mem using byte-write enables.
# - Etherbone exposes CSRs and both memories.
#

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

from litex.soc.interconnect     import stream, wishbone
from litex.soc.interconnect.csr import CSRStorage, CSRStatus

from liteeth.phy.model import LiteEthPHYModel

from gateware.bcrypt_wrapper import BcryptWrapper

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
        super().__init__("SIM", _io)

# AXI Streamer (8-bit) -----------------------------------------------------------------------------

class AXI8Streamer(LiteXModule):
    def __init__(self, sram_mem):
        self.source = source = stream.Endpoint([("data", 8)])

        self.length = CSRStorage(32)
        self.kick   = CSRStorage(1)
        self.done   = CSRStatus(1)

        # # #

        # Signals.
        addr     = Signal(32)
        byte_sel = Signal(2)

        # Kick edge detect.
        kick_d = Signal()
        self.sync += kick_d.eq(self.kick.storage)
        start = self.kick.storage & ~kick_d

        # SRAM Read Port.
        port = sram_mem.get_port(async_read=True)
        self.specials += port

        # Data-Generation.
        self.comb += [
            port.adr.eq(addr[2:]),
            byte_sel.eq(addr[0:2]),
            source.last.eq(addr == (self.length.storage - 1)),
            Case(byte_sel, {
                0b00: source.data.eq(port.dat_r[ 0: 8]),
                0b01: source.data.eq(port.dat_r[ 8:16]),
                0b10: source.data.eq(port.dat_r[16:24]),
                0b11: source.data.eq(port.dat_r[24:32]),
            })
        ]

        # FSM.
        self.fsm = fsm = FSM(reset_state="IDLE")
        fsm.act("IDLE",
            source.valid.eq(0),
            self.done.status.eq(1),
            If(start & (self.length.storage > 0),
                NextValue(addr, 0),
                NextState("RUN")
            )
        )
        fsm.act("RUN",
            source.valid.eq(1),
            self.done.status.eq(0),
            If(source.ready,
                NextValue(addr, addr + 1),
                If(source.last,
                    NextState("IDLE")
                )
            )
        )

# AXI Recorder (8-bit) -----------------------------------------------------------------------------

class AXI8Recorder(LiteXModule):
    def __init__(self, sram_mem):
        self.sink = stream.Endpoint([("data", 8)])

        self.kick  = CSRStorage(1)
        self.done  = CSRStatus (1)
        self.count = CSRStatus (32)

        # # #

        # Signals.
        byte_addr = Signal(32)
        byte_cnt  = Signal(32)

        # Kick edge detect.
        kick_d = Signal()
        self.sync += kick_d.eq(self.kick.storage)
        start = self.kick.storage & ~kick_d

        # SRAM Write Port.
        port = sram_mem.get_port(write_capable=True, we_granularity=8)
        self.specials += port
        self.comb += port.adr.eq(byte_addr[2:])

        # FSM.
        self.fsm = fsm = FSM(reset_state="IDLE")
        fsm.act("IDLE",
            self.sink.ready.eq(0),
            self.done.status.eq(1),
            If(start,
                NextValue(byte_addr, 0),
                NextValue(byte_cnt,  0),
                NextState("RUN")
            )
        )
        fsm.act("RUN",
            self.sink.ready.eq(1),
            self.done.status.eq(0),
            If(self.sink.valid,
                Case(byte_addr[0:2], {
                    0b00 : [port.dat_w[ 0: 8].eq(self.sink.data), port.we.eq(0b0001)],
                    0b01 : [port.dat_w[ 8:16].eq(self.sink.data), port.we.eq(0b0010)],
                    0b10 : [port.dat_w[16:24].eq(self.sink.data), port.we.eq(0b0100)],
                    0b11 : [port.dat_w[24:32].eq(self.sink.data), port.we.eq(0b1000)],
                }),
                NextValue(byte_addr, byte_addr + 1),
                NextValue(byte_cnt,  byte_cnt  + 1),
                If(self.sink.last,
                    NextState("IDLE")
                )
            )
        )
        self.comb += self.count.status.eq(byte_cnt)

# Simulation SoC -----------------------------------------------------------------------------------

class SimSoC(SoCMini):
    def __init__(self):
        sys_clk_freq = int(1e6)

        # Platform ---------------------------------------------------------------------------------
        platform = Platform()
        self.comb += platform.trace.eq(1)

        # SoC --------------------------------------------------------------------------------------
        SoCMini.__init__(self, platform, sys_clk_freq,
            cpu_type  = None,
            uart_name = "sim",
        )

        # CRG --------------------------------------------------------------------------------------
        self.crg = CRG(platform.request("sys_clk"))

        # Ethernet / Etherbone ---------------------------------------------------------------------
        self.ethphy = LiteEthPHYModel(self.platform.request("eth"))
        self.add_etherbone(phy=self.ethphy,
            ip_address  = "192.168.1.50",
            mac_address = 0x10e2d5000001,
        )

        # Streamer SRAM ----------------------------------------------------------------------------
        streamer_sram_size = 64*1024
        self.streamer_sram = wishbone.SRAM(streamer_sram_size)
        self.bus.add_region("streamer_mem", SoCRegion(origin=0x4010_0000, size=streamer_sram_size))
        self.bus.add_slave("streamer_mem",  self.streamer_sram.bus)

        # Streamer ---------------------------------------------------------------------------------
        self.streamer = AXI8Streamer(self.streamer_sram.mem)

        # Bcrypt Wrapper ---------------------------------------------------------------------------
        self.bcrypt = BcryptWrapper(self.platform,
            num_proxies     = 2,
            proxies_n_cores = [4, 4],
            proxies_dummy   = [0, 0],
            proxies_bitmap  = [0, 0],
        )
        self.platform.add_source("gateware/bcrypt_axis_8b.sv")
        self.bcrypt.add_sources()

        # Recorder SRAM ----------------------------------------------------------------------------
        recorder_sram_size = 64*1024
        self.recorder_sram = wishbone.SRAM(recorder_sram_size)
        self.bus.add_region("recorder_mem", SoCRegion(origin=0x4020_0000, size=recorder_sram_size))
        self.bus.add_slave("recorder_mem",  self.recorder_sram.bus)

        # Recorder ---------------------------------------------------------------------------------
        self.recorder = AXI8Recorder(self.recorder_sram.mem)

        # Streamer → Bcrypt → Recorder Datapaths ---------------------------------------------------
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

# Build / Main -------------------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="LiteX Bcrypt Sim.")
    parser.add_argument("--debug", action="store_true", help="Enable AXI byte traces (Display statements)")
    verilator_build_args(parser)
    args = parser.parse_args()
    verilator_kwargs = verilator_build_argdict(args)

    sim_config = SimConfig()
    sim_config.add_clocker("sys_clk", freq_hz=int(25e6))
    sim_config.add_module("ethernet", "eth", args={"interface": "tap0", "ip": "192.168.1.100"})

    soc     = SimSoC()
    if args.debug:
        soc.sync += [
            If(soc.bcrypt.sink.valid & soc.bcrypt.sink.ready,
               Display("AXIS.In  0x%02x last=%d", soc.bcrypt.sink.data, soc.bcrypt.sink.last)),
            If(soc.bcrypt.source.valid & soc.bcrypt.source.ready,
               Display("AXIS.Out 0x%02x last=%d", soc.bcrypt.source.data, soc.bcrypt.source.last)),
        ]
    builder = Builder(soc, csr_csv="csr.csv")
    builder.build(sim_config=sim_config, **verilator_kwargs)

if __name__ == "__main__":
    main()
