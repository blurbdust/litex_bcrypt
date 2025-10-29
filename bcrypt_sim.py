#!/usr/bin/env python3

#
# This file is part of LiteX-Bcrypt.
#
# bcrypt_sim.py — Bcrypt Sim
# Demonstrates LiteX Bcrypt Proof-of-Concept (PoC) for flexible hardware acceleration.
#
# High-level:
# - Two 1 KiB Wishbone SRAMs (host-accessible via Etherbone):
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

from litex.soc.interconnect import wishbone

from liteeth.phy.model import LiteEthPHYModel

from gateware.axis_8b import AXIS8Streamer, AXIS8Recorder
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

        streamer_sram_size = 1*1024
        self.streamer_sram = wishbone.SRAM(streamer_sram_size)
        self.bus.add_region("streamer_mem", SoCRegion(origin=0x4010_0000, size=streamer_sram_size))
        self.bus.add_slave("streamer_mem",  self.streamer_sram.bus)

        # Streamer ---------------------------------------------------------------------------------

        self.streamer = AXIS8Streamer(self.streamer_sram.mem)

        # Bcrypt Wrapper ---------------------------------------------------------------------------

        self.bcrypt = BcryptWrapper(self.platform,
            num_proxies     = 2,
            cores_per_proxy = 2,
        )
        self.platform.add_source("gateware/bcrypt_axis_8b.sv")
        self.bcrypt.add_sources()

        # Recorder SRAM ----------------------------------------------------------------------------

        recorder_sram_size = 1*1024
        self.recorder_sram = wishbone.SRAM(recorder_sram_size)
        self.bus.add_region("recorder_mem", SoCRegion(origin=0x4020_0000, size=recorder_sram_size))
        self.bus.add_slave("recorder_mem",  self.recorder_sram.bus)

        # Recorder ---------------------------------------------------------------------------------

        self.recorder = AXIS8Recorder(self.recorder_sram.mem)

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
