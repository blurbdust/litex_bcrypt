#!/usr/bin/env python3

#
# This file is part of LiteX-Bcrypt.
#
# bcrypt_acorn.py — Bcrypt on SQRL Acorn (CLE-215+)
# Demonstrates LiteX Bcrypt Proof-of-Concept (PoC) for flexible hardware acceleration.
#
# High-level:
# - Two 64 KiB Wishbone SRAMs (host-accessible via PCIe):
#   • streamer_mem  @ 0x40100000 : input packet buffer (written by host)
#   • recorder_mem  @ 0x40200000 : output capture buffer (read by host)
# - AXI8Streamer streams packet from streamer_mem (kick + length).
# - AXI8Recorder captures Bcrypt output into recorder_mem using byte-write enables.
# - PCIe exposes CSRs and both memories.
#

from migen import *

from litex.gen import *

from litex.build.io             import DifferentialInput
from litex.build.openfpgaloader import OpenFPGALoader

from litex_boards.platforms import sqrl_acorn

from litex.soc.integration.soc      import SoCRegion
from litex.soc.interconnect.csr     import *
from litex.soc.integration.soc_core import *
from litex.soc.integration.builder  import *

from litex.soc.interconnect     import stream, wishbone
from litex.soc.interconnect.csr import CSRStorage, CSRStatus

from litex.soc.cores.clock import *
from litex.soc.cores.led   import LedChaser

from litepcie.software      import generate_litepcie_software
from litepcie.software      import generate_litepcie_software_headers
from litepcie.phy.s7pciephy import S7PCIEPHY

from gateware.bcrypt_wrapper import BcryptWrapper

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

# CRG ----------------------------------------------------------------------------------------------

class CRG(LiteXModule):
    def __init__(self, platform, sys_clk_freq):
        self.rst    = Signal()
        self.cd_sys = ClockDomain()

        # # #

        # Clk/Rst.
        clk200    = platform.request("clk200")
        clk200_se = Signal()
        self.specials += DifferentialInput(clk200.p, clk200.n, clk200_se)

        # PLL.
        self.pll = pll = S7PLL()
        self.comb += pll.reset.eq(self.rst)
        pll.register_clkin(clk200_se, 200e6)
        pll.create_clkout(self.cd_sys, sys_clk_freq)
        platform.add_false_path_constraints(self.cd_sys.clk, pll.clkin)

# BaseSoC ------------------------------------------------------------------------------------------

class BaseSoC(SoCMini):
    def __init__(self, sys_clk_freq=125e6, with_led_chaser=True, num_proxies=1, cores_per_proxy=1, **kwargs):

        # Platform ---------------------------------------------------------------------------------

        platform = sqrl_acorn.Platform(variant="cle-215+")
        platform.add_extension(sqrl_acorn._litex_acorn_baseboard_mini_io, prepend=True)

        # Clocking ---------------------------------------------------------------------------------

        self.crg = CRG(platform, sys_clk_freq)

        # SoCMini ----------------------------------------------------------------------------------

        SoCMini.__init__(self, platform, sys_clk_freq,
            ident         = "Bcrypt on SQRL Acorn",
            ident_version = True,
        )

        # JTAGBone ---------------------------------------------------------------------------------

        self.add_jtagbone()
        platform.add_period_constraint(self.jtagbone_phy.cd_jtag.clk, 1e9/20e6)
        platform.add_false_path_constraints(self.jtagbone_phy.cd_jtag.clk, self.crg.cd_sys.clk)

        # PCIe -------------------------------------------------------------------------------------

        self.pcie_phy = S7PCIEPHY(platform, platform.request("pcie_x4"),
            data_width = 128,
            bar0_size  = 0x20000,
        )
        self.pcie_phy.update_config({
            "Base_Class_Menu"          : "Network_controller",  # FIXME: Update.
            "Sub_Class_Interface_Menu" : "Ethernet_controller", # FIXME: Update.
            "Class_Code_Base"          : "02",                  # FIXME: Update.
            "Class_Code_Sub"           : "00",                  # FIXME: Update.
        })
        self.add_pcie(phy=self.pcie_phy, ndmas=1, address_width=64)
        platform.add_period_constraint(self.crg.cd_sys.clk, 1e9/sys_clk_freq)

        # Leds -------------------------------------------------------------------------------------

        if with_led_chaser:
            self.leds = LedChaser(
                pads         = platform.request_all("user_led"),
                sys_clk_freq = sys_clk_freq)

        # Streamer SRAM ----------------------------------------------------------------------------

        streamer_sram_size = 64*1024
        self.streamer_sram = wishbone.SRAM(streamer_sram_size)
        self.bus.add_region("streamer_mem", SoCRegion(origin=0x4010_0000, size=streamer_sram_size))
        self.bus.add_slave("streamer_mem", self.streamer_sram.bus)

        # Streamer ---------------------------------------------------------------------------------

        self.streamer = AXI8Streamer(self.streamer_sram.mem)

        # Bcrypt Wrapper ---------------------------------------------------------------------------

        self.bcrypt = BcryptWrapper(
            platform,
            num_proxies     = num_proxies,
            cores_per_proxy = cores_per_proxy,
        )
        self.platform.add_source("gateware/bcrypt_axis_8b.sv")
        self.bcrypt.add_sources()

        # Recorder SRAM ----------------------------------------------------------------------------

        recorder_sram_size = 64*1024
        self.recorder_sram = wishbone.SRAM(recorder_sram_size)
        self.bus.add_region("recorder_mem", SoCRegion(origin=0x4020_0000, size=recorder_sram_size))
        self.bus.add_slave("recorder_mem", self.recorder_sram.bus)

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

# Build --------------------------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Bcrypt on SQRL Acorn.")

    # Build/Load/Flash Arguments.
    # ---------------------------
    parser.add_argument("--build", action="store_true", help="Build bitstream.")
    parser.add_argument("--load",  action="store_true", help="Load bitstream.")
    parser.add_argument("--flash", action="store_true", help="Flash bitstream.")
    # Bcrypt Configuration.
    # ---------------------
    parser.add_argument("--num-proxies",     type=int, default=1, help="Number of Bcrypt proxies.")
    parser.add_argument("--cores-per-proxy", type=int, default=1, help="Number of cores per proxy.")
    args = parser.parse_args()

    # Build SoC.
    # ----------
    soc = BaseSoC(
        num_proxies     = args.num_proxies,
        cores_per_proxy = args.cores_per_proxy,
    )
    builder = Builder(soc, csr_csv="csr.csv")
    builder.build(run=args.build)

    # Generate PCIe C Headers.
    # ------------------------
    #generate_litepcie_software_headers(soc, "software/kernel")

    # Load FPGA.
    # ----------
    if args.load:
        prog = soc.platform.create_programmer()
        prog.load_bitstream(builder.get_bitstream_filename(mode="sram"))

    # Flash FPGA.
    # -----------
    if args.flash:
        prog = soc.platform.create_programmer()
        prog.flash(0, builder.get_bitstream_filename(mode="flash"))

if __name__ == "__main__":
    main()
