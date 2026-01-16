#!/usr/bin/env python3

#
# This file is part of LiteX-Bcrypt.
#
# bcrypt_xcu1525.py — Bcrypt on XCU1525
# Demonstrates LiteX Bcrypt Proof-of-Concept (PoC) for flexible hardware acceleration.
#
# High-level:
# - Two 1 KiB Wishbone SRAMs (host-accessible via PCIe):
#   • streamer_mem  @ 0x00040000 : input packet buffer (written by host)
#   • recorder_mem  @ 0x00080000 : output capture buffer (read by host)
# - AXI8Streamer streams packet from streamer_mem (kick + length).
# - AXI8Recorder captures Bcrypt output into recorder_mem using byte-write enables.
# - PCIe exposes CSRs and both memories.
#

from migen import *

from litex.gen import *

from litex.build.io             import DifferentialInput
from litex.build.openfpgaloader import OpenFPGALoader

from litex_boards.platforms import sqrl_xcu1525

from litex.soc.integration.soc      import SoCRegion
from litex.soc.interconnect.csr     import *
from litex.soc.integration.soc_core import *
from litex.soc.integration.builder  import *

from litex.soc.interconnect import wishbone

from litex.soc.cores.clock import *
from litex.soc.cores.led   import LedChaser

from litepcie.software      import generate_litepcie_software_headers
from litepcie.phy.usppciephy import USPPCIEPHY

from gateware.axis_8b import AXIS8Streamer, AXIS8Recorder
from gateware.bcrypt_wrapper import BcryptWrapper

from litescope import LiteScopeAnalyzer

# CRG ----------------------------------------------------------------------------------------------

class CRG(LiteXModule):
    def __init__(self, platform, sys_clk_freq):
        self.rst       = Signal()
        self.cd_sys    = ClockDomain()
        self.cd_sys4x  = ClockDomain()
        self.cd_pll4x  = ClockDomain()
        self.cd_idelay = ClockDomain()

        # # #

        self.pll = pll = USPMMCM(speedgrade=-2)
        self.comb += pll.reset.eq(self.rst)
        pll.register_clkin(platform.request("clk300", 0), 300e6)
        pll.create_clkout(self.cd_pll4x, sys_clk_freq*4, buf=None, with_reset=False)
        pll.create_clkout(self.cd_idelay, 500e6)
        platform.add_false_path_constraints(self.cd_sys.clk, pll.clkin) # Ignore sys_clk to pll.clkin path created by SoC's rst.

        self.specials += [
            Instance("BUFGCE_DIV",
                p_BUFGCE_DIVIDE=4,
                i_CE=1, i_I=self.cd_pll4x.clk, o_O=self.cd_sys.clk),
            Instance("BUFGCE",
                i_CE=1, i_I=self.cd_pll4x.clk, o_O=self.cd_sys4x.clk),
        ]

        self.idelayctrl = USPIDELAYCTRL(cd_ref=self.cd_idelay, cd_sys=self.cd_sys)

# BaseSoC ------------------------------------------------------------------------------------------

class BaseSoC(SoCMini):
    def __init__(self, sys_clk_freq=125e6, with_led_chaser=True, num_proxies=1, cores_per_proxy=1, with_analyzer=False, **kwargs):

        # Platform ---------------------------------------------------------------------------------

        platform = sqrl_xcu1525.Platform()

        # Clocking ---------------------------------------------------------------------------------

        self.crg = CRG(platform, sys_clk_freq)

        # SoCMini ----------------------------------------------------------------------------------

        SoCMini.__init__(self, platform, sys_clk_freq,
            ident         = f"Bcrypt on XCU1525 (p{num_proxies} x c{cores_per_proxy}) / built on",
            ident_version = True,
        )

        # JTAGBone ---------------------------------------------------------------------------------

        self.add_jtagbone()
        platform.add_period_constraint(self.jtagbone_phy.cd_jtag.clk, 1e9/20e6)
        platform.add_false_path_constraints(self.jtagbone_phy.cd_jtag.clk, self.crg.cd_sys.clk)

        # PCIe -------------------------------------------------------------------------------------

        # PHY.
        # ----
        self.pcie_phy = USPPCIEPHY(platform, platform.request("pcie_x4"),
            data_width = 128,
            bar0_size  = 0x10_0000)

        # Core.
        # -----
        self.add_pcie(phy=self.pcie_phy, ndmas=1, address_width=64)
        platform.add_period_constraint(self.crg.cd_sys.clk, 1e9/sys_clk_freq)

        # Leds -------------------------------------------------------------------------------------

        if with_led_chaser:
            self.leds = LedChaser(
                pads         = platform.request_all("user_led"),
                sys_clk_freq = sys_clk_freq)

        # Streamer SRAM ----------------------------------------------------------------------------

        streamer_sram_size = 1*1024
        self.streamer_sram = wishbone.SRAM(streamer_sram_size)
        self.bus.add_region("streamer_mem", SoCRegion(origin=0x0004_0000, size=streamer_sram_size))
        self.bus.add_slave("streamer_mem", self.streamer_sram.bus)

        # Streamer ---------------------------------------------------------------------------------

        self.streamer = AXIS8Streamer(self.streamer_sram.mem)

        # Bcrypt Wrapper ---------------------------------------------------------------------------

        self.bcrypt = BcryptWrapper(
            platform,
            num_proxies     = num_proxies,
            cores_per_proxy = cores_per_proxy,
        )
        self.platform.add_source("gateware/bcrypt_axis_8b.sv")
        self.bcrypt.add_sources()

        # Recorder SRAM ----------------------------------------------------------------------------

        recorder_sram_size = 1*1024
        self.recorder_sram = wishbone.SRAM(recorder_sram_size, read_only=True)
        self.bus.add_region("recorder_mem", SoCRegion(origin=0x0008_0000, size=recorder_sram_size))
        self.bus.add_slave("recorder_mem", self.recorder_sram.bus)

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

        # Analyzer ---------------------------------------------------------------------------------

        if with_analyzer:
            analyzer_signals = [
                # Streamer → Bcrypt.
                self.streamer.source,

                # Bcrypt → Recorder.
                self.recorder.sink,
            ]
            self.analyzer = LiteScopeAnalyzer(analyzer_signals,
                depth        = 4096,
                clock_domain = "sys",
                register     = True,
                csr_csv      = "analyzer.csv"
            )

# Build --------------------------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Bcrypt on XCU1525.")

    # Build/Load/Flash Arguments.
    # ---------------------------
    parser.add_argument("--build",   action="store_true", help="Build bitstream.")
    parser.add_argument("--load",    action="store_true", help="Load bitstream.")
    parser.add_argument("--flash",   action="store_true", help="Flash bitstream.")

    # Bcrypt Configuration.
    # ---------------------
    parser.add_argument("--num-proxies",     type=int, default=1, help="Number of Bcrypt proxies.")
    parser.add_argument("--cores-per-proxy", type=int, default=1, help="Number of cores per proxy.")

    # Analyzer.
    # ---------
    parser.add_argument("--with-analyzer", action="store_true", help="Add LiteScope analyzer on AXI streams.")
    args = parser.parse_args()

    # Build SoC.
    # ----------
    def get_build_name():
        return f"bcrypt_p{args.num_proxies}_c{args.cores_per_proxy}"

    soc = BaseSoC(
        # Bcrypt.
        num_proxies     = args.num_proxies,
        cores_per_proxy = args.cores_per_proxy,

        # Analyzer.
        with_analyzer   = args.with_analyzer,
    )

    builder = Builder(soc, output_dir=os.path.join("build", get_build_name()), csr_csv="csr.csv")
    builder.build(build_name=get_build_name(), run=args.build)

    # Generate PCIe C Headers.
    # ------------------------
    generate_litepcie_software_headers(soc, "software/kernel")

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
