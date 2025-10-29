#!/usr/bin/env python3

#
# This file is part of LiteX-Bcrypt.
#
# bcrypt_acorn.py — Bcrypt on SQRL Acorn (CLE-215+)
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

from litex_boards.platforms import sqrl_acorn

from litex.soc.integration.soc      import SoCRegion
from litex.soc.interconnect.csr     import *
from litex.soc.integration.soc_core import *
from litex.soc.integration.builder  import *

from litex.soc.interconnect import wishbone

from litex.soc.cores.clock import *
from litex.soc.cores.led   import LedChaser

from litepcie.software      import generate_litepcie_software_headers
from litepcie.phy.s7pciephy import S7PCIEPHY

from gateware.axis_8b import AXIS8Streamer, AXIS8Recorder
from gateware.bcrypt_wrapper import BcryptWrapper

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
    def __init__(self, variant="m2", sys_clk_freq=125e6, with_led_chaser=True, num_proxies=1, cores_per_proxy=1, **kwargs):

        # Platform ---------------------------------------------------------------------------------

        platform = sqrl_acorn.Platform(variant="cle-215+")
        platform.add_extension(sqrl_acorn._litex_acorn_baseboard_mini_io, prepend=True)

        # Clocking ---------------------------------------------------------------------------------

        self.crg = CRG(platform, sys_clk_freq)

        # SoCMini ----------------------------------------------------------------------------------

        SoCMini.__init__(self, platform, sys_clk_freq,
            ident         = f"Bcrypt on SQRL Acorn / {variant} variant / built on",
            ident_version = True,
        )

        # JTAGBone ---------------------------------------------------------------------------------

        self.add_jtagbone()
        platform.add_period_constraint(self.jtagbone_phy.cd_jtag.clk, 1e9/20e6)
        platform.add_false_path_constraints(self.jtagbone_phy.cd_jtag.clk, self.crg.cd_sys.clk)

        # PCIe -------------------------------------------------------------------------------------

        # PHY.
        # ----
        pcie_lanes      = {"m2" :   4, "baseboard" :  1}[variant]
        pcie_data_width = {"m2" : 128, "baseboard" : 64}[variant]
        self.pcie_phy = S7PCIEPHY(platform, platform.request(f"pcie_x{pcie_lanes}"),
            data_width = pcie_data_width,
            bar0_size  = 0x10_0000,
        )
        if variant == "baseboard":
            platform.toolchain.pre_placement_commands.append("reset_property LOC [get_cells -hierarchical -filter {{NAME=~pcie_s7/*gtp_channel.gtpe2_channel_i}}]")
            platform.toolchain.pre_placement_commands.append("set_property LOC GTPE2_CHANNEL_X0Y7 [get_cells -hierarchical -filter {{NAME=~pcie_s7/*gtp_channel.gtpe2_channel_i}}]")

        self.pcie_phy.update_config({
            "Base_Class_Menu"          : "Encryption/Decryption_controllers",
            "Sub_Class_Interface_Menu" : "Other_en/decryption",
            "Class_Code_Base"          : "0B",
            "Class_Code_Sub"           : "80",
        })


        # Core.
        # -----
        self.add_pcie(phy=self.pcie_phy, ndmas=1, address_width=64)
        platform.add_period_constraint(self.crg.cd_sys.clk, 1e9/sys_clk_freq)

        # Timings False Paths.
        # --------------------
        false_paths = [
            ("{{*s7pciephy_clkout0}}", "{{sys_clk}}"),
            ("{{*s7pciephy_clkout1}}", "{{sys_clk}}"),
            ("{{*s7pciephy_clkout3}}", "{{sys_clk}}"),
            ("{{*s7pciephy_clkout0}}", "{{*s7pciephy_clkout1}}")
        ]
        for clk0, clk1 in false_paths:
            platform.toolchain.pre_placement_commands.append(f"set_false_path -from [get_clocks {clk0}] -to [get_clocks {clk1}]")
            platform.toolchain.pre_placement_commands.append(f"set_false_path -from [get_clocks {clk1}] -to [get_clocks {clk0}]")

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

# Build --------------------------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Bcrypt on SQRL Acorn.")

    # Build/Load/Flash Arguments.
    # ---------------------------
    parser.add_argument("--variant", default="m2",        help="Design variant.", choices=["m2", "baseboard"])
    parser.add_argument("--build",   action="store_true", help="Build bitstream.")
    parser.add_argument("--load",    action="store_true", help="Load bitstream.")
    parser.add_argument("--flash",   action="store_true", help="Flash bitstream.")

    # Bcrypt Configuration.
    # ---------------------
    parser.add_argument("--num-proxies",     type=int, default=1, help="Number of Bcrypt proxies.")
    parser.add_argument("--cores-per-proxy", type=int, default=1, help="Number of cores per proxy.")
    args = parser.parse_args()

    # Build SoC.
    # ----------
    def get_build_name():
        return f"bcrypt_p{args.num_proxies}_c{args.cores_per_proxy}"

    soc = BaseSoC(
        # Generic.
        variant         = args.variant,

        # Bcrypt.
        num_proxies     = args.num_proxies,
        cores_per_proxy = args.cores_per_proxy,
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
