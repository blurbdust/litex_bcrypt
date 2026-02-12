#!/usr/bin/env python3

#
# This file is part of LiteX-Bcrypt.
#
# bcrypt_ypcb.py — Bcrypt on YPCB-00338-1P1
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

from litex_boards.platforms import ypcb_00338_1p1

from litex.soc.integration.soc      import SoCRegion
from litex.soc.interconnect.csr     import *
from litex.soc.integration.soc_core import *
from litex.soc.integration.builder  import *

from litex.soc.interconnect import wishbone

from litex.soc.cores.clock     import *
from litex.soc.cores.led       import LedChaser
from litex.soc.cores.bpi_flash import BPIFlash

from litepcie.software      import generate_litepcie_software_headers
from litepcie.phy.s7pciephy import S7PCIEPHY

from gateware.axis_8b import AXIS8Streamer, AXIS8Recorder
from gateware.bcrypt_wrapper import BcryptWrapper

from litescope import LiteScopeAnalyzer

# CRG ----------------------------------------------------------------------------------------------

class CRG(LiteXModule):
    def __init__(self, platform, sys_clk_freq):
        self.rst       = Signal()
        self.cd_sys    = ClockDomain()
        self.cd_idelay = ClockDomain()

        # Clk/Rst.
        clk200    = platform.request("clk200")
        clk200_se = Signal()
        self.specials += DifferentialInput(clk200.p, clk200.n, clk200_se)
        rst_n = platform.request("rst_n")

        # PLL.
        self.pll = pll = S7MMCM(speedgrade=-2)
        self.comb += pll.reset.eq(~rst_n | self.rst)
        pll.register_clkin(clk200_se, 200e6)
        pll.create_clkout(self.cd_sys,       sys_clk_freq, reset_buf="bufg")
        pll.create_clkout(self.cd_idelay,    200e6)
        platform.add_false_path_constraints(self.cd_sys.clk, pll.clkin) # Ignore sys_clk to pll.clkin path created by SoC's rst.

        # IDelayCtrl.
        self.idelayctrl = S7IDELAYCTRL(self.cd_idelay)

# BaseSoC ------------------------------------------------------------------------------------------

class BaseSoC(SoCMini):
    def __init__(self, sys_clk_freq=150e6, with_led_chaser=True, num_proxies=1, cores_per_proxy=1, with_analyzer=False, **kwargs):

        # Platform ---------------------------------------------------------------------------------

        platform = ypcb_00338_1p1.Platform()

        # Clocking ---------------------------------------------------------------------------------

        self.crg = CRG(platform, sys_clk_freq)

        # SoCMini ----------------------------------------------------------------------------------

        SoCMini.__init__(self, platform, sys_clk_freq,
            ident         = f"Bcrypt on YPCB (p{num_proxies} x c{cores_per_proxy}) / built on",
            ident_version = True,
        )

        # JTAGBone ---------------------------------------------------------------------------------

        self.add_jtagbone()
        platform.add_period_constraint(self.jtagbone_phy.cd_jtag.clk, 1e9/20e6)
        platform.add_false_path_constraints(self.jtagbone_phy.cd_jtag.clk, self.crg.cd_sys.clk)

        # PCIe -------------------------------------------------------------------------------------

        # PHY.
        # ----
        self.pcie_phy = S7PCIEPHY(platform, platform.request("pcie_x8"),
            data_width = 128,
            bar0_size  = 0x10_0000)

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

        # Vivado Timing Closure: Limit fanout on bcrypt arbiter broadcast nets.
        platform.toolchain.pre_placement_commands.append(
            "set_property MAX_FANOUT 16 [get_cells -hierarchical -filter {{NAME =~ */u_arb/core_din_reg*}}]"
        )
        platform.toolchain.pre_placement_commands.append(
            "set_property MAX_FANOUT 16 [get_cells -hierarchical -filter {{NAME =~ */u_arb/core_ctrl_reg*}}]"
        )

        # Limit fanout on sys_rst (fanout=1381, 5.7ns route at 150MHz).
        platform.toolchain.pre_placement_commands.append(
            "set_property MAX_FANOUT 100 [get_nets sys_rst]"
        )

        # Overconstrain placement: add 500ps clock uncertainty so the placer
        # targets tighter timing, then remove it before routing (AMD UG949 technique).
        platform.toolchain.pre_placement_commands.append(
            "set_clock_uncertainty 0.500 [get_clocks sys_clk]"
        )
        platform.toolchain.pre_routing_commands.append(
            "set_clock_uncertainty 0 [get_clocks sys_clk]"
        )

        platform.toolchain.pre_placement_commands.append("reset_property LOC [get_cells -hierarchical -filter {{NAME=~pcie_s7/*gtx_channel.gtxe2_channel_i}}]")
        platform.toolchain.pre_placement_commands.append("set_property LOC GTXE2_CHANNEL_X0Y23 [get_cells -hierarchical -filter {{NAME=~pcie_s7/*pipe_lane[0].gt_wrapper_i/gtx_channel.gtxe2_channel_i}}]")
        platform.toolchain.pre_placement_commands.append("set_property LOC GTXE2_CHANNEL_X0Y22 [get_cells -hierarchical -filter {{NAME=~pcie_s7/*pipe_lane[1].gt_wrapper_i/gtx_channel.gtxe2_channel_i}}]")
        platform.toolchain.pre_placement_commands.append("set_property LOC GTXE2_CHANNEL_X0Y21 [get_cells -hierarchical -filter {{NAME=~pcie_s7/*pipe_lane[2].gt_wrapper_i/gtx_channel.gtxe2_channel_i}}]")
        platform.toolchain.pre_placement_commands.append("set_property LOC GTXE2_CHANNEL_X0Y20 [get_cells -hierarchical -filter {{NAME=~pcie_s7/*pipe_lane[3].gt_wrapper_i/gtx_channel.gtxe2_channel_i}}]")

        platform.toolchain.pre_placement_commands.append("set_property LOC GTXE2_CHANNEL_X0Y19 [get_cells -hierarchical -filter {{NAME=~pcie_s7/*pipe_lane[4].gt_wrapper_i/gtx_channel.gtxe2_channel_i}}]")
        platform.toolchain.pre_placement_commands.append("set_property LOC GTXE2_CHANNEL_X0Y18 [get_cells -hierarchical -filter {{NAME=~pcie_s7/*pipe_lane[5].gt_wrapper_i/gtx_channel.gtxe2_channel_i}}]")
        platform.toolchain.pre_placement_commands.append("set_property LOC GTXE2_CHANNEL_X0Y17 [get_cells -hierarchical -filter {{NAME=~pcie_s7/*pipe_lane[6].gt_wrapper_i/gtx_channel.gtxe2_channel_i}}]")
        platform.toolchain.pre_placement_commands.append("set_property LOC GTXE2_CHANNEL_X0Y16 [get_cells -hierarchical -filter {{NAME=~pcie_s7/*pipe_lane[7].gt_wrapper_i/gtx_channel.gtxe2_channel_i}}]")

        # Bitstream Configuration.
        # -----------------------
        platform.toolchain.bitstream_commands.append(
            "set_property BITSTREAM.CONFIG.UNUSEDPIN PULLNONE [current_design]"
        )

        # BPI Flash Image Generation.
        # ----------------------------
        platform.toolchain.additional_commands.append(
            "write_cfgmem -format bin -interface BPIx16 -size 64 "
            "-loadbit \"up 0x0 {build_name}.bit\" -force {build_name}_bpi.bin"
        )

        # Leds -------------------------------------------------------------------------------------

        if with_led_chaser:
            self.leds = LedChaser(
                pads         = platform.request_all("user_led"),
                sys_clk_freq = sys_clk_freq)

        # Flash ---------------------------------------------------------------------------------

        self.flash = BPIFlash(platform.request("linear_flash"), sys_clk_freq)

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
    parser = argparse.ArgumentParser(description="Bcrypt on YPCB-00338-1P1.")

    # Build/Load/Flash Arguments.
    # ---------------------------
    parser.add_argument("--build",   action="store_true", help="Build bitstream.")
    parser.add_argument("--load",    action="store_true", help="Load bitstream.")
    parser.add_argument("--flash",   action="store_true", help="Flash bitstream.")

    # Bcrypt Configuration.
    # ---------------------
    parser.add_argument("--num-proxies",     type=int, default=1,     help="Number of Bcrypt proxies.")
    parser.add_argument("--cores-per-proxy", type=int, default=1,     help="Number of cores per proxy.")
    parser.add_argument("--sys-clk-freq",    type=float, default=150e6, help="System clock frequency in Hz (default: 150 MHz).")

    # Build Speed/Tuning.
    # -------------------
    parser.add_argument("--threads",       type=int, default=24, help="Vivado max threads (default: 24).")

    # Analyzer.
    # ---------
    parser.add_argument("--with-analyzer", action="store_true", help="Add LiteScope analyzer on AXI streams.")
    args = parser.parse_args()

    # Build SoC.
    # ----------
    def get_build_name():
        mhz = int(args.sys_clk_freq / 1e6)
        return f"bcrypt_p{args.num_proxies}_c{args.cores_per_proxy}_{mhz}mhz"

    soc = BaseSoC(
        # Clock.
        sys_clk_freq    = args.sys_clk_freq,

        # Bcrypt.
        num_proxies     = args.num_proxies,
        cores_per_proxy = args.cores_per_proxy,

        # Analyzer.
        with_analyzer   = args.with_analyzer,
    )

    builder = Builder(soc, output_dir=os.path.join("build", get_build_name()), csr_csv="csr.csv")

    # Incremental compilation: reuse previous routing checkpoint if available.
    route_dcp = os.path.join("build", get_build_name(), "gateware", f"{get_build_name()}_route.dcp")
    if os.path.exists(route_dcp):
        builder.soc.platform.toolchain.incremental_implementation = True

    builder.build(build_name=get_build_name(), run=args.build,
        vivado_max_threads                   = args.threads,
        # SSI-aware strategies for 2-SLR K480T device.
        vivado_synth_directive               = "PerformanceOptimized",
        vivado_place_directive               = "SSI_ExtraTimingOpt",
        vivado_post_place_phys_opt_directive = "AggressiveExplore",
        vivado_route_directive               = "AggressiveExplore",
        vivado_post_route_phys_opt_directive = "AggressiveExplore",
    )

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
