#!/usr/bin/env python3

#
# This file is part of LiteX-Bcrypt.
#
# bcrypt_storey_peak.py: Bcrypt on Microsoft/HP "Storey Peak" (Altera Stratix V GS)
#
# High-level (same datapath as bcrypt_acorn.py):
# - Two 1 KiB Wishbone SRAMs (host-accessible via JTAGBone):
#   • streamer_mem  @ 0x00040000 : input packet buffer (written by host)
#   • recorder_mem  @ 0x00080000 : output capture buffer (read by host)
# - AXI8Streamer streams packet from streamer_mem (kick + length).
# - AXI8Recorder captures Bcrypt output into recorder_mem using byte-write enables.
#
# Difference from the Xilinx targets: there is NO PCIe here. LitePCIe has no Stratix V PHY, so the
# host talks to the CSRs and both SRAMs over JTAGBone (litex_server --jtag) through the card's
# onboard FT232H. That is functionally complete, since test_bcrypt.py drives everything through
# litex.RemoteClient, which does not care which bridge is underneath, but it is far slower than
# PCIe DMA, so treat throughput numbers from this target as a correctness result, not a benchmark.
#
# Start at 1x1 (the default). Larger arrays take a long time to build.

import os
import shutil
import argparse
import subprocess

from migen import *

from litex.gen import *

from litex_boards.platforms import microsoft_storey_peak

from litex.soc.integration.soc      import SoCRegion
from litex.soc.interconnect.csr     import *
from litex.soc.integration.soc_core import *
from litex.soc.integration.builder  import *

from litex.soc.interconnect import wishbone

from litex.soc.cores.clock.intel_stratix5 import StratixVPLL
from litex.soc.cores.led import LedChaser

from litepcie.phy.svpciephy import SVPCIEPHY

from gateware.axis_8b import AXIS8Streamer, AXIS8Recorder
from gateware.bcrypt_wrapper import BcryptWrapper

from litescope import LiteScopeAnalyzer

# CRG ----------------------------------------------------------------------------------------------

class CRG(LiteXModule):
    def __init__(self, platform, sys_clk_freq, with_pcie_mgmt=False, pcie_mgmt_freq=50e6):
        self.rst    = Signal()
        self.cd_sys = ClockDomain()
        # The Stratix V PCIe hard IP needs a free-running management clock for its transceiver
        # reconfiguration controller. Intel documents 100-125 MHz but their own example designs run
        # it at 50 MHz, and 125 MHz does not close timing on this part (measured Fmax 108.55 MHz).
        #
        # 50 MHz is used because it also frees sys_clk. Both outputs come from one VCO, and the
        # 100 MHz constraint forces awkward ratios: asking for 190 yields 188.75, which the fitter
        # then degrades to 186.976, and 205/208/210 MHz have no solution at all. At 50 MHz the same
        # requests are exact and clock uncertainty drops from 0.300 to 0.200 ns.
        if with_pcie_mgmt:
            self.cd_pcie_mgmt = ClockDomain()

        # # #

        # Clk/Rst.
        # 125 MHz single-ended from the onboard IDT clock generator. No reset input exists on this
        # board, so sys reset comes from PLL lock only.
        clk125 = platform.request("clk125")

        # PLL.
        self.pll = pll = StratixVPLL(speedgrade="-C1")
        self.comb += pll.reset.eq(self.rst)
        pll.register_clkin(clk125, 125e6)
        pll.create_clkout(self.cd_sys, sys_clk_freq)
        if with_pcie_mgmt:
            pll.create_clkout(self.cd_pcie_mgmt, pcie_mgmt_freq)

        # sys and clk125 are related only through the PLL. The SoC reset (sys domain) reaches
        # registers clocked by clk125 as an asynchronous reset, which STA otherwise times as a
        # synchronous CDC and reports as a setup violation.
        platform.add_false_path_constraints(self.cd_sys.clk, pll.clkin)

# BaseSoC ------------------------------------------------------------------------------------------

class BaseSoC(SoCMini):
    def __init__(self, sys_clk_freq=100e6, with_led_chaser=True, num_proxies=1, cores_per_proxy=1, with_analyzer=False, speed_opt=True, placement_margin=0.0,
                 with_pcie=False, pcie_connector=0, pcie_lanes=8, pcie_speed="gen2", pcie_data_width=128, pcie_ndmas=1, pcie_mgmt_freq=50e6, **kwargs):

        # Platform ---------------------------------------------------------------------------------

        platform = microsoft_storey_peak.Platform()

        # Clocking ---------------------------------------------------------------------------------

        self.crg = CRG(platform, sys_clk_freq, with_pcie_mgmt=with_pcie, pcie_mgmt_freq=pcie_mgmt_freq)

        # SoCMini ----------------------------------------------------------------------------------

        SoCMini.__init__(self, platform, sys_clk_freq,
            ident         = f"Bcrypt on Storey Peak (p{num_proxies} x c{cores_per_proxy}) / built on",
            ident_version = True,
        )

        # JTAGBone ---------------------------------------------------------------------------------
        #
        # This is the only host interface on this target; it replaces PCIe entirely.

        # altera_reserved_tck is otherwise an unconstrained clock, which would leave the JTAGBone
        # TAP logic untimed. Constrain it conservatively and declare it asynchronous.
        platform.toolchain.additional_sdc_commands += [
            "create_clock -name altera_reserved_tck -period 100.000 [get_ports {altera_reserved_tck}]",
            "set_clock_groups -asynchronous -group {altera_reserved_tck}",

            # Reset CDC, sys -> clk125.
            #
            # add_false_path_constraints(cd_sys.clk, pll.clkin) in the CRG emits a constraint naming
            # `main_crg_clkin_signal`, but the real latch clock on this crossing is `clk125` itself,
            # so it never matched and the path stayed timed. Measured at 396 cores: -0.978 ns, from
            # `main_reset_wr_stb` and `main_reset_storage[0]` (SoC reset CSR, sys domain) to a
            # register clocked by clk125. It scaled with sys_clk frequency (-0.09 at 200 MHz on a
            # 1-core build, -0.98 here) precisely because it was being timed as a synchronous CDC.
            #
            # The only traffic between these domains is the software reset reaching the PLL reset --
            # asynchronous by construction, and nothing else in the design is clocked by clk125 --
            # so false-pathing both directions is correct, not a way to hide a real violation.
            "set_false_path -from [get_clocks sys_clk] -to [get_clocks clk125]",
            "set_false_path -from [get_clocks clk125] -to [get_clocks sys_clk]",
        ]

        # Placement margin: the Quartus port of bcrypt_ypcb.py's UG949 trick.
        #
        # The Xilinx target adds 500ps of clock uncertainty before placement and removes it before
        # routing, so the placer aims tighter than the real target while the design still SIGNS OFF
        # at its real frequency. Quartus cannot be relaxed the same way: place and route happen in a
        # single quartus_fit invocation, and more importantly the PLL output frequency IS the
        # hardware clock, so simply constraining higher ships a part that really runs at the higher
        # (failing) frequency.
        #
        # Measured, 390 cores: constraining at 200 MHz achieves 194.59 MHz; constraining at 190 MHz
        # achieves only 185.7 MHz. Asking for less genuinely produces a worse placement. So set the
        # PLL to the real target and add uncertainty to squeeze placement instead. `-add` stacks on
        # top of derive_clock_uncertainty rather than replacing it.
        if placement_margin:
            platform.toolchain.additional_sdc_commands += [
                f"set_clock_uncertainty -add -setup -from [get_clocks sys_clk] -to [get_clocks sys_clk] {placement_margin:.3f}",
            ]

        # Speed-over-power fitter settings.
        #
        # Quartus enables power optimisation by default, and it puts Stratix V ALMs on the CRITICAL
        # path into Low Power mode, which is slower than High Speed mode. Measured on the 210-core
        # build: the worst sys_clk path is the Blowfish round loop
        #     S-box read -> Add0 (32-bit) -> xor -> Add1 (32-bit) -> next S-box address
        # and every adder on it was reported as "Low Power" while the surrounding registers were
        # "High Speed". Trading power for speed is unambiguously the right call for this design.
        #
        # These are Quartus-only .qsf assignments, so they are Altera-only by construction and
        # cannot affect the Xilinx targets.
        # Measured cost/benefit at 1 core, 200 MHz constraint: Fmax 205.0 -> 222.5 MHz (+8.5%) for
        # 2,122 -> 2,856 ALMs (+35%); at 210 cores roughly 341 -> 417 ALMs/core. Spare logic is free
        # while M20K is the binding resource, but near the ~399-core M20K wall that extra ~15%/core
        # is the difference between ~80% and ~98% ALM utilisation, where routing pressure can give
        # the clock back. Hence the switch: keep it on below ~350 cores, measure both at the wall.
        if speed_opt:
            platform.toolchain.additional_qsf_commands += [
                "set_global_assignment -name OPTIMIZE_POWER_DURING_SYNTHESIS OFF",
                "set_global_assignment -name OPTIMIZE_POWER_DURING_FITTING OFF",
                "set_global_assignment -name OPTIMIZATION_TECHNIQUE SPEED",
                "set_global_assignment -name OPTIMIZATION_MODE \"AGGRESSIVE PERFORMANCE\"",
            ]

        # Fanout control, ported from the Vivado tuning in bcrypt_ypcb.py.
        #
        # That target caps sys_rst at MAX_FANOUT 100 (it measured fanout 1381 / a 5.7ns route) and
        # the arbiter broadcast registers at MAX_FANOUT 16. The same nets are far worse here --
        # measured on the 210-core Stratix V build, from the fitter's "Non-Global High Fan-Out
        # Signals" report:
        #     bcrypt_axis_8b|full_rst~0      fanout 13,920
        #     main_bcrypt_proxy13_din_r[*]   fanout ~860-880 each
        # Quartus's equivalent control is MAX_FANOUT as an instance assignment, which makes the
        # fitter replicate the driving register rather than route one net to thousands of loads.
        #
        # Quartus-only .qsf assignments, so Altera-only by construction; the Xilinx targets keep
        # using their own MAX_FANOUT properties unchanged.
        platform.toolchain.additional_qsf_commands += [
            "set_instance_assignment -name MAX_FANOUT 100 -to \"*full_rst*\"",
            "set_instance_assignment -name MAX_FANOUT 16 -to \"*din_r*\"",
            "set_instance_assignment -name MAX_FANOUT 16 -to \"*ctrl_r*\"",
            "set_instance_assignment -name MAX_FANOUT 16 -to \"*wr_en_r*\"",
        ]

        # JTAGBone and PCIe are mutually exclusive on Stratix V.
        #
        # JTAGBone instantiates the raw `stratixv_jtag` primitive, while the PCIe hard IP's
        # transceiver reconfiguration controller embeds a Nios II whose debug slave uses
        # `sld_virtual_jtag`. Quartus permits only one JTAG mechanism per design and rejects the
        # combination outright:
        #   Error (12143): JTAG primitive "stratixv_jtag" is already used in the design. Other
        #   entities that interface with JTAG via debug hub ... are not allowed
        # The same collision blocks DDR3 ECC (its PHY CSR block adds an altsource_probe SLD node).
        #
        # With PCIe present JTAGBone is redundant, since the host reaches the same Wishbone bus
        # over BAR0 MMIO and far faster, so PCIe simply takes precedence.
        if not with_pcie:
            self.add_jtagbone()
            platform.add_period_constraint(self.jtagbone_phy.cd_jtag.clk, 1e9/20e6)
            platform.add_false_path_constraints(self.jtagbone_phy.cd_jtag.clk, self.crg.cd_sys.clk)

        # NOTE: deliberately NO add_period_constraint() on cd_sys here. The Xilinx targets need one
        # because Vivado does not derive the PLL output clock, but on Quartus `derive_pll_clocks`
        # already constrains it. Adding one anyway emits `create_clock ... [get_nets {sys_clk}]`,
        # which defines a base clock that shadows the PLL-generated one. STA then loses the
        # clk125->sys relationship and the reset false-path below stops matching the real launch
        # clock, resurfacing as a ~-0.37ns setup violation on clk125.

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
        # add_sources() registers gateware/{util,pkt_comm,bcrypt} as both source dirs and Verilog
        # include paths. On Quartus the include paths become SEARCH_PATH entries, which is also how
        # bcrypt_data.v's $readmemh("S_data.txt", ...) resolves. S_data.txt lives in gateware/bcrypt.
        #
        # vendor="altera" swaps gateware/bcrypt/bcrypt_core/S.v for gateware/bcrypt_altera/S.v,
        # whose S-box read path has no reset on the output register and therefore infers M20K
        # instead of 32,768 flip-flops plus four 256:1 soft mux trees per core. This selection is
        # local to this target. The Xilinx targets call add_sources() with the default vendor and
        # compile the original file unchanged.
        self.bcrypt.add_sources(vendor="altera")

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

        # PCIe -------------------------------------------------------------------------------------
        # Stratix V PCIe hard IP via litepcie.phy.svpciephy. Connector 0 (PCIE1, edge lanes 0-7) is
        # the half that a single-x8-wired slot actually connects; it lives on the hard IP block that
        # Quartus hides, so building this needs the sv_second_pcie_hip LD_PRELOAD shim.
        if with_pcie:
            self.pcie_phy = SVPCIEPHY(platform, platform.request("pcie_x8", pcie_connector),
                data_width = pcie_data_width,
                speed      = pcie_speed,
                nlanes     = pcie_lanes,
                # MUST cover the streamer/recorder SRAMs, not just the CSR region. The memory map is
                #   csr           0x00000000  64 KiB
                #   streamer_mem  0x00040000   1 KiB
                #   recorder_mem  0x00080000   1 KiB
                # so a 128 KiB BAR0 reaches the CSRs but leaves both SRAMs unreachable from the host
                # so the core can be kicked but never fed a packet or read for a result. 1 MiB spans
                # the whole map, and matches what bcrypt_acorn.py uses on Xilinx.
                bar0_size  = 0x10_0000,
                mgmt_clk   = self.crg.cd_pcie_mgmt.clk,
                mgmt_rst   = self.crg.cd_pcie_mgmt.rst,
                mgmt_clk_name = "pcie_mgmt_clk",
            )
            self.add_pcie(phy=self.pcie_phy, ndmas=pcie_ndmas)

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

# PCIe hard IP interposer ---------------------------------------------------------------------------

def build_pcie_hip_shim(output_dir):
    """Compile software/quartus/sv_pcie_hip_enable.c and return the .so path.

    Built into the build directory rather than shipped as a binary, and rebuilt only when the source
    is newer. Connector 0 cannot be fitted without it.
    """
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "software", "quartus", "sv_pcie_hip_enable.c")
    if not os.path.exists(src):
        raise SystemExit(f"PCIe hard IP interposer source is missing: {src}")

    # Absolute: LiteX's build script chdirs into the gateware directory before invoking Quartus, and
    # ld.so resolves LD_PRELOAD relative to the process CWD, so a relative path fails with
    # "Error (11176): Ld.so: object ... from LD_PRELOAD cannot be preloaded".
    so = os.path.abspath(os.path.join(output_dir, "sv_pcie_hip_enable.so"))
    os.makedirs(output_dir, exist_ok=True)
    if os.path.exists(so) and os.path.getmtime(so) >= os.path.getmtime(src):
        return so

    cc = os.environ.get("CC", "gcc")
    if shutil.which(cc) is None:
        raise SystemExit(
            f"Connector 0 needs the PCIe hard IP interposer, which requires {cc} to build.\n"
            f"Install it, set CC, pass a prebuilt --pcie-shim, or build for --pcie-connector 1\n"
            f"(connector 1 trains at width x0 in a slot wired for x8, since only edge lanes 0-7\n"
            f"are connected there)."
        )

    cmd = [cc, "-shared", "-fPIC", "-O2", "-o", so, src, "-ldl"]
    if subprocess.call(cmd) != 0:
        raise SystemExit("Failed to build the PCIe hard IP interposer: " + " ".join(cmd))
    print(f"[PCIe] built hard IP interposer: {so}")
    return so

# Build --------------------------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Bcrypt on Microsoft Storey Peak.")

    # Build/Load Arguments.
    # ---------------------
    parser.add_argument("--build",        action="store_true",           help="Build bitstream.")
    parser.add_argument("--load",         action="store_true",           help="Load bitstream.")
    parser.add_argument("--sys-clk-freq", default=100e6, type=float,     help="System clock frequency.")

    # Bcrypt Configuration.
    # ---------------------
    parser.add_argument("--num-proxies",     type=int, default=1, help="Number of Bcrypt proxies.")
    parser.add_argument("--cores-per-proxy", type=int, default=1, help="Number of cores per proxy.")

    # Analyzer.
    # ---------
    parser.add_argument("--with-analyzer", action="store_true", help="Add LiteScope analyzer on AXI streams.")
    parser.add_argument("--with-pcie",        action="store_true", help="Add PCIe endpoint (needs sv_second_pcie_hip LD_PRELOAD for connector 0).")
    parser.add_argument("--pcie-connector",   type=int, default=0, choices=[0,1], help="Which x8 half of the edge connector.")
    parser.add_argument("--pcie-lanes",       type=int, default=8, help="PCIe lanes.")
    parser.add_argument("--pcie-data-width",  type=int, default=128, help="PCIe datapath width.")
    parser.add_argument("--pcie-mgmt-freq",   type=float, default=50e6, help="Transceiver reconfiguration management clock. 50e6 keeps sys_clk on exact PLL ratios; 100e6 is Intel's documented minimum.")
    parser.add_argument("--placement-margin", type=float, default=0.0, help="Extra ns of setup clock uncertainty on sys_clk to over-constrain placement (e.g. 0.5).")
    parser.add_argument("--no-speed-opt", action="store_true", help="Disable Quartus speed-over-power fitter settings (saves ~15%% ALMs/core).")
    parser.add_argument("--build-suffix", default="", help="Suffix for the build name, so concurrent experiments at different clocks or seeds do not share a directory.")
    parser.add_argument("--fitter-seed",  type=int, default=None, help="Quartus fitter seed. Different seeds give different placements and a spread of Fmax.")
    parser.add_argument("--pcie-shim",     default=None, help="Path to sv_second_pcie_hip preload_me.so. Required for --pcie-connector 0; also read from SV_PCIE_SHIM.")
    parser.add_argument("--num-processors", type=int, default=None, help="Cap Quartus parallel processors, so several experiment builds can share a machine.")
    args = parser.parse_args()

    # Build SoC.
    # ----------
    def get_build_name():
        name = f"bcrypt_sp_p{args.num_proxies}_c{args.cores_per_proxy}"
        return name + (f"_{args.build_suffix}" if args.build_suffix else "")

    soc = BaseSoC(
        # Generic.
        sys_clk_freq    = args.sys_clk_freq,

        # Bcrypt.
        num_proxies     = args.num_proxies,
        cores_per_proxy = args.cores_per_proxy,

        # Analyzer.
        with_analyzer   = args.with_analyzer,
        speed_opt       = not args.no_speed_opt,
        placement_margin= args.placement_margin,
        with_pcie       = args.with_pcie,
        pcie_connector  = args.pcie_connector,
        pcie_lanes      = args.pcie_lanes,
        pcie_data_width = args.pcie_data_width,
        pcie_mgmt_freq  = args.pcie_mgmt_freq,
    )

    if args.fitter_seed is not None:
        soc.platform.toolchain.additional_qsf_commands += [
            f"set_global_assignment -name SEED {args.fitter_seed}",
        ]
    if args.num_processors is not None:
        soc.platform.toolchain.additional_qsf_commands += [
            f"set_global_assignment -name NUM_PARALLEL_PROCESSORS {args.num_processors}",
        ]

    output_dir = os.path.join("build", get_build_name())

    # Connector 0 sits on a PCIe hard IP block Quartus reports as disabled, so the Fitter refuses it
    # with Error (175020) before placement starts. software/quartus/sv_pcie_hip_enable.c answers
    # "enabled" for that one block and forwards every other query; see its header for the detail.
    #
    # LiteX's quartus.py run_script() calls subprocess.call() with no env=, so the Quartus child
    # inherits os.environ from this process and setting LD_PRELOAD here is enough.
    if args.build and args.with_pcie and args.pcie_connector == 0:
        shim = args.pcie_shim or os.environ.get("SV_PCIE_SHIM") or build_pcie_hip_shim(output_dir)
        quartus_lib = os.path.join(os.path.dirname(os.path.dirname(
            shutil.which("quartus_sh") or "")), "linux64")
        os.environ["LD_PRELOAD"] = shim
        os.environ["LD_LIBRARY_PATH"] = os.pathsep.join(
            [p for p in [quartus_lib, os.environ.get("LD_LIBRARY_PATH", "")] if p])
    builder = Builder(soc, output_dir=output_dir, csr_csv=os.path.join(output_dir, "csr.csv"))
    builder.build(build_name=get_build_name(), run=args.build)

    # Load FPGA.
    # ----------
    if args.load:
        prog = soc.platform.create_programmer()
        prog.load_bitstream(builder.get_bitstream_filename(mode="sram"))

if __name__ == "__main__":
    main()
