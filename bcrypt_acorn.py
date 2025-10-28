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

from litex.soc.interconnect.csr     import *
from litex.soc.integration.soc_core import *
from litex.soc.integration.builder  import *

from litex.soc.cores.clock import *
from litex.soc.cores.led   import LedChaser

from litepcie.software      import generate_litepcie_software
from litepcie.software      import generate_litepcie_software_headers
from litepcie.phy.s7pciephy import S7PCIEPHY

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
    def __init__(self, sys_clk_freq=125e6, with_led_chaser=True, **kwargs):
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

        # Bcrypt -----------------------------------------------------------------------------------

        from gateware.bcrypt_proxy import BcryptProxy
        self.bcrypt_proxy = BcryptProxy(n_cores=1)
        self.bcrypt_proxy.add_sources()

        class BcryptProxyControl(LiteXModule):
            # FIXME: Fake dummy control, just to avoid logic pruning.
            def __init__(self, bcrypt_proxy):
                self._din   = CSRStorage(8)
                self._ctrl  = CSRStorage()
                self._wr_en = CSRStorage()

                self._init_ready  = CSRStatus()
                self._crypt_ready = CSRStatus()

                self._rd_en = CSRStorage()
                self._empty = CSRStatus()
                self._dout  = CSRStatus()

                # # #

                self.comb += [
                    bcrypt_proxy.din.eq(self._din.storage),
                    bcrypt_proxy.ctrl.eq(self._ctrl.storage),
                    bcrypt_proxy.wr_en.eq(self._wr_en.storage),

                    self._init_ready.status.eq(bcrypt_proxy.init_ready),
                    self._crypt_ready.status.eq(bcrypt_proxy.crypt_ready),

                    bcrypt_proxy.rd_en.eq(self._rd_en.storage),
                    self._empty.status.eq(bcrypt_proxy.empty),
                    self._dout.status.eq(bcrypt_proxy.dout),
                ]

        self.bcrypt_proxy_control = BcryptProxyControl(bcrypt_proxy=self.bcrypt_proxy)

# Build --------------------------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Bcrypt on SQRL Acorn.")

    # Build/Load/Flash Arguments.
    # ---------------------------
    parser.add_argument("--build", action="store_true", help="Build bitstream.")
    parser.add_argument("--load",  action="store_true", help="Load bitstream.")
    parser.add_argument("--flash", action="store_true", help="Flash bitstream.")

    args = parser.parse_args()

    # Build SoC.
    # ----------
    soc = BaseSoC()
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
