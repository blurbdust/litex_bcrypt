# Porting to Intel/Altera

Board documentation for the card used here: [Microsoft Azure X930613-001 on TheRetroWeb](https://theretroweb.com/expansioncards/s/microsoft-azure-x930613-001-fpga-card), [ruurdk/storey-peak](https://github.com/ruurdk/storey-peak), [devops.lol/azure-fpga](https://devops.lol/azure-fpga), and Jan Marjanović's blog series [Stratix V accelerator card from eBay](https://j-marjanovic.io/stratix-v-accelerator-card-from-ebay.html).

Clocking comes from [litex_boards/platforms/microsoft_storey_peak.py](https://github.com/litex-hub/litex-boards/blob/master/litex_boards/platforms/microsoft_storey_peak.py). Single-ended 125 MHz, `StratixVPLL` instead of `S7MMCM`, no `IDELAYCTRL`. PCIe uses `litepcie.phy.svpciephy`.

Built with Quartus Prime Standard 25.1std.

Three things that aren't in the diff:

Altera-specific RTL is selected in Python via `BcryptWrapper.add_sources(vendor="altera")`, which swaps `S.v` and `P_2x32.v` for versions in `gateware/bcrypt_altera/`. Quartus seems to ignore `RAM_STYLE`, and won't infer a RAM whose output register has a reset, so the S-boxes land in logic instead of M20K unless you restructure them.

Altera apparently only allows one JTAG mechanism per design, so JTAGBone and PCIe can't coexist.

Some PCIe hard IP blocks are marked disabled in Quartus's device database and it will not place a design on one. [sv_second_pcie_hip](https://github.com/ruurdk/sv_second_pcie_hip) is an `LD_PRELOAD` shim that makes Quartus report one such block as enabled at build time. It modifies nothing on disk, but you are using a block the vendor disabled, and anyone rebuilding needs the same shim. Avoid it if the block Quartus already exposes reaches the lanes your slot wires.

## Example diff for quick port

```diff
< from litex.build.io             import DifferentialInput
< from litex_boards.platforms import ypcb_00338_1p1
---
> from litex_boards.platforms import microsoft_storey_peak

< from litex.soc.cores.clock     import *
< from litepcie.phy.s7pciephy import S7PCIEPHY
---
> from litex.soc.cores.clock.intel_stratix5 import StratixVPLL
> from litepcie.phy.svpciephy import SVPCIEPHY

<     def __init__(self, platform, sys_clk_freq):
<         self.cd_idelay = ClockDomain()
<         clk200    = platform.request("clk200")
<         clk200_se = Signal()
<         self.specials += DifferentialInput(clk200.p, clk200.n, clk200_se)
<         rst_n = platform.request("rst_n")
<         self.pll = pll = S7MMCM(speedgrade=-2)
<         self.comb += pll.reset.eq(~rst_n | self.rst)
<         pll.register_clkin(clk200_se, 200e6)
<         pll.create_clkout(self.cd_sys, sys_clk_freq, reset_buf="bufg")
<         pll.create_clkout(self.cd_idelay, 200e6)
<         self.idelayctrl = S7IDELAYCTRL(self.cd_idelay)
---
>     def __init__(self, platform, sys_clk_freq, with_pcie_mgmt=False):
>         if with_pcie_mgmt:
>             self.cd_pcie_mgmt = ClockDomain()
>         clk125 = platform.request("clk125")
>         self.pll = pll = StratixVPLL(speedgrade="-C1")
>         self.comb += pll.reset.eq(self.rst)
>         pll.register_clkin(clk125, 125e6)
>         pll.create_clkout(self.cd_sys, sys_clk_freq)
>         if with_pcie_mgmt:
>             pll.create_clkout(self.cd_pcie_mgmt, 100e6)

<         self.add_jtagbone()
---
>         if not with_pcie:
>             self.add_jtagbone()

<         self.pcie_phy = S7PCIEPHY(platform, platform.request("pcie_x8"),
<             data_width = 128,
---
>         self.pcie_phy = SVPCIEPHY(platform, platform.request("pcie_x8", 0),
>             data_width = 128,
>             bar0_size  = 0x10_0000,
>             mgmt_clk   = self.crg.cd_pcie_mgmt.clk,
>             mgmt_rst   = self.crg.cd_pcie_mgmt.rst,

<         self.bcrypt.add_sources()
---
>         self.bcrypt.add_sources(vendor="altera")

<         # Timings False Paths / GTX LOC constraints (Vivado)
---
>         # (none needed, Quartus places transceivers itself)
```
