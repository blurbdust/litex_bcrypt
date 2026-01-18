# Example efforts needed to port

The clocking information is taken from [litex_boards/platforms/ypcb_00338_1p1.py](https://github.com/litex-hub/litex-boards/blob/98106a18a234d161f723e1fad9c04e510d3c80f1/litex_boards/platforms/ypcb_00338_1p1.py#L28)
Along with usage of the clock [litex_boards/targets/ypcb_00338_1p1.py#L48](https://github.com/litex-hub/litex-boards/blob/98106a18a234d161f723e1fad9c04e510d3c80f1/litex_boards/targets/ypcb_00338_1p1.py#L48) and any PCIe usage requirements [litex_boards/targets/ypcb_00338_1p1.py#L99](https://github.com/litex-hub/litex-boards/blob/98106a18a234d161f723e1fad9c04e510d3c80f1/litex_boards/targets/ypcb_00338_1p1.py#L99)

Then it's just a simple matching of your target board within LiteX for the differing areas or usage of clock and/or PCIe
[litex_boards/platforms/sqrl_fk33.py](https://github.com/litex-hub/litex-boards/blob/98106a18a234d161f723e1fad9c04e510d3c80f1/litex_boards/platforms/sqrl_fk33.py#L17)
[litex_boards/targets/sqrl_fk33.py#L50](https://github.com/litex-hub/litex-boards/blob/98106a18a234d161f723e1fad9c04e510d3c80f1/litex_boards/targets/sqrl_fk33.py#L50)
[litex_boards/targets/sqrl_fk33.py#L103](https://github.com/litex-hub/litex-boards/blob/98106a18a234d161f723e1fad9c04e510d3c80f1/litex_boards/targets/sqrl_fk33.py#L103)

You will need a Vivado license to synthesize for the new board and something like the YPCB is not included in the free license.

## Example diff for quick port

```diff
6c6
< # bcrypt_ypcb.py — Bcrypt on YPCB-00338-1P1
---
> # bcrypt_fk33.py — Bcrypt on SQRL FK33
25c25
< from litex_boards.platforms import ypcb_00338_1p1
---
> from litex_boards.platforms import sqrl_fk33
36a37,38
> from litepcie.core import LitePCIeEndpoint, LitePCIeMSI
> 
38c40
< from litepcie.phy.s7pciephy import S7PCIEPHY
---
> from litepcie.phy.usppciephy import USPHBMPCIEPHY
51d52
<         self.cd_idelay = ClockDomain()
53,64c54,57
<         # Clk/Rst.
<         clk200    = platform.request("clk200")
<         clk200_se = Signal()
<         self.specials += DifferentialInput(clk200.p, clk200.n, clk200_se)
<         rst_n = platform.request("rst_n")
< 
<         # PLL.
<         self.pll = pll = S7MMCM(speedgrade=-2)
<         self.comb += pll.reset.eq(~rst_n | self.rst)
<         pll.register_clkin(clk200_se, 200e6)
<         pll.create_clkout(self.cd_sys,       sys_clk_freq)
<         pll.create_clkout(self.cd_idelay,    200e6)
---
>         self.pll = pll = USPMMCM(speedgrade=-2)
>         self.comb += pll.reset.eq(self.rst)
>         pll.register_clkin(platform.request("clk200"), 200e6)
>         pll.create_clkout(self.cd_sys, sys_clk_freq)
67,68d59
<         # IDelayCtrl.
<         self.idelayctrl = S7IDELAYCTRL(self.cd_idelay)
73c64
<     def __init__(self, sys_clk_freq=139e6, with_led_chaser=True, num_proxies=1, cores_per_proxy=1, with_analyzer=False, **kwargs):
---
>     def __init__(self, sys_clk_freq=125e6, with_led_chaser=True, num_proxies=1, cores_per_proxy=1, with_analyzer=False, **kwargs):
77c68
<         platform = ypcb_00338_1p1.Platform()
---
>         platform = sqrl_fk33.Platform()
86c77
<             ident         = f"Bcrypt on YPCB (p{num_proxies} x c{cores_per_proxy}) / built on",
---
>             ident         = f"Bcrypt on FK33 (p{num_proxies} x c{cores_per_proxy}) / built on",
100,101c91,92
<         self.pcie_phy = S7PCIEPHY(platform, platform.request("pcie_x8"),
<             data_width = 128,
---
>         self.pcie_phy = USPHBMPCIEPHY(platform, platform.request("pcie_x8"),
>             data_width = 256,
104,111d94
<         self.pcie_phy.update_config({
<             "Base_Class_Menu"          : "Encryption/Decryption_controllers",
<             "Sub_Class_Interface_Menu" : "Other_en/decryption",
<             "Class_Code_Base"          : "0B",
<             "Class_Code_Sub"           : "80",
<         })
< 
< 
117,139d99
<         # Timings False Paths.
<         # --------------------
<         false_paths = [
<             ("{{*s7pciephy_clkout0}}", "{{sys_clk}}"),
<             ("{{*s7pciephy_clkout1}}", "{{sys_clk}}"),
<             ("{{*s7pciephy_clkout3}}", "{{sys_clk}}"),
<             ("{{*s7pciephy_clkout0}}", "{{*s7pciephy_clkout1}}")
<         ]
<         for clk0, clk1 in false_paths:
<             platform.toolchain.pre_placement_commands.append(f"set_false_path -from [get_clocks {clk0}] -to [get_clocks {clk1}]")
<             platform.toolchain.pre_placement_commands.append(f"set_false_path -from [get_clocks {clk1}] -to [get_clocks {clk0}]")
< 
<         platform.toolchain.pre_placement_commands.append("reset_property LOC [get_cells -hierarchical -filter {{NAME=~pcie_s7/*gtx_channel.gtxe2_channel_i}}]")
<         platform.toolchain.pre_placement_commands.append("set_property LOC GTXE2_CHANNEL_X0Y23 [get_cells -hierarchical -filter {{NAME=~pcie_s7/*pipe_lane[0].gt_wrapper_i/gtx_channel.gtxe2_channel_i}}]")
<         platform.toolchain.pre_placement_commands.append("set_property LOC GTXE2_CHANNEL_X0Y22 [get_cells -hierarchical -filter {{NAME=~pcie_s7/*pipe_lane[1].gt_wrapper_i/gtx_channel.gtxe2_channel_i}}]")
<         platform.toolchain.pre_placement_commands.append("set_property LOC GTXE2_CHANNEL_X0Y21 [get_cells -hierarchical -filter {{NAME=~pcie_s7/*pipe_lane[2].gt_wrapper_i/gtx_channel.gtxe2_channel_i}}]")
<         platform.toolchain.pre_placement_commands.append("set_property LOC GTXE2_CHANNEL_X0Y20 [get_cells -hierarchical -filter {{NAME=~pcie_s7/*pipe_lane[3].gt_wrapper_i/gtx_channel.gtxe2_channel_i}}]")
< 
<         platform.toolchain.pre_placement_commands.append("set_property LOC GTXE2_CHANNEL_X0Y19 [get_cells -hierarchical -filter {{NAME=~pcie_s7/*pipe_lane[4].gt_wrapper_i/gtx_channel.gtxe2_channel_i}}]")
<         platform.toolchain.pre_placement_commands.append("set_property LOC GTXE2_CHANNEL_X0Y18 [get_cells -hierarchical -filter {{NAME=~pcie_s7/*pipe_lane[5].gt_wrapper_i/gtx_channel.gtxe2_channel_i}}]")
<         platform.toolchain.pre_placement_commands.append("set_property LOC GTXE2_CHANNEL_X0Y17 [get_cells -hierarchical -filter {{NAME=~pcie_s7/*pipe_lane[6].gt_wrapper_i/gtx_channel.gtxe2_channel_i}}]")
<         platform.toolchain.pre_placement_commands.append("set_property LOC GTXE2_CHANNEL_X0Y16 [get_cells -hierarchical -filter {{NAME=~pcie_s7/*pipe_lane[7].gt_wrapper_i/gtx_channel.gtxe2_channel_i}}]")
< 
214c174
<     parser = argparse.ArgumentParser(description="Bcrypt on YPCB-00338-1P1.")
---
>     parser = argparse.ArgumentParser(description="Bcrypt on SQRL FK33.")
```
