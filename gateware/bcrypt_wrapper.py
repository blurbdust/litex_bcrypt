#!/usr/bin/env python3

#
# This file is part of LiteX-Bcrypt.
#
# Bcrypt AXIS8 Wrapper + Proxy Fanout.
#
# LiteX/Migen wrapper instantiating the Verilog AXIS8 top (bcrypt_axis_8b) and a set of BcryptProxy
# instances. Exposes 8-bit AXI-Stream sink/source and minimal CSRs.

import os

from migen import *

from litex.gen import *
from litex.soc.interconnect.csr import *

from litex.soc.interconnect import stream

from gateware.bcrypt_proxy import BcryptProxy

# BcryptWrapper ------------------------------------------------------------------------------------

class BcryptWrapper(LiteXModule):
    """
    Bcrypt AXIS8 Wrapper.

    Parameters
    ----------
    platform        : LiteX platform (used to register Verilog sources).
    num_proxies     : Number of proxies exposed to the arbiter (default: 1).
    cores_per_proxy : Number of real cores per proxy (default: 1).
    """
    def __init__(self, platform,
        num_proxies     = 1,
        cores_per_proxy = 1):
        # AXI-Stream 8-bit -------------------------------------------------------------------------
        self.sink   = stream.Endpoint([("data", 8)])  # IN  (data/valid/ready/last)
        self.source = stream.Endpoint([("data", 8)])  # OUT (data/valid/ready/last)

        # CSRs -------------------------------------------------------------------------------------
        self._ctrl = CSRStorage(fields=[
            CSRField("mode_cmp",          size=1, reset=1),
            CSRField("output_mode_limit", size=1, reset=0),
            CSRField("reg_output_limit",  size=1, reset=0),
        ])

        self._app_status      = CSRStatus(8)
        self._pkt_comm_status = CSRStatus(8)
        self._idle            = CSRStatus(fields=[CSRField("idle",  size=1)])
        self._error           = CSRStatus(fields=[CSRField("error", size=1)])
        self._clear_error     = CSRStorage(fields=[CSRField("clear", size=1, pulse=True)])

        # Proxy fanout bus -------------------------------------------------------------------------
        core_din         = Signal(8)
        core_ctrl        = Signal(2)
        core_wr_en       = Signal(num_proxies)
        core_rd_en       = Signal(num_proxies)
        core_init_ready  = Signal(num_proxies)
        core_crypt_ready = Signal(num_proxies)
        core_empty       = Signal(num_proxies)
        core_dout        = Signal(num_proxies)
        core_rst         = Signal()  # Reset signal from bcrypt core

        # Verilog AXIS8 wrapper --------------------------------------------------------------------
        self.specials += Instance("bcrypt_axis_8b",
            # Parameter.
            p_NUM_CORES = num_proxies,

            # Clk/Rst.
            i_CORE_CLK  = ClockSignal("sys"),
            i_CORE_RSTN = ~ResetSignal("sys"),

            # AXIS In.
            i_s_axis_tdata  = self.sink.data,
            i_s_axis_tvalid = self.sink.valid,
            o_s_axis_tready = self.sink.ready,
            i_s_axis_tlast  = self.sink.last,

            # AXIS Out.
            o_m_axis_tdata  = self.source.data,
            o_m_axis_tvalid = self.source.valid,
            i_m_axis_tready = self.source.ready,
            o_m_axis_tlast  = self.source.last,

            # CSRs.
            i_mode_cmp          = self._ctrl.fields.mode_cmp,
            i_output_mode_limit = self._ctrl.fields.output_mode_limit,
            i_reg_output_limit  = self._ctrl.fields.reg_output_limit,

            o_app_status      = self._app_status.status,
            o_pkt_comm_status = self._pkt_comm_status.status,
            o_idle            = self._idle.fields.idle,
            o_error_o         = self._error.fields.error,
            i_clear_error     = self._clear_error.fields.clear,

            # Proxy-level bus.
            o_core_din          = core_din,
            o_core_ctrl         = core_ctrl,
            o_core_wr_en        = core_wr_en,
            i_core_init_ready   = core_init_ready,
            i_core_crypt_ready  = core_crypt_ready,
            o_core_rd_en        = core_rd_en,
            i_core_empty        = core_empty,
            i_core_dout         = core_dout,
            # Reset signal for proxies/cores.
            o_core_rst          = core_rst,
        )

        # Proxies ----------------------------------------------------------------------------------
        #
        # Per-proxy pipeline registers for the high-fanout broadcast signals (din, ctrl).
        # The arbiter's core_din register was routing 7.3ns across SLR boundaries to reach
        # 450 core din_r_reg destinations (fanout=540). By adding a register per proxy,
        # the arbiter only drives 30 proxy registers (low fanout, short route) and each
        # proxy register drives 15 local cores (short route). This breaks the critical
        # path into two manageable hops.
        #
        # The +1 cycle latency on the forward path is safe: din/ctrl/wr_en are all delayed
        # consistently, and the ctrl sequence is held for many cycles. This latency is on
        # the password-assignment path, NOT the per-round Blowfish computation.

        for i in range(num_proxies):
            p = BcryptProxy(n_cores=cores_per_proxy)
            self.add_module(name=f"proxy{i}", module=p)

            # Per-proxy pipeline registers for broadcast signals (break SLR-crossing routes).
            proxy_din_r  = Signal(8, name=f"proxy{i}_din_r")
            proxy_ctrl_r = Signal(2, name=f"proxy{i}_ctrl_r")
            proxy_wr_en_r = Signal(name=f"proxy{i}_wr_en_r")

            self.sync += [
                proxy_din_r.eq(core_din),
                proxy_ctrl_r.eq(core_ctrl),
                proxy_wr_en_r.eq(core_wr_en[i]),
            ]

            self.comb += [
                # Mode and Reset.
                p.mode_cmp.eq(self._ctrl.fields.mode_cmp),
                p.rst.eq(core_rst),

                # TX to proxy (via pipeline registers).
                p.din.eq(proxy_din_r),
                p.ctrl.eq(proxy_ctrl_r),
                p.wr_en.eq(proxy_wr_en_r),

                # RX from proxy.
                p.rd_en.eq(core_rd_en[i]),
                core_init_ready[i].eq(p.init_ready),
                core_crypt_ready[i].eq(p.crypt_ready),
                core_empty[i].eq(p.empty),
                core_dout[i].eq(p.dout),
            ]

    # Sources --------------------------------------------------------------------------------------
    #
    # Vendor-specific source overrides.
    #
    # Some RTL in this tree is written against Xilinx primitive behaviour and has no
    # neutral formulation. Rather than change the shared file (and risk the hand-tuned
    # Xilinx QoR), the vendor-specific replacement lives in gateware/bcrypt_<vendor>/ and
    # the shared file is *excluded* from the source list for that vendor only.
    #
    # Maps vendor -> list of the shared files that vendor replaces, as paths relative to
    # this directory. Each entry is either
    #   "<rel/path.v>"                       -- replacement is bcrypt_<vendor>/path.v, or
    #   ("<rel/path.v>", "<basename.ext>")   -- replacement is bcrypt_<vendor>/basename.ext
    # (the second form only exists so a replacement may carry a different extension, e.g.
    # .sv, when the vendor-specific formulation needs SystemVerilog). A replacement must
    # keep the same module name(s) and port list(s) as the file it replaces.
    #
    # altera / bcrypt/bcrypt_core/S.v:
    #   The S-box RAM output register carries a reset (`if (rst_rd) S0_out <= 0;`).
    #   Xilinx block RAM has a dedicated output-register reset pin (RSTREG) so Vivado
    #   infers BRAM from this; Altera M20K has no such pin, so Quartus infers no memory
    #   at all and builds 32,768 flip-flops plus four 256:1 x 32b soft mux trees per
    #   core. gateware/bcrypt_altera/S.v moves the reset downstream of the output
    #   register as an AND mask -- cycle-for-cycle identical, see the proof in that file.
    #
    # altera / bcrypt/bcrypt_core/P_2x32.v:
    #   ATTRIBUTE-ONLY delta -- one synthesis attribute changes, every statement is
    #   byte-identical. PD is a 32x32 LUTRAM with an asynchronous read whose read
    #   address is the same signal as its write address; Xilinx maps that to a RAM32M,
    #   Quartus refuses to infer memory ("uninferred due to asynchronous read logic")
    #   and builds 1,024 flip-flops plus a 32:1 x 32b soft mux. ramstyle="MLAB,
    #   no_rw_check" puts it in an MLAB. See the proof in gateware/bcrypt_altera/P_2x32.v
    #   that PD's read-during-write result is never consumed.
    #
    # altera / util/asymm_bram.v:
    #   The mixed-width memory is described in the XST/Vivado idiom -- one narrow array
    #   with RATIO separate always blocks each reading a different low-order slice of the
    #   address space. Vivado infers one width-asymmetric BRAM; Quartus sees an array with
    #   four independent synchronous read ports, which no M20K configuration provides, and
    #   builds registers plus address decoders instead. Standalone on this device that
    #   instance is 8,306 ALMs / 0 M20K, and in-design it was 8,211 of the 10,443 ALMs of
    #   a 1-proxy 1-core build -- fixed overhead paid at every core count.
    #   gateware/bcrypt_altera/asymm_bram.sv gathers the RATIO narrow words into a packed
    #   dimension so the wide port is a single ordinary array read (1 ALM / 1 M20K). Same
    #   storage elements, same addresses, same enables, same read-before-write semantics;
    #   see the element-identity argument in that file.
    _vendor_overrides = {
        "altera": [
            os.path.join("bcrypt", "bcrypt_core", "S.v"),
            os.path.join("bcrypt", "bcrypt_core", "P_2x32.v"),
            (os.path.join("util", "asymm_bram.v"), "asymm_bram.sv"),
        ],
    }

    def add_sources(self, vendor="xilinx"):
        """
        Register Verilog include paths and source dirs used by the wrapper.

        Parameters
        ----------
        vendor : "xilinx" (default) or "altera". Selects vendor-specific RTL overrides.
                 The default keeps the Xilinx targets on exactly the source set they
                 have always used -- no Xilinx build behaviour changes.
        """
        from litex.gen import LiteXContext
        from litex.build import tools
        platform = LiteXContext.platform
        cur_dir  = os.path.dirname(__file__)

        # Files replaced by a vendor-specific variant, and therefore skipped below.
        excluded = set()
        overrides = self._vendor_overrides.get(vendor, [])
        if overrides:
            vendor_dir = os.path.join(cur_dir, f"bcrypt_{vendor}")
            platform.add_verilog_include_path(vendor_dir)
            for entry in overrides:
                rel, basename = entry if isinstance(entry, tuple) else (entry, os.path.basename(entry))
                excluded.add(os.path.abspath(os.path.join(cur_dir, rel)))
                platform.add_source(os.path.join(vendor_dir, basename))

        for name in ["util", "pkt_comm", "bcrypt"]:
            rtl_dir = os.path.join(cur_dir, name)
            if not os.path.isdir(rtl_dir):
                continue
            platform.add_verilog_include_path(rtl_dir)
            if not excluded:
                # Untouched legacy path for vendors with no overrides (Xilinx).
                platform.add_source_dir(rtl_dir)
                continue
            # Exactly the walk add_source_dir() does, including its language filter
            # (which is what keeps S_data.txt out of the source list -- it is
            # $readmemh'd through the SEARCH_PATH entries added above, not compiled),
            # minus the overridden files.
            for root, _dirs, files in os.walk(rtl_dir):
                for filename in sorted(files):
                    path = os.path.abspath(os.path.join(root, filename))
                    if path in excluded:
                        continue
                    language = tools.language_by_filename(path)
                    if language is not None:
                        platform.add_source(path, language)
