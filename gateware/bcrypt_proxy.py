#!/usr/bin/env python3

import os

from migen import *

from litex.gen import *

# Bcrypt Proxy -------------------------------------------------------------------------------------

class BcryptProxy(LiteXModule):
    def __init__(self, n_cores=1, dummy=0, cores_not_dummy=0, clk_domain="sys"):
        # Proxy-side bus
        self.din         = Signal(8)
        self.ctrl        = Signal(2)
        self.wr_en       = Signal()

        self.init_ready  = Signal()
        self.crypt_ready = Signal()

        self.rd_en       = Signal()
        self.empty       = Signal()
        self.dout        = Signal()

        # Control
        self.mode_cmp    = Signal(reset=1)   # default: compare mode

        # Verilog proxy (instantiates n real cores internally).
        self.specials += Instance("bcrypt_proxy",
            p_NUM_CORES       = n_cores,
            p_DUMMY           = dummy,
            p_CORES_NOT_DUMMY = cores_not_dummy,

            i_CLK             = ClockSignal(clk_domain),
            i_mode_cmp        = self.mode_cmp,

            i_din             = self.din,
            i_ctrl            = self.ctrl,
            i_wr_en           = self.wr_en,
            o_init_ready      = self.init_ready,
            o_crypt_ready     = self.crypt_ready,

            i_rd_en           = self.rd_en,
            o_empty           = self.empty,
            o_dout            = self.dout
        )

    def add_sources(self):
        from litex.gen import LiteXContext
        cur_dir = os.path.dirname(__file__)
        rtl_dir = os.path.join(cur_dir, "bcrypt")
        LiteXContext.platform.add_verilog_include_path(rtl_dir)
        LiteXContext.platform.add_source_dir(rtl_dir)