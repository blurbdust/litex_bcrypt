#!/usr/bin/env python3

import os

from migen import *

from litex.gen import *

# Bcrypt Proxy -------------------------------------------------------------------------------------

class BcryptProxy(LiteXModule):
    def __init__(self, n_cores=1):
        self.din         = Signal(8)
        self.ctrl        = Signal(2)
        self.wr_en       = Signal()

        self.init_ready  = Signal()
        self.crypt_ready = Signal()

        self.rd_en       = Signal()
        self.empty       = Signal()
        self.dout        = Signal()

        # # #

        # Bcrypt Proxy Instance.
        self.specials += Instance("bcrypt_proxy",
            # Parameters.
            p_NUM_CORES       = n_cores,
            p_DUMMY           = 0, # FIXME/CHECKME.
            p_CORES_NOT_DUMMY = 0, # FIXME/CHECKME.

            # Clk/Config.
            i_CLK             = ClockSignal("sys"),
            i_mode_cmp        = 0b0,

            # Input stream.
            i_din             = self.din,
            i_ctrl            = self.ctrl,
            i_wr_en           = self.wr_en,
            o_init_ready      = self.init_ready,
            o_crypt_ready     = self.crypt_ready,

            # Output stream.
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
