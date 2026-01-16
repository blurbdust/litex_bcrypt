#!/usr/bin/env python3

#
# This file is part of LiteX-Bcrypt.
#
# Bcrypt Proxy Wrapper.
#
# Lightweight LiteX/Migen wrapper around the Verilog `bcrypt_proxy` module. Exposes an 8-bit
# streaming interface + minimal control/status to the SoC.

from litex.gen import *

# BcryptProxy --------------------------------------------------------------------------------------

class BcryptProxy(LiteXModule):
    """
    BcryptProxy.

    Thin LiteX wrapper for `bcrypt_proxy` (Verilog). One instance may encapsulate multiple backend
    cores selected by parameters.
    """
    def __init__(self, n_cores=1, dummy=0, cores_not_dummy=0):
        # IOs.
        # ----
        self.din   = Signal(8)   # 8-bit data to proxy.
        self.ctrl  = Signal(2)   # control (INIT/DATA/END).
        self.wr_en = Signal()    # write strobe.

        self.init_ready  = Signal()  # proxy ready for INIT phase.
        self.crypt_ready = Signal()  # proxy ready for DATA phase.

        self.rd_en = Signal()    # read strobe from proxy.
        self.empty = Signal()    # output FIFO empty.
        self.dout  = Signal()    # 1-bit serialized output.

        # Control.
        # --------
        self.mode_cmp = Signal(reset=1)  # default to compare mode.
        self.rst      = Signal()         # reset signal from bcrypt core.

        # Instance.
        # ---------
        self.specials += Instance("bcrypt_proxy",
            p_NUM_CORES       = n_cores,
            p_DUMMY           = dummy,
            p_CORES_NOT_DUMMY = cores_not_dummy,

            i_CLK             = ClockSignal("sys"),
            i_rst             = self.rst,
            i_mode_cmp        = self.mode_cmp,

            i_din             = self.din,
            i_ctrl            = self.ctrl,
            i_wr_en           = self.wr_en,
            o_init_ready      = self.init_ready,
            o_crypt_ready     = self.crypt_ready,

            i_rd_en           = self.rd_en,
            o_empty           = self.empty,
            o_dout            = self.dout,
        )

    # Sources --------------------------------------------------------------------------------------
    def add_sources(self):
        """Register Verilog sources and include path for `bcrypt_proxy`."""
        from litex.gen import LiteXContext
        cur_dir = os.path.dirname(__file__)
        rtl_dir = os.path.join(cur_dir, "bcrypt")
        LiteXContext.platform.add_verilog_include_path(rtl_dir)
        LiteXContext.platform.add_source_dir(rtl_dir)
