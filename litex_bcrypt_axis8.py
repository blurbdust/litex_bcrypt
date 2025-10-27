# SPDX-License-Identifier: BSD-2-Clause
#
# litex_bcrypt_axis8.py — LiteX integration (symmetric 8-bit streams)
#
import os

from migen import *
from litex.gen import LiteXModule
from litex.soc.interconnect.csr import CSRStorage, CSRStatus, AutoCSR, CSRField
from litex.soc.interconnect import stream

class BcryptCoreAXIS8(LiteXModule, AutoCSR):
    def __init__(self, platform, num_cores=1):
        # Stream endpoints (8-bit + last)
        self.sink   = stream.Endpoint([('data', 8)])
        self.source = stream.Endpoint([('data', 8)])

        # CSRs
        self._ctrl  = CSRStorage(fields=[
            CSRField("mode_cmp", size=1, reset=0),
            CSRField("output_mode_limit", size=1, reset=0),
            CSRField("reg_output_limit",  size=1, reset=0)
        ], reset=0)
        self._app_status      = CSRStatus(8, name="app_status")
        self._pkt_comm_status = CSRStatus(8, name="pkt_comm_status")
        self._idle            = CSRStatus(fields=[CSRField("idle", size=1)])
        self._error           = CSRStatus(fields=[CSRField("error", size=1)])

        platform.add_source("bcrypt_axis8_wrap.sv")

        # Core array passthroughs (tie off or expose later)
        core_din   = Signal(8)
        core_ctrl  = Signal(2)
        core_wr_en = Signal(num_cores)
        core_rd_en = Signal(num_cores)
        core_init_ready = Signal(num_cores)
        core_crypt_ready= Signal(num_cores)
        core_empty = Signal(num_cores)
        core_dout  = Signal(num_cores)

        self.specials += Instance("bcrypt_axis8_wrap",
            p_NUM_CORES      = num_cores,
            i_CORE_CLK       = ClockSignal(),
            i_CORE_RSTN      = ~ResetSignal(),

            # AXIS IN 8-bit
            i_s_axis_tdata   = self.sink.data,
            i_s_axis_tvalid  = self.sink.valid,
            o_s_axis_tready  = self.sink.ready,
            i_s_axis_tlast   = self.sink.last,

            # AXIS OUT 8-bit
            o_m_axis_tdata   = self.source.data,
            o_m_axis_tvalid  = self.source.valid,
            i_m_axis_tready  = self.source.ready,
            o_m_axis_tlast   = self.source.last,

            # CSRs
            i_mode_cmp          = self._ctrl.fields.mode_cmp,
            i_output_mode_limit = self._ctrl.fields.output_mode_limit,
            i_reg_output_limit  = self._ctrl.fields.reg_output_limit,

            o_app_status        = self._app_status.status,
            o_pkt_comm_status   = self._pkt_comm_status.status,
            o_idle              = self._idle.fields.idle,
            o_error_o           = self._error.fields.error,

            # Core array
            o_core_din          = core_din,
            o_core_ctrl         = core_ctrl,
            o_core_wr_en        = core_wr_en,
            i_core_init_ready   = core_init_ready,
            i_core_crypt_ready  = core_crypt_ready,
            o_core_rd_en        = core_rd_en,
            i_core_empty        = core_empty,
            i_core_dout         = core_dout
        )

    def add_sources(self):
        from litex.gen import LiteXContext
        cur_dir = os.path.dirname(__file__)
        for name in ["util", "pkt_comm", "bcrypt"]:
            rtl_dir = os.path.join(cur_dir, f"gateware/{name}")
            LiteXContext.platform.add_verilog_include_path(rtl_dir)
            LiteXContext.platform.add_source_dir(rtl_dir)

