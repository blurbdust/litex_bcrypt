#!/usr/bin/env python3

import os
import sys
import socket
import argparse

from migen import *

from litex.gen import *

from litex.build.generic_platform import *
from litex.build.sim              import SimPlatform
from litex.build.sim.config       import SimConfig
from litex.build.sim.verilator    import verilator_build_args, verilator_build_argdict

from litex.soc.integration.common   import *
from litex.soc.integration.soc_core import *
from litex.soc.integration.builder  import *
from litex.soc.interconnect.csr     import *

from litex.soc.integration.soc import SoCRegion
from litex.soc.interconnect import wishbone

# IOs ----------------------------------------------------------------------------------------------

_io = [
    # Clk / Rst.
    ("sys_clk", 0, Pins(1)),
    ("sys_rst", 0, Pins(1)),

    # Serial.
    ("serial", 0,
        Subsignal("source_valid", Pins(1)),
        Subsignal("source_ready", Pins(1)),
        Subsignal("source_data",  Pins(8)),

        Subsignal("sink_valid",   Pins(1)),
        Subsignal("sink_ready",   Pins(1)),
        Subsignal("sink_data",    Pins(8)),
    ),
]

# Platform -----------------------------------------------------------------------------------------

class Platform(SimPlatform):
    def __init__(self):
        SimPlatform.__init__(self, "SIM", _io)

# Helpers ------------------------------------------------------------------------------------------

# Proxy micro-protocol CTRLs (match bcrypt.vh)
CTRL_INIT_START = 0b01
CTRL_DATA_START = 0b10
CTRL_END        = 0b11

def le_bytes_from_word32(w):
    return [(w >> (8*i)) & 0xff for i in range(4)]  # LSB-first

def build_init_stream(s_data_path=None):
    """INIT: 30 words P/MW + 1024 words S (LSB-first per word)."""
    # P[0..17]
    P = [
        0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
        0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
        0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
        0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
        0x9216d5d9, 0x8979fb1b,
    ]
    # P[18..23] reserved
    P += [0x00000000]*6
    # P[24..29] MW
    P += [0x65616E42, 0x4F727068, 0x64657253, 0x65686F6C, 0x6F756274, 0x63727944]

    # S[0..1023]
    if s_data_path is None:
        cand_local = "gateware/bcrypt/S_data.txt"
        if os.path.exists(cand_local):
            s_data_path = cand_local
        else:
            raise SystemExit("S_data.txt not found. Put it at gateware/bcrypt/S_data.txt or set BCRYPT_RTL.")

    S = []
    with open(s_data_path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                S.append(int(line, 16))
    if len(S) != 1024:
        raise SystemExit(f"Expected 1024 S words, got {len(S)} from {s_data_path}")

    stream = []
    for w in P: stream += le_bytes_from_word32(w)
    for w in S: stream += le_bytes_from_word32(w)
    return stream

def build_data_stream(salt16_le, iter_count, pkt_id=0x1234, word_id=0xABCD):
    """
    DATA (31 words):
      EK[18], 64, iter_count, salt[4], IDs[2], cmp_data[5]
    All words emitted LSB-first on the 8-bit bus.
    """
    words = []
    # Dummy EK (deterministic) — replace with real EK to get true bcrypt results.
    for i in range(18):
        words.append(0x11110000 + i)

    words.append(64)  # d64
    words.append(iter_count & 0xFFFFFFFF)

    assert len(salt16_le) == 16
    for i in range(4):
        b0,b1,b2,b3 = [salt16_le[4*i + k] for k in range(4)]
        words.append(b0 | (b1<<8) | (b2<<16) | (b3<<24))

    # IDs
    words.append(((pkt_id & 0xFFFF) | ((word_id & 0xFFFF)<<16)))
    words.append(0)

    # cmp_data[5]
    words += [0,0,0,0,0]
    assert len(words) == 31

    stream = []
    for w in words: stream += le_bytes_from_word32(w)
    return stream

# Simulation SoC -----------------------------------------------------------------------------------

class SimSoC(SoCCore):
    def __init__(self):
        # Platform ---------------------------------------------------------------------------------
        platform     = Platform()
        self.comb += platform.trace.eq(1) # Always enable tracing.
        sys_clk_freq = int(100e6)

        # SoCCore ----------------------------------------------------------------------------------

        SoCCore.__init__(self, platform, sys_clk_freq,
            cpu_type            = None,
            uart_name           = "sim",
        )

        # CRG --------------------------------------------------------------------------------------

        self.crg = CRG(platform.request("sys_clk"))

        # Bcrypt -----------------------------------------------------------------------------------

        from gateware.bcrypt_proxy import BcryptProxy
        self.bcrypt_proxy = BcryptProxy(n_cores=1)
        self.bcrypt_proxy.add_sources()

        # Optional: raw bit monitor (kept, harmless)
        mon = r"""
module sim_monitor(input clk, input pop, input bit_in);
    always @(posedge clk) if (pop) $display("[SIM] POP bit = %0d", bit_in);
endmodule
"""
        with open("sim_monitor.v", "w") as f: f.write(mon)
        platform.add_source("sim_monitor.v")

        # Result dumper (prints IDs and 6 words once a packet is captured)
        dump = r"""
module sim_dump(input clk, input done,
    input [31:0] id0, input [31:0] id1,
    input [31:0] h0,  input [31:0] h1, input [31:0] h2,
    input [31:0] h3,  input [31:0] h4, input [31:0] h5);
    always @(posedge clk) if (done) begin
        $display("=== BCRYPT PACKET ===");
        $display("ID0 = 0x%08x", id0);
        $display("ID1 = 0x%08x", id1);
        $display("H0  = 0x%08x", h0);
        $display("H1  = 0x%08x", h1);
        $display("H2  = 0x%08x", h2);
        $display("H3  = 0x%08x", h3);
        $display("H4  = 0x%08x", h4);
        $display("H5  = 0x%08x", h5);
    end
endmodule
"""
        with open("sim_dump.v", "w") as f: f.write(dump)
        platform.add_source("sim_dump.v")

        # Bcrypt Test ------------------------------------------------------------------------------
        salt_bytes = [0x04, 0x41, 0x10, 0x04, 0x00, 0x00, 0x41, 0x10] + [0x00]*8
        iter_count = 1

        init_stream = build_init_stream()
        data_stream = build_data_stream(salt_bytes, iter_count, pkt_id=0x1234, word_id=0xABCD)

        INIT_LEN = len(init_stream)    # 4216
        DATA_LEN = len(data_stream)    # 124

        init_idx = Signal(max=INIT_LEN)
        data_idx = Signal(max=DATA_LEN)

        # Simple timeouts so we don't hang if something’s off
        wait_init_rdy_to  = Signal(24)
        wait_crypt_rdy_to = Signal(24)

        # ------------------------
        # 1-bit output reader
        # ------------------------
        reading    = Signal(reset=0)
        bit_cnt    = Signal(9)   # 0..256 (+1 header)
        word_cnt   = Signal(4)   # 0..7 (2 IDs + 6 results)
        bit_idx    = Signal(5)   # 0..31 within word
        cur_word   = Signal(32)
        rd_en_pulse = Signal(reset=0)  # the only driver of rd_en

        id0 = Signal(32); id1 = Signal(32)
        h0  = Signal(32); h1  = Signal(32); h2 = Signal(32)
        h3  = Signal(32); h4  = Signal(32); h5 = Signal(32)

        # Connect ports (avoid combinational default on rd_en to prevent PROCASSWIRE)
        self.comb += [
            self.bcrypt_proxy.din.eq(0),
            self.bcrypt_proxy.ctrl.eq(0),
            self.bcrypt_proxy.wr_en.eq(0),
            self.bcrypt_proxy.rd_en.eq(rd_en_pulse),
        ]

        # Small monitors
        self.specials += Instance("sim_monitor",
            i_clk    = ClockSignal("sys"),
            i_pop    = rd_en_pulse & ~self.bcrypt_proxy.empty,
            i_bit_in = self.bcrypt_proxy.dout
        )

        # Kick reading when data appears; then shift header(1) + 8 words (256 bits), LSB-first.
        self.sync += [
            rd_en_pulse.eq(0),  # default: 0, pulse when starting burst

            If(~reading & ~self.bcrypt_proxy.empty,
                rd_en_pulse.eq(1),
                reading.eq(1),
                bit_cnt.eq(0),
                word_cnt.eq(0),
                bit_idx.eq(0),
                cur_word.eq(0)
            ).Elif(reading,
                bit_cnt.eq(bit_cnt + 1),
                If(bit_cnt > 0,  # skip the 1-bit header at bit_cnt==0
                    cur_word.eq(cur_word | (self.bcrypt_proxy.dout << bit_idx)),
                    bit_idx.eq(bit_idx + 1),

                    If(bit_idx == 31,
                        Case(word_cnt, {
                            0: [id0.eq(cur_word | (self.bcrypt_proxy.dout << 31))],
                            1: [id1.eq(cur_word | (self.bcrypt_proxy.dout << 31))],
                            2: [h0 .eq(cur_word | (self.bcrypt_proxy.dout << 31))],
                            3: [h1 .eq(cur_word | (self.bcrypt_proxy.dout << 31))],
                            4: [h2 .eq(cur_word | (self.bcrypt_proxy.dout << 31))],
                            5: [h3 .eq(cur_word | (self.bcrypt_proxy.dout << 31))],
                            6: [h4 .eq(cur_word | (self.bcrypt_proxy.dout << 31))],
                            7: [h5 .eq(cur_word | (self.bcrypt_proxy.dout << 31))],
                        }),
                        word_cnt.eq(word_cnt + 1),
                        bit_idx.eq(0),
                        cur_word.eq(0),
                        If(word_cnt == 7,
                            reading.eq(0)
                        )
                    )
                )
            )
        ]

        done = Signal()
        self.comb += done.eq((~reading) & (word_cnt == 8))
        self.specials += Instance("sim_dump",
            i_clk = ClockSignal("sys"),
            i_done = done,
            i_id0 = id0, i_id1 = id1,
            i_h0  = h0,  i_h1  = h1,  i_h2 = h2,
            i_h3  = h3,  i_h4  = h4,  i_h5 = h5
        )

        # FSM --------------------------------------------------------------------
        self.fsm = fsm = FSM(reset_state="WAIT_INIT_READY")

        # 1) Wait for init_ready from the core
        fsm.act("WAIT_INIT_READY",
            NextValue(wait_init_rdy_to, wait_init_rdy_to + 1),
            If(self.bcrypt_proxy.init_ready,
                NextValue(init_idx, 0),
                NextValue(wait_init_rdy_to, 0),
                NextState("INIT_START")
            ).Elif(wait_init_rdy_to == (2**24-1),
                NextState("DONE")  # timeout
            )
        )

        # 2) INIT: START
        fsm.act("INIT_START",
            self.bcrypt_proxy.wr_en.eq(1),
            self.bcrypt_proxy.ctrl.eq(CTRL_INIT_START),
            NextValue(init_idx, 0),
            NextState("INIT_STREAM")
        )

        # 3) INIT: streaming bytes (continuous)
        fsm.act("INIT_STREAM",
            self.bcrypt_proxy.wr_en.eq(1),
            self.bcrypt_proxy.din.eq(Array(init_stream)[init_idx]),
            If(init_idx == (INIT_LEN - 1),
                NextState("INIT_END")
            ).Else(
                NextValue(init_idx, init_idx + 1)
            )
        )

        # 4) INIT: END
        fsm.act("INIT_END",
            self.bcrypt_proxy.wr_en.eq(1),
            self.bcrypt_proxy.ctrl.eq(CTRL_END),
            NextValue(wait_crypt_rdy_to, 0),
            NextState("WAIT_CRYPT_READY")
        )

        # 5) Wait for crypt_ready from the core
        fsm.act("WAIT_CRYPT_READY",
            NextValue(wait_crypt_rdy_to, wait_crypt_rdy_to + 1),
            If(self.bcrypt_proxy.crypt_ready,
                NextValue(data_idx, 0),
                NextState("DATA_START")
            ).Elif(wait_crypt_rdy_to == (2**24-1),
                NextState("DONE")  # timeout
            )
        )

        # 6) DATA: START
        fsm.act("DATA_START",
            self.bcrypt_proxy.wr_en.eq(1),
            self.bcrypt_proxy.ctrl.eq(CTRL_DATA_START),
            NextState("DATA_STREAM")
        )

        # 7) DATA: bytes (continuous)
        fsm.act("DATA_STREAM",
            self.bcrypt_proxy.wr_en.eq(1),
            self.bcrypt_proxy.din.eq(Array(data_stream)[data_idx]),
            If(data_idx == (DATA_LEN - 1),
                NextState("DATA_END")
            ).Else(
                NextValue(data_idx, data_idx + 1)
            )
        )

        # 8) DATA: END
        fsm.act("DATA_END",
            self.bcrypt_proxy.wr_en.eq(1),
            self.bcrypt_proxy.ctrl.eq(CTRL_END),
            NextState("READ")
        )

        # 9) READ: let the 1-bit reader run; finish when a packet is captured (or nothing shows up).
        fsm.act("READ",
            If(done,
                NextState("DONE")
            ).Else(
                NextState("READ")
            )
        )

        fsm.act("DONE")

        # Sim Finish -------------------------------------------------------------------------------

        cycles = Signal(32)
        self.sync += cycles.eq(cycles + 1)
        self.sync += If(cycles == int(1e6), Finish())

# Build --------------------------------------------------------------------------------------------

def sim_args(parser):
    verilator_build_args(parser)

def main():
    parser = argparse.ArgumentParser(description="Bcrypt Sim.")
    sim_args(parser)
    args = parser.parse_args()

    verilator_build_kwargs = verilator_build_argdict(args)

    sys_clk_freq = int(1e6)
    sim_config   = SimConfig()
    sim_config.add_clocker("sys_clk", freq_hz=sys_clk_freq)
    sim_config.add_module("serial2console", "serial")

    # Build SoC.
    soc = SimSoC( )
    builder = Builder(soc, csr_csv="csr.csv")
    builder.build(sim_config=sim_config, **verilator_build_kwargs)

if __name__ == "__main__":
    main()
