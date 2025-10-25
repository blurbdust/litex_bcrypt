#!/usr/bin/env python3

import os
import sys
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

    Note: This path feeds the two ID words and then echoes them back from the core.
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

    # IDs (what we expect to read back)
    words.append(((pkt_id & 0xFFFF) << 16) | (word_id & 0xFFFF))  # ID0 = {pkt_id, word_id}
    words.append(0x00000024)                                      # ID1 = example "gen_id"

    # cmp_data[5]
    words += [0,0,0,0,0]
    assert len(words) == 31

    stream = []
    for w in words: stream += le_bytes_from_word32(w)
    return stream

# Software model -----------------------------------------------------------------------------------
# Mirrors the core’s “Expand-Key-B (salt-only)” phase + final 64 enciphers.

def _bf_F(x, S0, S1, S2, S3):
    a = (x >> 24) & 0xff
    b = (x >> 16) & 0xff
    c = (x >>  8) & 0xff
    d = (x >>  0) & 0xff
    return ((((S0[a] + S1[b]) & 0xffffffff) ^ S2[c]) + S3[d]) & 0xffffffff

def _bf_encipher(l, r, P, S0, S1, S2, S3):
    for i in range(16):
        l = (l ^ P[i]) & 0xffffffff
        r = (r ^ _bf_F(l, S0, S1, S2, S3)) & 0xffffffff
        l, r = r, l
    l, r = r, l
    r = (r ^ P[16]) & 0xffffffff
    l = (l ^ P[17]) & 0xffffffff
    return l, r

def _expand_key_b_once(P, S0, S1, S2, S3, salt_words):
    # Expand-Key-B salt-only pass: rewrite P then S in pairs; XOR L/R with salt words before each encipher.
    L = 0
    R = 0
    sj = 0
    # P (18 entries --> 9 pairs)
    for i in range(0, 18, 2):
        L ^= salt_words[sj]; R ^= salt_words[(sj + 1) & 3]; sj = (sj + 2) & 3
        L, R = _bf_encipher(L, R, P, S0, S1, S2, S3)
        P[i], P[i+1] = L, R
    # S (4*256 entries)
    for box in (S0, S1, S2, S3):
        for i in range(0, 256, 2):
            L ^= salt_words[sj]; R ^= salt_words[(sj + 1) & 3]; sj = (sj + 2) & 3
            L, R = _bf_encipher(L, R, P, S0, S1, S2, S3)
            box[i], box[i+1] = L, R

# ---- Variant sweep helpers (endianness + iteration semantics + swaps) ----------------------------

def _byteswap32(w):
    return ((w & 0x000000FF) << 24) | ((w & 0x0000FF00) << 8) | ((w & 0x00FF0000) >> 8) | ((w & 0xFF000000) >> 24)

def _swap16(w):
    return ((w & 0xFFFF) << 16) | ((w >> 16) & 0xFFFF)

def _parse_word_from_bytes(b0, b1, b2, b3, mode):
    if mode == "LE":
        return (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) & 0xFFFFFFFF
    if mode == "BE":
        return (b3 | (b2 << 8) | (b1 << 16) | (b0 << 24)) & 0xFFFFFFFF
    if mode == "LE16":
        w = (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) & 0xFFFFFFFF
        return _swap16(w)
    if mode == "BE16":
        w = (b3 | (b2 << 8) | (b1 << 16) | (b0 << 24)) & 0xFFFFFFFF
        return _swap16(w)
    raise ValueError("bad mode")

def _decode_ek_words(data_stream, ek_mode):
    ek = []
    for i in range(18):
        off = 4*i
        ek.append(_parse_word_from_bytes(
            data_stream[off+0], data_stream[off+1], data_stream[off+2], data_stream[off+3], ek_mode))
    return ek

def _decode_salt_words(salt16_le_bytes, salt_mode):
    assert len(salt16_le_bytes) == 16
    words = []
    for i in range(4):
        b0,b1,b2,b3 = [salt16_le_bytes[4*i + k] for k in range(4)]
        words.append(_parse_word_from_bytes(b0,b1,b2,b3, salt_mode))
    return words

def _expand_times(iter_count, mode):
    if mode == "none":         return 0
    if mode == "iter":         return int(iter_count)
    if mode == "iter_plus_1":  return 1 + int(iter_count)
    if mode == "pow2":         return 1 << int(iter_count)
    raise ValueError(mode)

def _final_24_words(P, S0, S1, S2, S3):
    pt = b"OrpheanBeholderScryDoubt"
    blocks = []
    for i in range(3):
        b = pt[8*i:8*i+8]
        l = (b[0]<<24)|(b[1]<<16)|(b[2]<<8)|b[3]
        r = (b[4]<<24)|(b[5]<<16)|(b[6]<<8)|b[7]
        blocks.append((l, r))
    for _ in range(64):
        for i in range(3):
            l, r = blocks[i]
            l, r = _bf_encipher(l, r, P, S0, S1, S2, S3)
            blocks[i] = (l, r)
    out = []
    for (l, r) in blocks:
        out.append(l & 0xffffffff)
        out.append(r & 0xffffffff)
    return out  # 6 words

def compute_expected_variants(data_stream, s_data_path, salt_bytes, iter_count):
    # Load S base
    Sall = []
    with open(s_data_path, "r") as f:
        for ln in f:
            ln = ln.strip()
            if ln:
                Sall.append(int(ln, 16))
    if len(Sall) != 1024:
        raise SystemExit(f"Expected 1024 S words, got {len(Sall)} from {s_data_path}")

    S0b = Sall[0:256]; S1b = Sall[256:512]; S2b = Sall[512:768]; S3b = Sall[768:1024]

    ek_modes    = ["LE", "BE", "LE16", "BE16"]
    salt_modes  = ["LE", "BE", "LE16", "BE16"]
    iter_modes  = ["none", "iter", "iter_plus_1", "pow2"]
    lr_swaps    = [False, True]
    out_bswaps  = [False, True]

    variants = []
    for ekm in ek_modes:
        EK = _decode_ek_words(data_stream, ekm)
        for sm in salt_modes:
            salt_words = _decode_salt_words(salt_bytes, sm)
            for im in iter_modes:
                # clone base P,S for this iter mode
                P  = EK[:]
                S0 = S0b[:]; S1 = S1b[:]; S2 = S2b[:]; S3 = S3b[:]
                passes = _expand_times(iter_count, im)
                for _ in range(passes):
                    _expand_key_b_once(P, S0, S1, S2, S3, salt_words)
                base_out = _final_24_words(P, S0, S1, S2, S3)
                for lrs in lr_swaps:
                    if lrs:
                        out_lr = [base_out[1], base_out[0], base_out[3], base_out[2], base_out[5], base_out[4]]
                    else:
                        out_lr = base_out[:]
                    for bsw in out_bswaps:
                        if bsw:
                            out_final = list(map(_byteswap32, out_lr))
                        else:
                            out_final = out_lr
                        lbl = f"EK={ekm:>4}  SALT={sm:>4}  ITER={im:>11}  LR_SWAP={'yes' if lrs else 'no '}  OUT_BSWAP={'yes' if bsw else 'no '}"
                        variants.append((lbl, tuple(out_final)))
    return variants

def print_sw_candidate_variants(variants, limit=48):
    print("=== SW model candidate variants (augmented) ===")
    shown = 0
    # Deterministic iteration order (common combos first)
    pref = []
    for ek in ["LE","BE","LE16","BE16"]:
        for sa in ["LE","BE","LE16","BE16"]:
            for it in ["iter","iter_plus_1","pow2","none"]:
                for lrs in [False, True]:
                    for bs in [False, True]:
                        pref.append((ek,sa,it,lrs,bs))
    for ek,sa,it,lrs,bs in pref:
        for lbl, H in variants:
            if (f"EK={ek}" in lbl) and (f"SALT={sa}" in lbl) and (f"ITER={it}" in lbl) \
               and (("LR_SWAP=yes" in lbl) == lrs) and (("OUT_BSWAP=yes" in lbl) == bs):
                print(lbl)
                print(f"  SW H: {H[0]:08x} {H[1]:08x} {H[2]:08x} {H[3]:08x} {H[4]:08x} {H[5]:08x}")
                shown += 1
                if shown >= limit:
                    print(f"... ({len(variants)-shown} more variants not shown)")
                    return
    if shown == 0:
        print("(no variants generated)")

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

        # Minimal result printer (IDs + 6 result words + SW compare)
        dump = r"""
module sim_dump #(
    parameter EXP_ID0 = 32'h1234_ABCD,
    parameter EXP_ID1 = 32'h0000_0024,
    parameter EXP_H0  = 32'h0,
    parameter EXP_H1  = 32'h0,
    parameter EXP_H2  = 32'h0,
    parameter EXP_H3  = 32'h0,
    parameter EXP_H4  = 32'h0,
    parameter EXP_H5  = 32'h0
)(
    input clk, input done,
    input [31:0] id0, input [31:0] id1,
    input [31:0] h0,  input [31:0] h1, input [31:0] h2,
    input [31:0] h3,  input [31:0] h4, input [31:0] h5
);
    function [7*8-1:0] passfail; input ok; begin passfail = ok ? "PASS   " : "FAIL   "; end endfunction
    always @(posedge clk) if (done) begin
        $display("=== BCRYPT PACKET ===");
        $display("IDs: observed vs expected");
        $display("ID0  obs=0x%08x  exp=0x%08x  %s", id0, EXP_ID0, passfail(id0==EXP_ID0));
        $display("ID1  obs=0x%08x  exp=0x%08x  %s", id1, EXP_ID1, passfail(id1==EXP_ID1));
        $display("Results (observed) vs (software model from EK+ExpandKeyB+64enc):");
        $display("H0  obs=0x%08x  exp=0x%08x  %s", h0, EXP_H0, passfail(h0==EXP_H0));
        $display("H1  obs=0x%08x  exp=0x%08x  %s", h1, EXP_H1, passfail(h1==EXP_H1));
        $display("H2  obs=0x%08x  exp=0x%08x  %s", h2, EXP_H2, passfail(h2==EXP_H2));
        $display("H3  obs=0x%08x  exp=0x%08x  %s", h3, EXP_H3, passfail(h3==EXP_H3));
        $display("H4  obs=0x%08x  exp=0x%08x  %s", h4, EXP_H4, passfail(h4==EXP_H4));
        $display("H5  obs=0x%08x  exp=0x%08x  %s", h5, EXP_H5, passfail(h5==EXP_H5));
    end
endmodule
"""
        with open("sim_dump.v", "w") as f: f.write(dump)
        platform.add_source("sim_dump.v")

        # Bcrypt Test ------------------------------------------------------------------------------
        salt_bytes = [0x04, 0x41, 0x10, 0x04, 0x00, 0x00, 0x41, 0x10] + [0x00]*8
        iter_count = 1
        PKT_ID     = 0x1234
        WORD_ID    = 0xABCD
        EXP_ID0    = ((PKT_ID & 0xFFFF) << 16) | (WORD_ID & 0xFFFF)  # 0x1234ABCD
        EXP_ID1    = 0x00000024

        s_data_path = "gateware/bcrypt/S_data.txt"
        init_stream = build_init_stream(s_data_path=s_data_path)
        data_stream = build_data_stream(salt_bytes, iter_count, pkt_id=PKT_ID, word_id=WORD_ID)

        # --- Software variants (print once so you can compare with RTL output) ---
        variants = compute_expected_variants(data_stream, s_data_path, salt_bytes, iter_count)
        print_sw_candidate_variants(variants, limit=1024)

        #exit()

        # Choose an in-sim comparison variant.
        # Default heuristic: prefer EK=LE, SALT=LE, ITER=pow2, no LR swap, no OUT_BSWAP.
        def _pick_variant(variants):
            prefs = [
                ("EK= LE", "SALT= LE", "ITER=     pow2", "LR_SWAP=no", "OUT_BSWAP=no"),
                ("EK= LE", "SALT= LE", "ITER=       iter", "LR_SWAP=no", "OUT_BSWAP=no"),
            ]
            for ek_tag, sa_tag, it_tag, lr_tag, bs_tag in prefs:
                for idx, (lbl, _) in enumerate(variants):
                    if (ek_tag in lbl) and (sa_tag in lbl) and (it_tag in lbl) and (lr_tag in lbl) and (bs_tag in lbl):
                        return idx
            return 0
        _sel = _pick_variant(variants)
        print("Using variant:", variants[_sel][0])
        (EXP_H0, EXP_H1, EXP_H2, EXP_H3, EXP_H4, EXP_H5) = variants[_sel][1]

        INIT_LEN = len(init_stream)    # 4216
        DATA_LEN = len(data_stream)    # 124

        init_idx = Signal(max=INIT_LEN)
        data_idx = Signal(max=DATA_LEN)

        # Simple timeouts so we don't hang if something’s off
        wait_init_rdy_to  = Signal(24)
        wait_crypt_rdy_to = Signal(24)

        # ------------------------
        # 1-bit output reader with header-hunt (LSB-first per 32-bit word)
        # ------------------------
        reading      = Signal(reset=0)
        saw_header   = Signal(reset=0)
        bit_idx      = Signal(5)   # 0..31 within word
        word_cnt     = Signal(4)   # 0..7 (2 IDs + 6 results)
        cur_word     = Signal(32)
        rd_en_pulse  = Signal(reset=0)  # single driver for rd_en

        id0 = Signal(32); id1 = Signal(32)
        h0  = Signal(32); h1  = Signal(32); h2 = Signal(32)
        h3  = Signal(32); h4  = Signal(32); h5 = Signal(32)

        # Proxy ports (keep rd_en purely from a reg to avoid PROCASSWIRE)
        self.comb += [
            self.bcrypt_proxy.din.eq(0),
            self.bcrypt_proxy.ctrl.eq(0),
            self.bcrypt_proxy.wr_en.eq(0),
            self.bcrypt_proxy.rd_en.eq(rd_en_pulse),
        ]

        # Capture: wait for empty==0, pulse rd_en once, hunt header bit '1',
        # then capture 8×32 data bits, LSB-first.
        self.sync += [
            rd_en_pulse.eq(0),

            If(~reading & ~self.bcrypt_proxy.empty,
                rd_en_pulse.eq(1),
                reading.eq(1),
                saw_header.eq(0),
                bit_idx.eq(0),
                word_cnt.eq(0),
                cur_word.eq(0)
            ).Elif(reading,
                If(~saw_header,
                    If(self.bcrypt_proxy.dout,
                        saw_header.eq(1),
                        bit_idx.eq(0),
                        cur_word.eq(0)
                    )
                ).Else(
                    # capture LSB-first into cur_word
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
            p_EXP_ID0 = EXP_ID0,
            p_EXP_ID1 = EXP_ID1,
            p_EXP_H0  = EXP_H0,
            p_EXP_H1  = EXP_H1,
            p_EXP_H2  = EXP_H2,
            p_EXP_H3  = EXP_H3,
            p_EXP_H4  = EXP_H4,
            p_EXP_H5  = EXP_H5,
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
    soc = SimSoC()
    builder = Builder(soc, csr_csv="csr.csv")
    builder.build(sim_config=sim_config, **verilator_build_kwargs)

if __name__ == "__main__":
    main()
