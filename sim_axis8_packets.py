#!/usr/bin/env python3

# SPDX-License-Identifier: BSD-2-Clause
#
# sim_axis8_packets.py — Packet-level LiteX/Migen simulation for BcryptCoreAXIS8.
#
# This drives the 8-bit AXI-Stream IN with three "high-level" packets:
#   1) CMP_CONFIG (type=0x03): iter_count + salt + cmp_data[5]
#   2) WORD_LIST  (type=0x01): a single word "pass\0"
#   3) WORD_GEN   (type=0x02): minimal config to consume 1 word from WORD_LIST
#
# Notes
# -----
# * Header format assumed (adjust to match your repo's `inpkt_header`):
#     [ver:8][type:8][id:16-LE][len:16-LE] [payload...]
#   With SIMULATION=1 on the wrapper, checksum is disabled.
# * Payload encodings for cmp_config/word_list/word_gen may need tweaks to your exact RTL.
#   The structure below follows the comments in bcrypt_data.v and typical repo defaults.
#
import argparse
from migen import *
from litex.gen import *
from litex.build.generic_platform import *
from litex.build.sim              import SimPlatform
from litex.build.sim.config       import SimConfig
from litex.build.sim.verilator import verilator_build_args, verilator_build_argdict
from litex.soc.integration.soc_core import SoCMini
from litex.soc.integration.builder import Builder
from litex.soc.interconnect import stream
from litex.gen import LiteXModule

WRAPPER_SV = "bcrypt_axis8_wrap.sv"
LITEX_MOD  = "litex_bcrypt_axis8.py"

PKT_VERSION = 2  # Adjust to match `PKT_COMM_VERSION` in your repo
PKT_TYPE_WORD_LIST   = 0x01
PKT_TYPE_WORD_GEN    = 0x02
PKT_TYPE_CMP_CONFIG  = 0x03

def le16(x): return [x & 0xFF, (x >> 8) & 0xFF]
def le32(x): return [ (x >> (8*i)) & 0xFF for i in range(4) ]

def build_header(pkt_type, pkt_id, payload_len):
    return [PKT_VERSION, pkt_type] + le16(pkt_id) + le16(payload_len)

def build_cmp_config_payload(iter_count, salt16_le_bytes):
    # Heuristic mapping:
    #   - iter_count : 1 * 32b
    #   - salt       : 4 * 32b (16 bytes), already LE-packed by caller
    #   - cmp_data   : 5 * 32b (zeros if not matching on-FPGA)
    # Total: 10 * 32b = 40 bytes
    assert len(salt16_le_bytes) == 16
    payload = []
    payload += le32(iter_count)
    # pack the 16 salt bytes into 4 LE words
    for i in range(4):
        b0,b1,b2,b3 = salt16_le_bytes[4*i:4*i+4]
        payload += [b0, b1, b2, b3]
    # cmp_data[5] zeros
    for _ in range(5):
        payload += le32(0)
    return payload

def build_word_list_payload(words):
    # Simplest form: concatenate zero-terminated bytes for each word, and rely on packet end
    # as the list terminator (this mirrors typical template_list_b behavior). Adjust if your
    # repo expects explicit counts or ranges.
    p = []
    for w in words:
        p += [ord(c) for c in w] + [0x00]  # C-style NUL termination
    return p

def build_word_gen_payload(single_packet_id):
    # Minimalistic control to pull one word from WORD_LIST for a given inpkt_id.
    # Actual fields can vary per repo (ranges, masks, etc.). We put a tiny header:
    #   - pkt_id (16b LE) of the WORD_LIST packet to consume from
    #   - count  (16b LE) number of words to generate (1)
    # Adjust this to your exact `word_gen_b` encoding.
    return le16(single_packet_id) + le16(1)

class ByteStreamer(LiteXModule):
    def __init__(self, data):
        self.source = stream.Endpoint([('data', 8)])
        self.start  = Signal(reset=0)
        self.done   = Signal(reset=0)

        n = len(data)
        mem = Array([Signal(8, reset=d) for d in data])
        idx = Signal(max=n+1)
        running = Signal(reset=0)

        self.comb += self.source.data.eq(mem[idx])
        self.comb += self.source.last.eq(idx == (n-1))

        self.sync += [
            self.done.eq(0),
            If(self.start & ~running,
               running.eq(1),
               idx.eq(0)
            ).Elif(running,
               self.source.valid.eq(1),
               If(self.source.valid & self.source.ready,
                  If(idx == (n-1),
                      self.source.valid.eq(0),
                      self.done.eq(1),
                      running.eq(0)
                  ).Else(
                      idx.eq(idx + 1)
                  )
               )
            ).Else(
               self.source.valid.eq(0)
            )
        ]

class WordCollector(LiteXModule):
    def __init__(self, nwords=8):
        self.sink  = stream.Endpoint([('data', 8)])
        self.done  = Signal()
        self.words = [Signal(32) for _ in range(nwords)]

        cur = Signal(32)
        byte_pos = Signal(2)   # 0..3 within word
        idx = Signal(max=nwords)
        capturing = Signal(reset=1)

        self.sync += [
            self.done.eq(0),
            If(capturing,
                If(self.sink.valid & self.sink.ready,
                    # LSB-first 32b assembly
                    cur.eq(cur | (self.sink.data << (8*byte_pos))),
                    byte_pos.eq(byte_pos + 1),
                    If(byte_pos == 3,
                        Case(idx, {i: self.words[i].eq(cur | (self.sink.data << 24)) for i in range(nwords)}),
                        idx.eq(idx + 1),
                        byte_pos.eq(0),
                        cur.eq(0),
                        If(idx == (nwords - 1),
                            capturing.eq(0),
                            self.done.eq(1)
                        )
                    )
                )
            )
        ]
        self.comb += self.sink.ready.eq(1)

_io = [("sys_clk", 0, Pins(1)), ("sys_rst", 0, Pins(1))]

class Platform(SimPlatform):
    def __init__(self): SimPlatform.__init__(self, "SIM", _io)

class SimSoC(SoCMini):
    def __init__(self):
        platform     = Platform()
        sys_clk_freq = int(50e6)
        SoCMini.__init__(self, platform, sys_clk_freq)
        self.crg = CRG(platform.request("sys_clk"))

        # Import integration
        import importlib.util, sys as _sys
        spec = importlib.util.spec_from_file_location("litex_bcrypt_axis8", LITEX_MOD)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _sys.modules["litex_bcrypt_axis8"] = mod
        BcryptCoreAXIS8 = mod.BcryptCoreAXIS8

        self.platform.add_source(WRAPPER_SV)
        # Force SIMULATION=1 by defining the parameter at instantiation
        self.bcrypt = bcrypt = BcryptCoreAXIS8(self.platform, num_cores=1)
        self.bcrypt.add_sources()

        # Packets -----------------------------------------------------------------
        cmp_id  = 0x0001
        wl_id   = 0x0002
        wg_id   = 0x0003

        iter_count = 5
        salt16     = [0x00]*16

        cmp_pl   = build_cmp_config_payload(iter_count, salt16)
        cmp_hdr  = build_header(PKT_TYPE_CMP_CONFIG, cmp_id, len(cmp_pl))
        pkt_cmp  = cmp_hdr + cmp_pl

        wl_pl    = build_word_list_payload(["pass"])
        wl_hdr   = build_header(PKT_TYPE_WORD_LIST, wl_id, len(wl_pl))
        pkt_wl   = wl_hdr + wl_pl

        wg_pl    = build_word_gen_payload(wl_id)
        wg_hdr   = build_header(PKT_TYPE_WORD_GEN, wg_id, len(wg_pl))
        pkt_wg   = wg_hdr + wg_pl

        # Streamers + collector
        self.tx_cmp = tx_cmp = ByteStreamer(pkt_cmp)
        self.tx_wl  = tx_wl  = ByteStreamer(pkt_wl)
        self.tx_wg  = tx_wg  = ByteStreamer(pkt_wg)
        self.rx     = rx     = WordCollector(nwords=8)

        # CSRs: mode_cmp=1
        self.comb += bcrypt._ctrl.storage.eq(0b001)

        # AXIS connections
        self.comb += [
            bcrypt.sink.valid.eq(tx_cmp.source.valid | tx_wl.source.valid | tx_wg.source.valid),
            bcrypt.sink.data.eq(
                Mux(tx_cmp.source.valid, tx_cmp.source.data,
                Mux(tx_wl .source.valid, tx_wl .source.data, tx_wg.source.data))
            ),
            bcrypt.sink.last.eq(
                Mux(tx_cmp.source.valid, tx_cmp.source.last,
                Mux(tx_wl .source.valid, tx_wl .source.last, tx_wg.source.last))
            ),
            tx_cmp.source.ready.eq(bcrypt.sink.ready & tx_cmp.source.valid),
            tx_wl .source.ready.eq(bcrypt.sink.ready & ~tx_cmp.source.valid & tx_wl.source.valid),
            tx_wg .source.ready.eq(bcrypt.sink.ready & ~tx_cmp.source.valid & ~tx_wl.source.valid & tx_wg.source.valid),

            rx.sink.valid.eq(bcrypt.source.valid),
            rx.sink.data .eq(bcrypt.source.data),
            rx.sink.last .eq(bcrypt.source.last),
            bcrypt.source.ready.eq(1),
        ]

        # Sequencer
        self.fsm = fsm = FSM(reset_state="SEND_CMP")
        fsm.act("SEND_CMP",
            tx_cmp.start.eq(1),
            If(tx_cmp.done, NextState("SEND_WL"))
        )
        fsm.act("SEND_WL",
            tx_wl.start.eq(1),
            If(tx_wl.done, NextState("SEND_WG"))
        )
        fsm.act("SEND_WG",
            tx_wg.start.eq(1),
            If(tx_wg.done, NextState("WAIT_RX"))
        )
        fsm.act("WAIT_RX",
            If(rx.done, NextState("DONE"))
        )
        fsm.act("DONE")

def main():
    parser = argparse.ArgumentParser()
    verilator_build_args(parser)
    args = parser.parse_args()
    build_kwargs = verilator_build_argdict(args)

    sim_config = SimConfig()
    sim_config.add_clocker("sys_clk", freq_hz=int(25e6))

    soc = SimSoC()
    builder = Builder(soc, csr_csv="csr.csv", compile_software=False)
    builder.build(sim_config=sim_config, **build_kwargs)

if __name__ == "__main__":
    main()
