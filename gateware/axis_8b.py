#!/usr/bin/env python3

#
# This file is part of LiteX-Bcrypt.
#
# AXIS Streamer/Recorder (8-bit).
#

from litex.gen import *

from litex.soc.interconnect import stream

from litex.soc.interconnect.csr import CSRStorage, CSRStatus

# AXIS Streamer (8-bit) ----------------------------------------------------------------------------

class AXIS8Streamer(LiteXModule):
    def __init__(self, sram_mem):
        self.source = source = stream.Endpoint([("data", 8)])

        self.length = CSRStorage(32)
        self.kick   = CSRStorage(1)
        self.done   = CSRStatus(1)

        # # #

        # Signals.
        addr     = Signal(32)
        byte_sel = Signal(2)

        # Kick edge detect.
        kick_d = Signal()
        self.sync += kick_d.eq(self.kick.storage)
        start = self.kick.storage & ~kick_d

        # SRAM Read Port.
        port = sram_mem.get_port(async_read=True)
        self.specials += port

        # Data-Generation.
        self.comb += [
            port.adr.eq(addr[2:]),
            byte_sel.eq(addr[0:2]),
            source.last.eq(addr == (self.length.storage - 1)),
            Case(byte_sel, {
                0b00: source.data.eq(port.dat_r[ 0: 8]),
                0b01: source.data.eq(port.dat_r[ 8:16]),
                0b10: source.data.eq(port.dat_r[16:24]),
                0b11: source.data.eq(port.dat_r[24:32]),
            })
        ]

        # FSM.
        self.fsm = fsm = FSM(reset_state="IDLE")
        fsm.act("IDLE",
            source.valid.eq(0),
            self.done.status.eq(1),
            If(start & (self.length.storage > 0),
                NextValue(addr, 0),
                NextState("RUN")
            )
        )
        fsm.act("RUN",
            source.valid.eq(1),
            self.done.status.eq(0),
            If(source.ready,
                NextValue(addr, addr + 1),
                If(source.last,
                    NextState("IDLE")
                )
            )
        )

# AXIS Recorder (8-bit) ----------------------------------------------------------------------------

class AXIS8Recorder(LiteXModule):
    def __init__(self, sram_mem):
        self.sink = stream.Endpoint([("data", 8)])

        self.kick  = CSRStorage(1)
        self.done  = CSRStatus (1)
        self.count = CSRStatus (32)

        # # #

        # Signals.
        byte_addr = Signal(32)
        byte_cnt  = Signal(32)

        # Kick edge detect.
        kick_d = Signal()
        self.sync += kick_d.eq(self.kick.storage)
        start = self.kick.storage & ~kick_d

        # SRAM Write Port.
        port = sram_mem.get_port(write_capable=True, we_granularity=8)
        self.specials += port
        self.comb += port.adr.eq(byte_addr[2:])

        # FSM.
        self.fsm = fsm = FSM(reset_state="IDLE")
        fsm.act("IDLE",
            self.sink.ready.eq(0),
            self.done.status.eq(1),
            If(start,
                NextValue(byte_addr, 0),
                NextValue(byte_cnt,  0),
                NextState("RUN")
            )
        )
        fsm.act("RUN",
            self.sink.ready.eq(1),
            self.done.status.eq(0),
            If(self.sink.valid,
                Case(byte_addr[0:2], {
                    0b00 : [port.dat_w[ 0: 8].eq(self.sink.data), port.we.eq(0b0001)],
                    0b01 : [port.dat_w[ 8:16].eq(self.sink.data), port.we.eq(0b0010)],
                    0b10 : [port.dat_w[16:24].eq(self.sink.data), port.we.eq(0b0100)],
                    0b11 : [port.dat_w[24:32].eq(self.sink.data), port.we.eq(0b1000)],
                }),
                NextValue(byte_addr, byte_addr + 1),
                NextValue(byte_cnt,  byte_cnt  + 1),
                If(self.sink.last,
                    NextState("IDLE")
                )
            )
        )
        self.comb += self.count.status.eq(byte_cnt)
