`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Altera/Intel variant (2026): mixed-width memory rewritten in the packed-array
 * form Quartus recognises. Behaviourally identical, see the proof below.
 */

//
// ALTERA/INTEL VARIANT of gateware/util/asymm_bram.v
// =================================================
//
// Selected from Python (BcryptWrapper.add_sources(vendor="altera")); the shared
// gateware/util/asymm_bram.v is excluded from the Altera source list and is NEVER
// touched by a Xilinx build.
//
// WHY THIS FILE EXISTS
// --------------------
// The shared file describes a mixed-width dual-port RAM in the idiom XST/Vivado
// documents: ONE narrow array, a narrow write port, and RATIO *separate* always
// blocks that each read a different low-order slice of the address space:
//
//     reg [7:0] mem [0:2047];
//     always @(posedge wr_clk) if (wr_en) mem[wr_addr] <= din;
//     generate for (i=0; i<4; i=i+1)
//       always @(posedge rd_clk) if (rd_en)
//         dout[8*i +: 8] <= mem[{rd_addr, i[1:0]}];
//     endgenerate
//
// Vivado infers a single width-asymmetric BRAM from this. Quartus does not: it sees
// one array with FOUR independent synchronous read ports plus a write port, which no
// M20K configuration can provide, so it gives up on memory inference entirely and
// builds the array out of registers plus four address decoders.
//
// Measured, standalone, on 5SGSMD5K1F40C1 with this exact instance shape
// (minWIDTH=8, RATIO=4, maxDEPTH=512 -- i.e. what comparator.v instantiates):
//
//     shared file  : 8,306 ALMs,  0 M20K
//     this file    :     1 ALM ,  1 M20K
//
// In the real design that array is `comparator:u_cmp|asymm_bram_min_wr:mem`, which
// accounted for 8,211 of the 10,443 ALMs of a 1-proxy 1-core Stratix V build -- 79% of
// the whole design, and pure fixed overhead that every core count pays.
//
// THE TRANSFORM, AND WHY IT IS THE SAME CIRCUIT
// ---------------------------------------------
// The RATIO narrow words that share a wide-port address are gathered into one packed
// dimension, so the wide port becomes a single ordinary read of one array element:
//
//     logic [RATIO-1:0][minWIDTH-1:0] mem [0:maxDEPTH-1];
//     write: mem[wr_addr[hi:log2RATIO]][wr_addr[log2RATIO-1:0]] <= din;
//     read : dout <= mem[rd_addr];
//
// Element identity: in the shared file the byte written by address `wr_addr` is
// mem[wr_addr], and the byte that appears in dout[minWIDTH*i +: minWIDTH] is
// mem[{rd_addr, i}] -- i.e. the element whose narrow address has high part rd_addr and
// low part i. Here the byte written by `wr_addr` is
// mem[wr_addr >> log2RATIO][wr_addr & (RATIO-1)], and `dout <= mem[rd_addr]` expands,
// by the LSB-is-rightmost packing rule of a packed dimension, to
// dout[minWIDTH*i +: minWIDTH] <= mem[rd_addr][i]. So the two descriptions name the
// same storage element by the same address in both directions. RATIO is a power of two
// at every instantiation, so the >> / & split is exactly the {high, low} concatenation.
//
// Timing/RDW identity: every access is a non-blocking assignment clocked by the same
// clock and qualified by the same enable as before, so
//   - write: synchronous, enabled by wr_en, unchanged;
//   - read : synchronous, enabled by rd_en, and because the read RHS is evaluated
//            before any non-blocking update commits, a same-cycle same-address access
//            still returns the OLD contents -- read-before-write, exactly as in the
//            shared file. (Quartus maps that to the M20K's native mixed-port
//            "Old data" read-during-write mode, no bypass logic required.)
// Power-up state is likewise unchanged: mem is zeroed by an initial block and dout
// still initialises to INIT.
//
// The two always blocks are kept separate, matching the shared file statement for
// statement; that is also semantically irrelevant, since all four assignments are
// non-blocking.
//
// asymm_bram_min_rd is currently instantiated nowhere in this tree, but is converted
// the same way so the file remains a drop-in replacement for the whole shared unit.
//

`define MSB(x) ( \
	//x >= *65536 ?: \
	x >= 256 *65536 ? 24 : \
	x >= 128 *65536 ? 23 : \
	x >= 64 *65536 ? 22 : \
	x >= 32 *65536 ? 21 : \
	x >= 16 *65536 ? 20 : \
	x >= 8 *65536 ? 19 : \
	x >= 4 *65536 ? 18 : \
	x >= 2 *65536 ? 17 : \
	x >= 65536 ? 16 : \
	x >= 32768 ? 15 : \
	x >= 16384 ? 14 : \
	x >= 8192 ?	13 : \
	x >= 4096 ? 12 : \
	x >= 2048 ? 11 : \
	x >= 1024 ? 10 : \
	x >= 512 ? 9 : \
	x >= 256 ? 8 : \
	x >= 128 ? 7 : \
	x >= 64 ? 6 : \
	x >= 32 ? 5 : \
	x >= 16 ? 4 : \
	x >= 8 ? 3 : \
	x >= 4 ? 2 : \
	x >= 2 ? 1 : \
	x >= 1 ? 0 : \
	x == 0 ? 0 : \
	-1 )

//
// Asymmetric BRAM, 1 write port, 1 read port
// Write port has smaller data width
//
module asymm_bram_min_wr #(
	parameter minWIDTH = 8,
	parameter RATIO = 4,
	parameter maxDEPTH = 512,
	parameter INIT = 0
	)(
	input wr_clk,
	input [minWIDTH-1:0] din,
	input wr_en,
	input [`MSB(maxDEPTH*RATIO-1) :0] wr_addr,

	input rd_clk,
	output reg [minWIDTH*RATIO-1:0] dout = INIT,
	input rd_en,
	input [`MSB(maxDEPTH-1) :0] rd_addr
	);

	localparam log2RATIO = `MSB(RATIO);
	localparam WR_MSB    = `MSB(maxDEPTH*RATIO-1);

	integer k;

	// One array element == one wide-port word == RATIO narrow-port words.
	logic [RATIO-1:0][minWIDTH-1:0] mem [0:maxDEPTH-1];
	initial
		for (k=0; k < maxDEPTH; k=k+1)
			mem[k] = '0;

	// Narrow (write) port: high part of the address selects the row, low part
	// selects the narrow word within it.
	always @(posedge wr_clk)
		if (wr_en)
			mem [wr_addr[WR_MSB:log2RATIO]] [wr_addr[log2RATIO-1:0]] <= din;

	// Wide (read) port: one whole row.
	always @(posedge rd_clk)
		if (rd_en)
			dout <= mem [rd_addr];

endmodule


//
// Asymmetric BRAM, 1 write port, 1 read port
// Read port has smaller data width
//
module asymm_bram_min_rd #(
	parameter minWIDTH = 8,
	parameter RATIO = 4,
	parameter maxDEPTH = 512,
	parameter INIT = 0
	)(
	input wr_clk,
	input [minWIDTH*RATIO-1:0] din,
	input wr_en,
	input [`MSB(maxDEPTH-1) :0] wr_addr,

	input rd_clk,
	output reg [minWIDTH-1:0] dout = INIT,
	input rd_en,
	input [`MSB(maxDEPTH*RATIO-1) :0] rd_addr
	);

	localparam log2RATIO = `MSB(RATIO);
	localparam RD_MSB    = `MSB(maxDEPTH*RATIO-1);

	integer k;

	logic [RATIO-1:0][minWIDTH-1:0] mem [0:maxDEPTH-1];
	initial
		for (k=0; k < maxDEPTH; k=k+1)
			mem[k] = '0;

	// Narrow (read) port.
	always @(posedge rd_clk)
		if (rd_en)
			dout <= mem [rd_addr[RD_MSB:log2RATIO]] [rd_addr[log2RATIO-1:0]];

	// Wide (write) port: one whole row.
	always @(posedge wr_clk)
		if (wr_en)
			mem [wr_addr] <= din;

endmodule
