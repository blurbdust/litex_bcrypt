`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Altera/Intel variant (2026): read path restructured for M20K inference.
 */

//
// 4x 1K S-blocks for bcrypt core -- ALTERA/INTEL VARIANT
// =====================================================
//
// This is a drop-in, cycle-for-cycle equivalent replacement for
// gateware/bcrypt/bcrypt_core/S.v.  It is selected from Python
// (BcryptWrapper.add_sources(vendor="altera")) and is NEVER compiled into a
// Xilinx build -- the Xilinx targets keep the original file byte-for-byte.
//
// WHY THIS FILE EXISTS
// --------------------
// The original writes the RAM output register as
//
//     if (rst_rd)      S0_out <= 0;
//     else if (rd_en)  S0_out <= S0[addr];
//
// Xilinx block RAM has a dedicated output-register reset pin (RSTREG), so
// Vivado infers a BRAM from this without complaint.  Altera M20K has no such
// pin, so Quartus refuses to infer memory at all and implements the four
// 256x32 arrays as 32,768 flip-flops plus four 256:1 x 32b soft mux trees.
// On a 1x1 Stratix V build that was 15,831 of the core's 16,578 ALMs and the
// worst timing path in the whole design (sys_clk Fmax 110.6 MHz).
//
// This is an architectural difference between the two vendors, not a missing
// attribute: `ramstyle = "M20K"` alone cannot fix it while the reset is on the
// output register.
//
// THE TRANSFORM
// -------------
// The reset is moved *downstream* of the RAM output register, into a single
// 1-bit "output is zero" flag, and applied as an AND mask on the read data:
//
//   original:  S0_out' = rst_rd ? 0 : (rd_en ? MEM0[a0] : S0_out)
//              out     = S3_out + (S2_out ^ (S1_out + S0_out))
//
//   here:      S0_q'   = rd_en ? MEM0[a0] : S0_q          (no reset -> inferable)
//              zero'   = rst_rd ? 1 : (rd_en ? 0 : zero)
//              out     = (S3_q & m) + ((S2_q & m) ^ ((S1_q & m) + (S0_q & m)))
//              where m = {32{~zero}}
//
// PROOF OF CYCLE-EXACT EQUIVALENCE
// --------------------------------
// Invariant I(t):  zero(t)==1  =>  S0_out(t)==S1_out(t)==S2_out(t)==S3_out(t)==0
//                  zero(t)==0  =>  Sk_q(t) == Sk_out(t) for k=0..3
//
//   Base t=0: zero=1 and the original initialises all four Sk_out to 0.  OK.
//   Step, assuming I(t):
//     rst_rd(t)=1              : zero(t+1)=1 and original Sk_out(t+1)=0.  OK.
//     rst_rd(t)=0, rd_en(t)=1  : zero(t+1)=0, Sk_q(t+1)=MEMk[ak](t)=Sk_out(t+1). OK.
//     rst_rd(t)=0, rd_en(t)=0  : both zero and all Sk_q / Sk_out hold; I carries. OK.
//
// Output: when zero==1 the mask is 0, so out = 0 + (0 ^ (0 + 0)) = 0, which is
// exactly what the original computes from four zeroed registers.  When zero==0
// the mask is all-ones and every Sk_q equals the original Sk_out, so the
// arithmetic is identical.  Hence out is bit-identical on every cycle. QED.
//
// The AND mask is also X-safe in simulation: (X & 1'b0) is 0 in Verilog, so an
// un-initialised memory read that the original would have cleared to 0 is still
// driven to 0 here rather than leaking X.
//
// COST
// ----
// The mask is absorbed into the LUTs that already feed the two carry chains:
// S0/S1 adder bit i becomes f(S0_q[i], S1_q[i], zero) = 3 inputs, and the
// second adder's bits are f(S2_q[i], zero, sum[i]) and f(S3_q[i], zero), all
// within a Stratix V ALM arithmetic-mode 4-input LUT.  No extra logic level.
//
// Sk_q intentionally has no initial value -- it is unobservable at power-up
// because `zero` starts at 1 and masks it -- which keeps the read path free of
// anything that could block output-register inference.
//
module S #(
	parameter MSB = 31,
	parameter ADDR_NBITS = 8
	)(
	input CLK,
	input [MSB:0] din,
	input wr_en,
	input [9:0] addr_wr,

	input rd_en,
	input rst_rd,
	input [MSB:0] addr_rd,
	output [MSB:0] out
	);

	(* ramstyle = "M20K" *) reg [MSB:0] S0 [255:0];
	(* ramstyle = "M20K" *) reg [MSB:0] S1 [255:0];
	(* ramstyle = "M20K" *) reg [MSB:0] S2 [255:0];
	(* ramstyle = "M20K" *) reg [MSB:0] S3 [255:0];

	reg [MSB:0] S0_q, S1_q, S2_q, S3_q;

	wire [ADDR_NBITS-1:0] a0 = addr_rd [4*ADDR_NBITS-1 : 3*ADDR_NBITS];
	wire [ADDR_NBITS-1:0] a1 = addr_rd [3*ADDR_NBITS-1 : 2*ADDR_NBITS];
	wire [ADDR_NBITS-1:0] a2 = addr_rd [2*ADDR_NBITS-1 : ADDR_NBITS];
	wire [ADDR_NBITS-1:0] a3 = addr_rd [ADDR_NBITS-1 : 0];

	// One canonical Quartus simple-dual-port template per S-block: one write
	// port with a decoded enable, one read port with a read enable, no reset
	// anywhere in the block.
	always @(posedge CLK) begin
		if (wr_en && addr_wr[9:8] == 2'b00)
			S0 [addr_wr[7:0]] <= din;
		if (rd_en)
			S0_q <= S0 [a0];
	end

	always @(posedge CLK) begin
		if (wr_en && addr_wr[9:8] == 2'b01)
			S1 [addr_wr[7:0]] <= din;
		if (rd_en)
			S1_q <= S1 [a1];
	end

	always @(posedge CLK) begin
		if (wr_en && addr_wr[9:8] == 2'b10)
			S2 [addr_wr[7:0]] <= din;
		if (rd_en)
			S2_q <= S2 [a2];
	end

	always @(posedge CLK) begin
		if (wr_en && addr_wr[9:8] == 2'b11)
			S3 [addr_wr[7:0]] <= din;
		if (rd_en)
			S3_q <= S3 [a3];
	end

	// Downstream replacement for the output-register reset.
	reg out_zero = 1'b1;

	always @(posedge CLK)
		if (rst_rd)
			out_zero <= 1'b1;
		else if (rd_en)
			out_zero <= 1'b0;

	wire [MSB:0] mask = {(MSB+1){~out_zero}};

	assign out = (S3_q & mask) + ((S2_q & mask) ^ ((S1_q & mask) + (S0_q & mask)));

endmodule
