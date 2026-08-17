`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016,2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Altera/Intel variant (2026): PD given an MLAB ramstyle. ATTRIBUTE-ONLY DELTA.
 */

//
// ALTERA/INTEL VARIANT of gateware/bcrypt/bcrypt_core/P_2x32.v
// ============================================================
//
// This file differs from the shared original by EXACTLY TWO LINES, neither of which
// changes a statement -- every line of RTL is byte-identical, so the semantics are
// unchanged by construction. It is selected from Python
// (BcryptWrapper.add_sources(vendor="altera")) and never enters a Xilinx build.
//
// Difference 1 (cosmetic, forced by the file's location): the original sits in
// gateware/bcrypt/bcrypt_core/ and includes "../bcrypt.vh"; this copy sits one level
// higher in gateware/bcrypt_altera/, so it includes "bcrypt.vh" and lets Quartus
// resolve it through SEARCH_PATH -- which already lists gateware/bcrypt, and is how
// bcrypt_arbiter.v / bcrypt_data.v / bcrypt_proxy.v already include the same header.
// It is the same file either way.
//
// Difference 2 (the point of this file): the synthesis attribute on the PD array.
//
//   original:  (* RAM_STYLE="DISTRIBUTED" *)      reg [MSB:0] PD [31:0];
//   here:      (* ramstyle = "MLAB, no_rw_check" *) reg [MSB:0] PD [31:0];
//
// WHY
// ---
// PD is a 32x32 LUTRAM with a synchronous write and an ASYNCHRONOUS read, and the
// read address is the same signal as the write address (PD_addr). On Xilinx that is
// a RAM32M and costs ~16 LUTs. Quartus reports
//
//   Info (276007): RAM logic "P_2x32:P|PD" is uninferred due to asynchronous read logic
//
// and builds 1,024 flip-flops plus a 32:1 x 32b soft mux instead -- ~470 ALMs per
// core, which after the S-box fix was 63% of the entire core.
//
// Adding `ramstyle = "MLAB"` alone is not enough; Quartus then reports
//
//   Info (276009): RAM logic "P_2x32:P|PD" is uninferred due to unsupported
//                  read-during-write behavior
//
// because a Stratix V MLAB cannot reproduce the RTL's same-address read-during-write
// result (the RTL's asynchronous read returns the OLD contents during a write cycle;
// the MLAB writes on an internal edge and would return the new data). `no_rw_check`
// tells Quartus that the read-during-write result is a don't-care.
//
// WHY no_rw_check IS SAFE HERE -- COMPLETE PROOF, NOT AN ASSUMPTION
// ----------------------------------------------------------------
// Because the read and write addresses are literally the same signal, a same-address
// read-during-write happens on EVERY cycle where PD_wr_en is asserted. So the claim
// that has to hold is: PD_out is never consumed on a cycle where PD_wr_en is 1.
//
// 1. PD_out's entire fanout is one expression in unit.v:
//        assign L_in = (L_input_select ? L : R ^ S_dout) ^ PD ^ PN;
//    (grep: `PD` appears nowhere else in unit.v.)
//
// 2. L_in's entire fanout is:
//        Ltmp <= L_in          when Ltmp_wr_en
//        L    <= L_in          when L_wr_en (and not an S-read exception, which can
//                              only suppress the write further)
//        S.addr_rd = L_in      which the S-box samples only when S_rd_en
//    R takes L, not L_in, so R_wr_en is not a consumer.
//    Hence "PD_out is consumed" == (Ltmp_wr_en | L_wr_en | S_rd_en).
//
// 3. PD_wr_en, Ltmp_wr_en, L_wr_en and S_rd_en are ALL registered directly off the
//    microcode ROM word in fsm.v, with no intervening logic:
//        { PN_wr_en, PD_wr_en, ... }              <= MC_P;
//        { L_input_select, Ltmp_wr_en, ... }      <= MC_LR;
//        { S_wr_en, S_rd_en, S_rst, SWAR_op }     <= MC_S;
//    The only other influence is `rst`, which forces every one of them to 0. So the
//    96-word microcode ROM IS the complete, input-independent set of reachable
//    combinations of these four signals.
//
// 4. Enumerating all 96 ROM words (see the microcode dump in the verification notes)
//    gives: PD_wr_en is asserted in exactly ONE word, MC[5], and that word has
//        Ltmp_wr_en=0  L_wr_en=0  S_rd_en=0  R_wr_en=0  PN_wr_en=0  S_wr_en=0
//    i.e. PD_out is unused on the one and only cycle type where PD is written.
//
// Therefore the read-during-write result is genuinely a don't-care and no_rw_check
// cannot change the behaviour of the design. QED.
//
// PN is deliberately left alone: 7 of the 13 microcode words that assert PN_wr_en do
// consume PN_out, so the same argument does NOT hold for it. Quartus already infers
// PN as memory in-context anyway (with pass-through logic that preserves the RTL
// read-during-write result), so it costs no ALMs to leave it correct.
//

`include "bcrypt.vh"
//
// "EK" means expanded key
//
module P_2x32 #(
	parameter MSB = 31
	)(
	input CLK,

	// Memory PD (1 write/read port)
	input [4:0] PD_addr,
	input PD_wr_en,
	output [MSB:0] PD_out,

	// Input MUX
	input [MSB:0] din,
	input [MSB:0] Ltmp_in,
	input PS_input_select, decr,
	output [MSB:0] S_input,

	// Memory PN (1 write, 1 read port)
	input [4:0] PN_wr_addr,
	input [4:0] PN_addr,
	input PN_wr_en,
	output [MSB:0] PN_out,

	input ZF_wr_en,
	output reg ZF = 0
	);


	integer i;

	// PD: 32-deep RAM for constant data, 1 write/read port
	// - input only from din
	//
	(* ramstyle = "MLAB, no_rw_check" *)
	reg [MSB:0] PD [31:0];
	initial begin
		// - EK(18)
		// - constant 'd64(1) - off+18
		// - iter_count(1) - off+19
		// - salt(4) - off+20
		// - IDs(2) - off+24
		// - reserved(5) - off+26
		// Total words in data for encryption: 31
		PD[31] = 0;
	end

	always @(posedge CLK)
		if (PD_wr_en)
			PD [PD_addr] <= din;

	// Force creation of RAM32M instead of RAM32X1S
	// (by defining separate read port) - save 8 LUTs
	(* KEEP="true" *)
	wire [4:0] PD_addr_rd = PD_addr;

	assign PD_out = PD [PD_addr_rd];


	//
	// PN: 32-deep RAM, 1 write, 1 read port
	//
	// PN is 32x32 = 1024 bits and Quartus places it in a full 20,480-bit M20K (measured:
	// M20K_X47_Y89_N0), 1 block per core, ~5% utilised. That is the fifth block per core on top of
	// the four the S-boxes need, and it is what makes M20K bind at ~399 cores rather than ~499.
	//
	// MEASURED AND REJECTED: forcing (* ramstyle = "MLAB" *) here does NOT move PN into MLAB. Without
	// no_rw_check, Quartus cannot reconcile the asynchronous read (assign PN_out = PN[PN_addr]) with
	// preserving read-during-write semantics, so it abandons memory inference entirely and builds
	// registers plus an address decoder. Measured at 15 cores: M20K/core 5.0 -> 4.0 as hoped, but
	// ALMs/core 341 -> 768, and PN disappears from the Fitter RAM Summary altogether. That moves the
	// ALM-bound ceiling to ~222 cores, far worse than the ~399 the M20K bound gives, and 390 cores
	// stops fitting at all. sys_clk also regressed (-0.011 at a 200 MHz constraint).
	//
	// no_rw_check is NOT the fix either: 7 of the 13 microcode words that assert PN_wr_en also
	// consume PN_out, so read-during-write genuinely occurs and asserting it cannot is unsound.
	// Leaving PN in M20K is the correct trade until the read port itself is restructured.
	(* RAM_STYLE="DISTRIBUTED" *)
	reg [MSB:0] PN [31:0];
	initial begin
		// P(0-17)
		// 18 - current value for iter_count
		// resevrved(19-23)
		// magic_w(24-29), replaced by result
		// Total: 30
		PN[30] = 0;
		PN[31] = 0;
	end

	wire [MSB:0] PN_input;
	always @(posedge CLK)
		if (PN_wr_en)
			PN [PN_wr_addr] <= PN_input;

	assign PN_out = PN [PN_addr];


	//
	// Input selection.
	// It's able to perform decrement w/o touching L,R.
	//
	//assign PN_input =
	//	PS_input_select == `INPUT_DIN & ~decr ? din :
	//	PS_input_select == `INPUT_X_ & ~decr ? Ltmp_in :
	//	{ {31-`SETTING_MAX{1'b0}}, PN_out[`SETTING_MAX:0] - 1'b1 }; // INPUT_DECR
	//
	// Saving 32+6 LUT in contrast with the above
	// (+6 for allowance to contain trash in upper bits after decrement)
	//
	assign PN_input[31:`SETTING_MAX+1] =
		//decr ? {31-`SETTING_MAX{1'b0}} : // 6 LUT
		PS_input_select == `INPUT_DIN ? din[31:`SETTING_MAX+1] :
		Ltmp_in[31:`SETTING_MAX+1];

	assign PN_input[`SETTING_MAX:0] = (
		decr ? PN_out[`SETTING_MAX:0] :
		PS_input_select == `INPUT_DIN ? din[`SETTING_MAX:0] :
		Ltmp_in[`SETTING_MAX:0]
	) - (decr ? 1'b1 : 1'b0);

	assign S_input = PN_input;


	//
	// Zero flag (ZF)
	//
	always @(posedge CLK)
		if (ZF_wr_en)
			ZF <= PN_input[`SETTING_MAX:0] == 0;


endmodule
