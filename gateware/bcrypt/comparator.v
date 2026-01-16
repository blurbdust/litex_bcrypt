`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

`include "main.vh"

module comparator(
	input CLK,
	input rst,

	// Input from cmp_config
	input [7:0] din,
	input wr_en,
	input [`HASH_NUM_MSB+2:0] wr_addr,
	input [`HASH_COUNT_MSB:0] hash_count,

	// Iteraction with arbiter_rx (comparsion)
	input [31:0] cmp_data,
	input start,
	output found, finished,
	output reg [`HASH_NUM_MSB:0] hash_num = 0
	);

	// **************************************************
	//
	// Comparator's state machine states
	//
	// **************************************************
	localparam STATE_IDLE = 0,
				STATE_START = 1,
				STATE_START2 = 2,
				STATE_COMPARE = 3;

	(* FSM_EXTRACT="true" *)
	reg [1:0] state = STATE_IDLE;

	// Internal state registers for found/finished
	// These are masked combinationally to prevent race conditions
	reg found_r = 0;
	reg finished_r = 0;

	// Combinational outputs - masked when comparison not complete
	// result_valid is only true when in STATE_IDLE after a comparison completed
	// This eliminates the 1-cycle race window caused by non-blocking assignments
	wire result_valid = (state == STATE_IDLE);
	assign found = found_r & result_valid;
	assign finished = finished_r & result_valid;


	// **************************************************
	//
	// Comparator's memory.
	// Input is 8-bit, output is 32-bit.
	//
	// **************************************************
	reg [`HASH_NUM_MSB:0] rd_addr = 0;
	reg [`HASH_COUNT_MSB:0] hash_count_curr = 1;

	wire [31:0] mem_dout;
	asymm_bram_min_wr #( .minWIDTH(), .RATIO(4), .maxDEPTH(`NUM_HASHES)
	) mem(
		.wr_clk(CLK), .din(din), .wr_en(wr_en), .wr_addr(wr_addr),
		.rd_clk(CLK), .dout(mem_dout), .rd_en(rd_en),
		.rd_addr(rd_addr)
	);

	// Prevent inference of BRAM output regs
	wire [31:0] mem_dout_r;
	ff32 ff_reg(
		.CLK(CLK), .en(rd_en), .rst(1'b0),
		.i(mem_dout), .o(mem_dout_r)
	);

	always @(posedge CLK) begin
		if (rst) begin
			// Reset all state
			found_r <= 0;
			finished_r <= 0;
			state <= STATE_IDLE;
			rd_addr <= 0;
			hash_count_curr <= 1;
			hash_num <= 0;
		end
		else begin
			case (state)
			STATE_IDLE: if (start) begin
				rd_addr <= 0;
				found_r <= 0;      // Clear internal register immediately
				finished_r <= 0;  // Clear internal register immediately
				state <= STATE_START;
			end

			STATE_START: begin
				// found_r/finished_r already cleared in STATE_IDLE
				hash_count_curr <= 1;
				hash_num <= 0;
				rd_addr <= rd_addr + 1'b1;
				state <= STATE_START2;
			end

			STATE_START2: begin
				rd_addr <= rd_addr + 1'b1;
				state <= STATE_COMPARE;
			end

			STATE_COMPARE: begin
				rd_addr <= rd_addr + 1'b1;
				hash_count_curr <= hash_count_curr + 1'b1;
				if (hash_count_curr == hash_count) begin
					finished_r <= 1;
					state <= STATE_IDLE;
				end

				if (mem_dout_r == cmp_data) begin
					found_r <= 1;
					state <= STATE_IDLE;
				end
				else
					hash_num <= hash_num + 1'b1;
			end
			endcase
		end
	end

	assign rd_en = state != STATE_IDLE;


endmodule
