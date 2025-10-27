// SPDX-License-Identifier: BSD-2-Clause
//
// bcrypt_axis8_wrap.sv — Symmetric AXI4-Stream 8-bit IN/OUT + CSR-style control for LiteX
//
`timescale 1ns/1ps
/* verilator lint_off TIMESCALEMOD */
`include "main.vh"
`include "bcrypt.vh"

//`define SIM_TRACE 1
`define SIM_TRACE2 1

module bcrypt_axis_8b #(
  parameter int NUM_CORES      = 12,
  parameter int VERSION        = `PKT_COMM_VERSION,
  parameter int PKT_MAX_LEN    = 16*65536,
  parameter int PKT_LEN_MSB    = `MSB(PKT_MAX_LEN),
  parameter int WORD_MAX_LEN   = `PLAINTEXT_LEN,
  parameter int CHAR_BITS      = `CHAR_BITS,
  parameter int RANGES_MAX     = `RANGES_MAX,
  parameter int RANGE_INFO_MSB = 1 + `MSB(WORD_MAX_LEN-1),
  parameter bit SIMULATION     = 1'b0
)(
  input  wire                   CORE_CLK,
  input  wire                   CORE_RSTN,

  // -------------------- AXI4-Stream IN (8-bit) --------------------
  input  wire [7:0]             s_axis_tdata,
  input  wire                   s_axis_tvalid,
  output wire                   s_axis_tready,
  input  wire                   s_axis_tlast,

  // -------------------- AXI4-Stream OUT (8-bit) -------------------
  output wire [7:0]             m_axis_tdata,
  output wire                   m_axis_tvalid,
  input  wire                   m_axis_tready,
  output wire                   m_axis_tlast,

  // -------------------- CSR-like control/status --------------------
  input  wire                   mode_cmp,
  input  wire                   output_mode_limit,
  input  wire                   reg_output_limit,

  output wire [7:0]             app_status,
  output wire [7:0]             pkt_comm_status,
  output wire                   idle,
  output wire                   error_o,

  // Core array ports passthrough
  output wire  [7:0]            core_din,
  output wire  [1:0]            core_ctrl,
  output wire  [NUM_CORES-1:0]  core_wr_en,
  input  wire  [NUM_CORES-1:0]  core_init_ready,
  input  wire  [NUM_CORES-1:0]  core_crypt_ready,
  output wire  [NUM_CORES-1:0]  core_rd_en,
  input  wire  [NUM_CORES-1:0]  core_empty,
  input  wire  [NUM_CORES-1:0]  core_dout
);
  wire CLK  = CORE_CLK;
  wire RSTN = CORE_RSTN;

  // ================= IN: AXIS8 → byte FIFO =================
  wire [7:0] din;
  wire       rd_en;
  wire       empty;
  wire       inpkt_end;

  axis8_to_fifo #(.DEPTH(2048)) u_axis_in (
    .CLK(CLK), .RSTN(RSTN),
    .s_tdata (s_axis_tdata),
    .s_tvalid(s_axis_tvalid),
    .s_tready(s_axis_tready),
    .s_tlast (s_axis_tlast),
    .dout(din), .rd_en(rd_en), .empty(empty), .pkt_end_pulse(inpkt_end)
  );

`ifdef SIM_TRACE
  // Raw AXIS ingress visibility
  always @(posedge CLK) if (s_axis_tvalid && s_axis_tready)
    $display("[%0t] AXIS.IN byte=0x%02x last=%0d", $time, s_axis_tdata, s_axis_tlast);
`endif

  // ================= OUT: 16-bit producer → AXIS8 =================
  wire [15:0] dout16;
  wire        outpkt_empty;
  wire        outpkt_rd_en;
  wire        outpkt_last;

  stream16_to_axis8 u_axis_out (
    .CLK(CLK), .RSTN(RSTN),
    .din(dout16), .din_valid(~outpkt_empty), .din_ready(outpkt_rd_en), .din_last(outpkt_last),
    .m_tdata(m_axis_tdata), .m_tvalid(m_axis_tvalid), .m_tready(m_axis_tready), .m_tlast(m_axis_tlast)
  );

`ifdef SIM_TRACE
  // AXIS egress visibility
  always @(posedge CLK) if (m_axis_tvalid && m_axis_tready)
    $display("[%0t] AXIS.OUT byte=0x%02x last=%0d", $time, m_axis_tdata, m_axis_tlast);
`endif

  // ================= Datapath original ====================
  localparam PKT_TYPE_WORD_LIST     = 8'd1;
  localparam PKT_TYPE_WORD_GEN      = 8'd2;
  localparam PKT_TYPE_CMP_CONFIG    = 8'd3;
  localparam PKT_TYPE_TEMPLATE_LIST = 8'd4;

  wire [`MSB(4):0] inpkt_type;
  wire [15:0]      inpkt_id;
  wire             inpkt_data;
  wire             err_pkt_version, err_inpkt_type, err_inpkt_len, err_inpkt_checksum;

  inpkt_header #(
    .VERSION(VERSION), .PKT_MAX_LEN(PKT_MAX_LEN), .PKT_MAX_TYPE(4), .DISABLE_CHECKSUM(SIMULATION)
  ) u_hdr (
    .CLK(CLK), .din(din), .wr_en(rd_en),
    .pkt_type(inpkt_type), .pkt_id(inpkt_id), .pkt_data(inpkt_data), .pkt_end(inpkt_end),
    .err_pkt_version(err_pkt_version), .err_pkt_type(err_inpkt_type),
    .err_pkt_len(err_inpkt_len), .err_pkt_checksum(err_inpkt_checksum)
  );

reg [7:0] dbg_cnt;
always @(posedge CLK) begin
  if (!RSTN) dbg_cnt <= 0;
  else if (inpkt_data && rd_en && dbg_cnt < 32) begin
    $display("[%0t] CMP_PAY[%0d] = 0x%02x (type=%0d id=0x%04x)",
      $time, dbg_cnt, din, inpkt_type, inpkt_id);
    dbg_cnt <= dbg_cnt + 1;
  end
  if (inpkt_end) dbg_cnt <= 0;
end

`ifdef SIM_TRACE
  // Header + errors
  always @(posedge CLK) begin
    if (inpkt_end) $display("[%0t] HDR: end type=%0d id=0x%04x", $time, inpkt_type, inpkt_id);
    if (err_pkt_version)   $display("[%0t] HDR: ERR version",  $time);
    if (err_inpkt_type)    $display("[%0t] HDR: ERR type",     $time);
    if (err_inpkt_len)     $display("[%0t] HDR: ERR len",      $time);
    if (err_inpkt_checksum)$display("[%0t] HDR: ERR checksum", $time);
  end
`endif

  wire word_gen_conf_en, word_list_wr_en, cmp_config_wr_en;
  assign rd_en = ~empty & (~inpkt_data | word_gen_conf_en | word_list_wr_en | cmp_config_wr_en);

  // WORD_LIST/TEMPLATE
  wire word_list_full, word_list_empty, word_list_set_empty, word_list_end, err_template, err_word_list_count;
  wire [7:0]  word_list_dout;
  wire [`MSB(WORD_MAX_LEN-1):0] word_rd_addr;
  wire [RANGES_MAX * (RANGE_INFO_MSB+1) - 1 :0] range_info;
  wire [15:0] word_id;

  assign word_list_wr_en = ~empty & (inpkt_type==PKT_TYPE_WORD_LIST || inpkt_type==PKT_TYPE_TEMPLATE_LIST)
                         & inpkt_data & ~word_list_full;

  template_list_b #(.WORD_MAX_LEN(WORD_MAX_LEN), .RANGES_MAX(RANGES_MAX)) u_word_list (
    .CLK(CLK), .din(din), .wr_en(word_list_wr_en), .full(word_list_full), .inpkt_end(inpkt_end),
    .is_template_list(inpkt_type==PKT_TYPE_TEMPLATE_LIST),
    .dout(word_list_dout), .rd_addr(word_rd_addr),
    .set_empty(word_list_set_empty), .empty(word_list_empty),
    .range_info(range_info), .word_id(word_id), .word_list_end(word_list_end),
    .err_template(err_template), .err_word_list_count(err_word_list_count)
  );

`ifdef SIM_TRACE
  always @(posedge CLK) begin
    if (word_list_wr_en)
      $display("[%0t] WORD_LIST wr din=0x%02x empty=%0d full=%0d", $time, din, word_list_empty, word_list_full);
    if (inpkt_end && (inpkt_type==PKT_TYPE_WORD_LIST || inpkt_type==PKT_TYPE_TEMPLATE_LIST))
      $display("[%0t] WORD_LIST pkt end", $time);
    if (err_template)         $display("[%0t] WORD_LIST ERR template", $time);
    if (err_word_list_count)  $display("[%0t] WORD_LIST ERR count",    $time);
  end
`endif

  // WORD_GEN
  wire word_gen_conf_full, word_gen_empty, word_gen_set_empty;
  wire [7:0]  word_gen_dout;
  wire [`MSB(WORD_MAX_LEN-1):0] word_gen_rd_addr;
  wire [15:0] pkt_id, word_id_out;
  wire [31:0] gen_id;
  wire        gen_end;
  wire        err_word_gen_conf;

  assign word_gen_conf_en = ~empty & (inpkt_type==PKT_TYPE_WORD_GEN) & inpkt_data & ~word_gen_conf_full;

  word_gen_b #(.RANGES_MAX(RANGES_MAX), .WORD_MAX_LEN(WORD_MAX_LEN)) u_word_gen (
    .CLK(CLK), .din(din), .inpkt_id(inpkt_id), .conf_wr_en(word_gen_conf_en), .conf_full(word_gen_conf_full),
    .word_in(word_list_dout), .word_rd_addr(word_rd_addr), .word_set_empty(word_list_set_empty), .word_empty(word_list_empty),
    .range_info(range_info), .word_id(word_id), .word_list_end(word_list_end),
    .dout(word_gen_dout), .rd_addr(word_gen_rd_addr), .set_empty(word_gen_set_empty), .empty(word_gen_empty),
    .pkt_id(pkt_id), .word_id_out(word_id_out), .gen_id(gen_id), .gen_end(gen_end), .word_end(),
    .err_word_gen_conf(err_word_gen_conf)
  );

`ifdef SIM_TRACE
  always @(posedge CLK) begin
    if (word_gen_conf_en)    $display("[%0t] WORD_GEN conf din=0x%02x", $time, din);
    if (word_gen_conf_full)  $display("[%0t] WORD_GEN conf_full=1",     $time);
    if (word_gen_set_empty)  $display("[%0t] WORD_GEN set_empty",       $time);
    if (!word_gen_empty)     $display("[%0t] WORD_GEN dout=0x%02x rd_addr=%0d pkt_id=0x%04x", $time, word_gen_dout, word_gen_rd_addr, pkt_id);
    if (err_word_gen_conf)   $display("[%0t] WORD_GEN ERR conf",        $time);
  end
`endif

  // CMP_CONFIG
  wire cmp_config_full, new_cmp_config, cmp_config_applied, sign_extension_bug, err_cmp_config;
  wire [`HASH_COUNT_MSB:0]  hash_count;
  wire [`HASH_NUM_MSB+2:0]  cmp_wr_addr;
  wire                      cmp_wr_en;
  wire [7:0]                cmp_din;
  wire [3:0]                cmp_config_addr;
  wire [31:0]               cmp_config_dout;

  assign cmp_config_wr_en = ~empty & (inpkt_type==PKT_TYPE_CMP_CONFIG) & inpkt_data & ~cmp_config_full;

  bcrypt_cmp_config u_cmp_config (
    .CLK(CLK), .din(din), .wr_en(cmp_config_wr_en), .full(cmp_config_full),
    .mode_cmp(mode_cmp), .error(err_cmp_config),
    .hash_count(hash_count), .cmp_wr_addr(cmp_wr_addr), .cmp_wr_en(cmp_wr_en), .cmp_din(cmp_din),
    .new_cmp_config(new_cmp_config), .cmp_config_applied(cmp_config_applied),
    .addr(cmp_config_addr), .dout(cmp_config_dout), .sign_extension_bug(sign_extension_bug)
  );

`ifdef SIM_TRACE
  always @(posedge CLK) begin
    if (cmp_config_wr_en)     $display("[%0t] CMP_CFG wr din=0x%02x addr=%0d", $time, din, cmp_config_addr);
    if (new_cmp_config)       $display("[%0t] CMP_CFG new_cmp_config=1",       $time);
    if (cmp_config_applied)   $display("[%0t] CMP_CFG applied",                $time);
    if (err_cmp_config)       $display("[%0t] CMP_CFG ERR",                    $time);
  end
`endif

  // EXPAND KEY
  wire [31:0] ek_dout;
  wire        ek_rd_en, ek_empty;
  wire        bcrypt_data_ek_full;

  bcrypt_expand_key_b u_expand (
    .CLK(CLK), .din(word_gen_dout), .rd_addr(word_gen_rd_addr),
    .word_set_empty(word_gen_set_empty), .word_empty(word_gen_empty), .sign_extension_bug(sign_extension_bug),
    .dout(ek_dout), .rd_en(ek_rd_en), .empty(ek_empty)
  );

`ifdef SIM_TRACE
  always @(posedge CLK) begin
    if (ek_rd_en && ~ek_empty) $display("[%0t] EK rd_en dout=0x%08x", $time, ek_dout);
  end
`endif

  // BCDATA
  wire [7:0]  bcdata_dout;
  wire [1:0]  bcdata_ctrl;
  wire [15:0] bcdata_pkt_id;
  wire        bcdata_gen_end;
  wire        bcdata_ready;
  wire        start_init_tx, start_data_tx;
  wire [2:0]  bcdata_error;

  assign ek_rd_en = ~ek_empty & ~bcrypt_data_ek_full;

  wire bc_init_ready;

  bcrypt_data u_bcdata (
    .CLK(CLK), .pkt_id(pkt_id), .word_id(word_id_out), .gen_id(gen_id), .gen_end(gen_end),
    .ek_in(ek_dout), .ek_wr_en(ek_rd_en), .ek_full(bcrypt_data_ek_full), .ek_valid(~ek_empty),
    .new_cmp_config(new_cmp_config), .cmp_config_applied(cmp_config_applied),
    .cmp_config_addr(cmp_config_addr), .cmp_config_data(cmp_config_dout),
    .dout(bcdata_dout), .ctrl(bcdata_ctrl), .error(bcdata_error),
    .bcdata_pkt_id(bcdata_pkt_id), .bcdata_gen_end(bcdata_gen_end),
    .data_ready(bcdata_ready), .init_ready(bc_init_ready),
    .start_init_tx(start_init_tx), .start_data_tx(start_data_tx), .data_tx_done(), .init_tx_done()
  );

`ifdef SIM_TRACE
  always @(posedge CLK) begin
    if (bcdata_ready)      $display("[%0t] BCDATA data_ready=1 pkt_id=0x%04x gen_end=%0d", $time, bcdata_pkt_id, bcdata_gen_end);
    if (|bcdata_error)     $display("[%0t] BCDATA ERR bits=0x%0x", $time, bcdata_error);
  end
`endif

  // ARBITER + CORES
  wire [31:0]            cmp_data;
  wire                   cmp_start, cmp_found, cmp_finished;
  wire [`HASH_NUM_MSB:0] cmp_hash_num;
  wire [`OUTPKT_TYPE_MSB:0] outpkt_type;
  wire [15:0]            arbiter_pkt_id;
  wire [31:0]            num_processed;
  wire [`HASH_NUM_MSB:0] hash_num;
  wire [15:0]            arbiter_dout;
  wire [3:0]             arbiter_rd_addr;
  wire                   arbiter_empty, arbiter_rd_en;
  wire [3:0]             arbiter_error;
  wire                   arbiter_idle;

  bcrypt_arbiter #(.NUM_CORES(NUM_CORES)) u_arb (
    .CLK(CLK), .mode_cmp(mode_cmp),
    .din(bcdata_dout), .ctrl(bcdata_ctrl),
    .init_ready(bc_init_ready), .data_ready(bcdata_ready),
    .start_init_tx(start_init_tx), .start_data_tx(start_data_tx),
    .bcdata_gen_end(bcdata_gen_end), .bcdata_pkt_id(bcdata_pkt_id),
    .cmp_data(cmp_data), .cmp_start(cmp_start), .cmp_found(cmp_found), .cmp_finished(cmp_finished), .cmp_hash_num(cmp_hash_num),
    .dout(arbiter_dout), .rd_addr(arbiter_rd_addr), .outpkt_type(outpkt_type), .pkt_id(arbiter_pkt_id),
    .num_processed(num_processed), .hash_num(hash_num), .empty(arbiter_empty), .rd_en(arbiter_rd_en),
    .error(arbiter_error), .idle(arbiter_idle),
    .core_din(core_din), .core_ctrl(core_ctrl), .core_wr_en(core_wr_en),
    .core_init_ready_in(core_init_ready), .core_crypt_ready_in(core_crypt_ready),
    .core_rd_en(core_rd_en), .core_empty_in(core_empty), .core_dout_in(core_dout)
  );

`ifdef SIM_TRACE
  always @(posedge CLK) begin
    if (start_init_tx)   $display("[%0t] ARB start_init_tx", $time);
    if (start_data_tx)   $display("[%0t] ARB start_data_tx pkt_id=0x%04x", $time, bcdata_pkt_id);
    if (cmp_start)       $display("[%0t] CMP start hash_num=%0d", $time, cmp_hash_num);
    if (cmp_found)       $display("[%0t] CMP found hash_num=%0d", $time, cmp_hash_num);
    if (cmp_finished)    $display("[%0t] CMP finished", $time);
    if (|arbiter_error)  $display("[%0t] ARB ERR bits=0x%0x", $time, arbiter_error);
  end
`endif

  // COMPARATOR
  comparator u_cmp (
    .CLK(CLK), .din(cmp_din), .wr_en(cmp_wr_en), .wr_addr(cmp_wr_addr), .hash_count(hash_count),
    .cmp_data(cmp_data), .start(cmp_start), .found(cmp_found), .finished(cmp_finished), .hash_num(cmp_hash_num)
  );

  // OUTPKT → split 16→8
  wire outpkt_full = 1'b0;
  assign arbiter_rd_en = ~arbiter_empty & ~outpkt_full;

  outpkt_bcrypt #(.HASH_NUM_MSB(`HASH_NUM_MSB), .SIMULATION(SIMULATION)) u_outpkt (
    .CLK(CLK),
    .din(arbiter_dout), .rd_addr(arbiter_rd_addr),
    .source_not_empty(~arbiter_empty),
    .wr_en(arbiter_rd_en),
    .full(outpkt_full),

    .pkt_type(outpkt_type), .pkt_id(arbiter_pkt_id),
    .hash_num(hash_num), .num_processed(num_processed),

    .dout(dout16), .rd_en(outpkt_rd_en),
    .empty(outpkt_empty), .pkt_end_out(outpkt_last)
  );

`ifdef SIM_TRACE
  always @(posedge CLK) begin
    if (arbiter_rd_en && ~arbiter_empty)
      $display("[%0t] OUTPKT rd word=0x%04x last=%0d", $time, dout16, outpkt_last);
  end
`endif

  // STATUS/IDLE/ERROR
  assign pkt_comm_status = {err_cmp_config, err_word_gen_conf, err_template, err_word_list_count,
                            err_pkt_version, err_inpkt_type, err_inpkt_len, err_inpkt_checksum};
  assign app_status      = {1'b0, bcdata_error, arbiter_error};

  reg error_r;
  always @(posedge CLK or negedge RSTN) begin
    if (!RSTN) error_r <= 1'b0;
    else if (|app_status | |pkt_comm_status) error_r <= 1'b1;
  end

  delay #(.INIT(1), .NBITS(6)) u_idle_delay (.CLK(CLK),
    .in(~s_axis_tvalid & arbiter_idle), .out(idle));

  assign error_o = error_r;

  `ifdef SIM_TRACE2
  // OUTPKT -> stream16_to_axis8 handshake
  always @(posedge CLK) begin
    if (~outpkt_empty && outpkt_rd_en)
      $display("[%0t] OUTPKT->AXIS16 word=0x%04x last=%0d (empty=%0d)",
               $time, dout16, outpkt_last, outpkt_empty);
    if (~outpkt_empty && ~outpkt_rd_en)
      $display("[%0t] OUTPKT waiting: AXIS16 not ready (empty=%0d vld=%0d m_tready=%0d)",
               $time, outpkt_empty, m_axis_tvalid, m_axis_tready);

    // Downstream readiness
    if (m_axis_tvalid && ~m_axis_tready)
      $display("[%0t] AXIS8 downstream not ready (valid=1)", $time);
  end
`endif


endmodule

// ============================ Helpers ============================

module axis8_to_fifo #(parameter DEPTH=2048) (
  input  wire       CLK,
  input  wire       RSTN,
  input  wire [7:0] s_tdata,
  input  wire       s_tvalid,
  output wire       s_tready,
  input  wire       s_tlast,
  output wire [7:0] dout,
  input  wire       rd_en,
  output wire       empty,
  output wire       pkt_end_pulse
);
  localparam AW = $clog2(DEPTH);
  reg  [8:0] mem [0:DEPTH-1];
  reg  [AW:0] wr_ptr, rd_ptr;

  assign s_tready = 1'b1;

  always @(posedge CLK or negedge RSTN) begin
    if (!RSTN) wr_ptr <= '0;
    else if (s_tvalid & s_tready) begin
      mem[wr_ptr[AW-1:0]] <= {s_tlast, s_tdata};
      wr_ptr <= wr_ptr + 1'b1;
    end
  end

  assign empty         = (wr_ptr==rd_ptr);
  assign dout          = mem[rd_ptr[AW-1:0]][7:0];
  assign pkt_end_pulse = rd_en & ~empty & mem[rd_ptr[AW-1:0]][8];

  always @(posedge CLK or negedge RSTN) begin
    if (!RSTN) rd_ptr <= '0;
    else if (rd_en & ~empty) rd_ptr <= rd_ptr + 1'b1;
  end
endmodule

module stream16_to_axis8 (
  input  wire        CLK, RSTN,
  input  wire [15:0] din,
  input  wire        din_valid,
  output wire        din_ready,
  input  wire        din_last,
  output wire [7:0]  m_tdata,
  output wire        m_tvalid,
  input  wire        m_tready,
  output wire        m_tlast
);
  typedef enum logic [0:0] {IDLE=1'b0, HI=1'b1} st_t;
  st_t state;
  reg  [15:0] shreg;
  reg         last_reg;
  reg         vld;

  assign din_ready = (state == IDLE) && (~vld) && din_valid;
  //assign din_ready = (state==IDLE) ? (((~vld) || (vld && m_tready)) && din_valid) : 1'b0;
  assign m_tdata   = (state==IDLE) ? shreg[7:0] : shreg[15:8];
  assign m_tvalid  = vld;
  assign m_tlast   = vld && (state==HI) && last_reg;

  always @(posedge CLK or negedge RSTN) begin
    if (!RSTN) begin
      state <= IDLE; shreg <= 16'd0; last_reg<=1'b0; vld<=1'b0;
    end else begin
      case (state)
        IDLE: begin
          if (din_valid && din_ready) begin
            shreg    <= din;
            last_reg <= din_last;
            vld      <= 1'b1;
          end
          if (vld && m_tready) state <= HI;
        end
        HI: begin
          if (vld && m_tready) begin
            vld   <= 1'b0;
            state <= IDLE;
          end
        end
      endcase
    end
  end

endmodule
