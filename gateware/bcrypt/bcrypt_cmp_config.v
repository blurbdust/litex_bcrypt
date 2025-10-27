`timescale 1ns / 1ps
/*
 * Instrumented bcrypt_cmp_config (SIM_TRACE)
 */
`include "bcrypt.vh"

//`define SIM_TRACE 1

module bcrypt_cmp_config(
    input CLK,

    input [7:0] din,
    input wr_en,
    output reg full = 0,
    output error,

    // When asserted, it accepts packets without comparator data.
    input mode_cmp,

    // Interaction with other subsystems.
    output reg new_cmp_config = 0, // asserted when new cmp_config incoming
    // do not finish processing, block processing next packets by pkt_comm
    // until cmp_config_applied asserted
    input cmp_config_applied,

    // Output into comparator
    output reg [`HASH_COUNT_MSB:0] hash_count,
    output reg [`HASH_NUM_MSB+2:0] cmp_wr_addr = {`HASH_NUM_MSB+3{1'b1}},
    output reg cmp_wr_en = 0,
    output reg [7:0] cmp_din,

    // Output
    input [3:0] addr,
    output [31:0] dout,
    output reg sign_extension_bug = 0
    );

    integer k;

    reg [31:0] tmp = 0;
    reg sign_extension_bug_tmp;

    // Data for output is stored in 16 x32-bit distributed RAM.
    // 0 - iter_count(1)
    // 1-4 - salt(4)
    //
    (* RAM_STYLE="DISTRIBUTED" *)
    reg [31:0] data [15:0];
    initial
        for (k=6; k <= 10; k=k+1)
            data[k] = 0;

    assign dout = data [addr];
    reg [3:0] wr_addr = 1;

    reg [1:0] byte_count = 0;
    reg [1:0] salt_word_count = 0;

    reg [`HASH_NUM_MSB+2:0] cmp_wr_addr_max;
    wire [`HASH_NUM_MSB+3:0] cmp_wr_addr_max_eqn
        = { din[`HASH_COUNT_MSB-8:0], hash_count[7:0], 2'b00 } - 2'b10;

    localparam STATE_SALT                    = 0,
               STATE_SALT_SUBTYPE            = 1,
               STATE_ITER_COUNT              = 2,
               STATE_HASH_COUNT0             = 3,
               STATE_HASH_COUNT1             = 4,
               STATE_CMP_DATA                = 5,
               STATE_WAIT_CMP_CONFIG_APPLIED = 6,
               STATE_MAGIC                   = 7,
               STATE_ERROR                   = 8;

    (* FSM_EXTRACT="true" *)
    reg [3:0] state = STATE_SALT;

`ifdef SIM_TRACE
    // -------- Pretty state prints --------
    task automatic _print_state(input [3:0] st);
        case (st)
        STATE_SALT:                    $write("SALT");
        STATE_SALT_SUBTYPE:            $write("SUBTYPE");
        STATE_ITER_COUNT:              $write("ITER");
        STATE_HASH_COUNT0:             $write("HCNT0");
        STATE_HASH_COUNT1:             $write("HCNT1");
        STATE_CMP_DATA:                $write("CMP_DATA");
        STATE_WAIT_CMP_CONFIG_APPLIED: $write("WAIT_APPLIED");
        STATE_MAGIC:                   $write("MAGIC");
        STATE_ERROR:                   $write("ERROR");
        default:                       $write("?");
        endcase
    endtask

    reg [3:0] prev_state = STATE_SALT;
    reg       printed_error = 1'b0;

    // one-line helpers to keep strings short (avoid multiline literals)
    task automatic _log_state_change;
        $write("[%0t] CMP_CFG: ", $time);
        _print_state(prev_state);
        $write(" -> ");
        _print_state(state);
        $display("");
    endtask
`endif

    always @(posedge CLK) begin
`ifdef SIM_TRACE
        if (state != prev_state) begin
            _log_state_change();
            prev_state <= state;
        end
`endif

        if (state == STATE_ERROR) begin
            full <= 1;
`ifdef SIM_TRACE
            if (!printed_error) begin
                $display("[%0t] CMP_CFG ERR: state=ERROR byte_count=%0d salt_word=%0d wr_addr=%0d tmp=0x%08x mode_cmp=%0d",
                    $time, byte_count, salt_word_count, wr_addr, tmp, mode_cmp);
                printed_error <= 1'b1;
            end
`endif
        end

        else if (state == STATE_WAIT_CMP_CONFIG_APPLIED) begin
            cmp_wr_en <= 0;
            if (cmp_config_applied) begin
                new_cmp_config <= 0;
                sign_extension_bug <= sign_extension_bug_tmp;
                full <= 0;
                state <= STATE_MAGIC;
`ifdef SIM_TRACE
                $display("[%0t] CMP_CFG: applied=1 (sign_ext_bug=%0d) -> MAGIC", $time, sign_extension_bug_tmp);
`endif
            end
        end

        else if (~wr_en)
            cmp_wr_en <= 0;

        else if (wr_en) begin
        case (state)
        // ---------------- SALT (16 bytes, 4×32b words) ----------------
        STATE_SALT: begin
            if (byte_count == 3) begin
`ifdef SIM_TRACE
                $display("[%0t] CMP_CFG: SALT word%0d = 0x%08x", $time, salt_word_count, tmp);
`endif
                if (salt_word_count == 3)
                    state <= STATE_SALT_SUBTYPE;
                salt_word_count <= salt_word_count + 1'b1;
            end
            tmp[8*(byte_count+1)-1 -:8] <= din;
            byte_count <= byte_count + 1'b1;
            if (byte_count == 0 && salt_word_count > 0) begin
                wr_addr <= wr_addr + 1'b1;
            end
        end

        // ---------------- SUBTYPE ('a','b','x','y') ----------------
        STATE_SALT_SUBTYPE: begin
            if (din == "x") begin
                sign_extension_bug_tmp <= 1;
                state <= STATE_ITER_COUNT;
`ifdef SIM_TRACE
                $display("[%0t] CMP_CFG: SUBTYPE='x' (sign_ext_bug=1)", $time);
`endif
            end
            else if (din == "a" || din == "b" || din == "y") begin
                sign_extension_bug_tmp <= 0;
                state <= STATE_ITER_COUNT;
`ifdef SIM_TRACE
                $display("[%0t] CMP_CFG: SUBTYPE='%c' (sign_ext_bug=0)", $time, din);
`endif
            end
            else begin
                state <= STATE_ERROR;
`ifdef SIM_TRACE
                $display("[%0t] CMP_CFG: SUBTYPE invalid 0x%02x -> ERROR", $time, din);
`endif
            end
        end

        // ---------------- ITER COUNT (4 bytes) ----------------
        STATE_ITER_COUNT: begin
            if (byte_count == 3) begin
                state <= STATE_HASH_COUNT0;
`ifdef SIM_TRACE
                $display("[%0t] CMP_CFG: ITER tmp=0x%08x (will be stored at data[0])", $time, tmp);
`endif
            end
            tmp[8*(byte_count+1)-1 -:8] <= din;
            byte_count <= byte_count + 1'b1;
            wr_addr <= 0;
        end

        // ---------------- HASH COUNT low byte ----------------
        STATE_HASH_COUNT0: begin
            hash_count[7:0] <= din;
            if (|tmp[31:`SETTING_MAX+1]) begin
                state <= STATE_ERROR;
`ifdef SIM_TRACE
                $display("[%0t] CMP_CFG: ITER out-of-range tmp=0x%08x -> ERROR", $time, tmp);
`endif
            end
            else begin
                state <= STATE_HASH_COUNT1;
`ifdef SIM_TRACE
                $display("[%0t] CMP_CFG: HCNT0=0x%02x", $time, din);
`endif
            end
        end

        // ---------------- HASH COUNT high bits & branch ----------------
        STATE_HASH_COUNT1: begin
            hash_count[`HASH_COUNT_MSB:8] <= din[`HASH_COUNT_MSB-8:0];
            cmp_wr_addr <= {`HASH_NUM_MSB+3{1'b1}};
            cmp_wr_addr_max <= cmp_wr_addr_max_eqn[`HASH_NUM_MSB+2:0];

`ifdef SIM_TRACE
            $display("[%0t] CMP_CFG: HCNT1=0x%02x  hash_count=%0d  mode_cmp=%0d  cmp_wr_addr_max=0x%0x",
                     $time, din, hash_count[`HASH_COUNT_MSB:0], mode_cmp, cmp_wr_addr_max);
`endif
            if (mode_cmp) begin
                state <= STATE_CMP_DATA;
`ifdef SIM_TRACE
                $display("[%0t] CMP_CFG: entering CMP_DATA", $time);
`endif
            end
            else begin
                if (din != 0) begin
                    state <= STATE_ERROR;
`ifdef SIM_TRACE
                    $display("[%0t] CMP_CFG: nonzero HCNT1 while mode_cmp=0 -> ERROR", $time);
`endif
                end
                else begin
                    new_cmp_config <= 1;
                    full <= 1;
                    state <= STATE_WAIT_CMP_CONFIG_APPLIED;
`ifdef SIM_TRACE
                    $display("[%0t] CMP_CFG: new_cmp_config=1 (no comparator data), waiting applied...", $time);
`endif
                end
            end
        end

        // ---------------- Comparator data stream ----------------
        STATE_CMP_DATA: begin
            cmp_wr_en <= 1;
            cmp_din   <= din;
            cmp_wr_addr <= cmp_wr_addr + 1'b1;
`ifdef SIM_TRACE
            // print first few and last few writes
            if (cmp_wr_addr == {`HASH_NUM_MSB+3{1'b1}})
                $display("[%0t] CMP_CFG: CMP_DATA start (addr starts at -1)", $time);
            if (cmp_wr_addr[4:0] == 0)
                $display("[%0t] CMP_CFG: CMP wr addr=0x%0x din=0x%02x", $time, cmp_wr_addr + 1'b1, din);
`endif
            if (cmp_wr_addr == cmp_wr_addr_max) begin
                new_cmp_config <= 1;
                full <= 1;
                state <= STATE_WAIT_CMP_CONFIG_APPLIED;
`ifdef SIM_TRACE
                $display("[%0t] CMP_CFG: CMP_DATA end at addr=0x%0x  new_cmp_config=1, wait applied...",
                         $time, cmp_wr_addr + 1'b1);
`endif
            end
        end

        // ---------------- MAGIC byte (0xCC) ----------------
        STATE_MAGIC: begin
            wr_addr <= 1;
            if (din == 8'hCC) begin
                state <= STATE_SALT;
`ifdef SIM_TRACE
                $display("[%0t] CMP_CFG: MAGIC ok (0xCC), back to SALT", $time);
`endif
            end else begin
                state <= STATE_ERROR;
`ifdef SIM_TRACE
                $display("[%0t] CMP_CFG: MAGIC bad 0x%02x -> ERROR", $time, din);
`endif
            end
        end

        endcase
        end
    end

    assign error = state == STATE_ERROR;

    // Writes into data[] map (iter and salt)
    always @(posedge CLK)
        if (state == STATE_SALT & (byte_count == 0 && salt_word_count > 0)
            | state == STATE_SALT_SUBTYPE // saves last 32-bit of salt
            | state == STATE_HASH_COUNT0) // saves iter_count
            data[wr_addr] <= tmp;

endmodule
