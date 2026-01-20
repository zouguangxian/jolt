//! CSRRW (CSR Read-Write) — Write rs1 to CSR, read old value to rd.
//!
//! Encoding: csr[31:20] | rs1[19:15] | funct3=001[14:12] | rd[11:7] | opcode=1110011[6:0]
//!
//! For ZeroOS: Single-core, no-interrupts, M-mode-only. Supports the following CSRs
//! mapped to virtual registers for proof verification:
//!   - mtvec (0x305) → vr33
//!   - mscratch (0x340) → vr34
//!   - mepc (0x341) → vr35
//!   - mcause (0x342) → vr36
//!   - mtval (0x343) → vr37
//!   - mstatus (0x300) → vr38
//!
//! The `csrw csr, rs` pseudo-instruction is `csrrw x0, csr, rs` (rd=0, discard old value).
//! The full `csrrw rd, csr, rs` swaps rd ← old_CSR, CSR ← rs.

use serde::{Deserialize, Serialize};

use crate::{
    declare_riscv_instr,
    emulator::cpu::{Cpu, Xlen},
    utils::inline_helpers::InstrAssembler,
    utils::virtual_registers::VirtualRegisterAllocator,
};

use super::{
    addi::ADDI,
    format::format_i::FormatI,
    virtual_advice::VirtualAdvice,
    virtual_assert_eq::VirtualAssertEQ,
    Cycle, Instruction, RISCVInstruction, RISCVTrace,
};

/// CSR addresses for M-mode CSRs
const CSR_MSTATUS: u16 = 0x300;  // Machine Status
const CSR_MTVEC: u16 = 0x305;    // Machine Trap-Vector Base Address
const CSR_MSCRATCH: u16 = 0x340; // Machine Scratch Register
const CSR_MEPC: u16 = 0x341;     // Machine Exception Program Counter
const CSR_MCAUSE: u16 = 0x342;   // Machine Trap Cause
const CSR_MTVAL: u16 = 0x343;    // Machine Trap Value

declare_riscv_instr!(
    name   = CSRRW,
    mask   = 0x0000707f,  // Match opcode (7 bits) + funct3 (3 bits)
    match  = 0x00001073,  // opcode=1110011, funct3=001
    format = FormatI,
    ram    = ()
);

impl CSRRW {
    /// Extract CSR address from the immediate field (bits [31:20] of instruction)
    fn csr_address(&self) -> u16 {
        (self.operands.imm & 0xfff) as u16
    }

    fn exec(&self, cpu: &mut Cpu, _: &mut <CSRRW as RISCVInstruction>::RAMAccess) {
        let csr_addr = self.csr_address();
        let rs1_val = cpu.x[self.operands.rs1 as usize] as u64;

        // Read old CSR value (for rd, if rd != 0)
        let old_val = cpu.read_csr_raw(csr_addr);

        // Write new value to CSR (emulation state - NOT proven)
        cpu.write_csr_raw(csr_addr, rs1_val);

        // Write old value to rd (if rd != x0)
        if self.operands.rd != 0 {
            cpu.x[self.operands.rd as usize] = cpu.sign_extend(old_val as i64);
        }
    }
}

impl RISCVTrace for CSRRW {
    fn trace(&self, cpu: &mut Cpu, trace: Option<&mut Vec<Cycle>>) {
        let csr_addr = self.csr_address();

        // Get the OLD CSR value before executing (for rd when rd != 0)
        let old_csr_val = cpu.read_csr_raw(csr_addr);

        // Get the value being written (from rs1)
        let write_val = cpu.x[self.operands.rs1 as usize] as u64;

        if std::env::var("JOLT_DEBUG_CSRRW").is_ok() {
            eprintln!(
                "CSRRW @ {:#x}: csr=0x{:03x} rd=x{} rs1=x{} old={:#x} write={:#x}",
                self.address, csr_addr, self.operands.rd, self.operands.rs1, old_csr_val, write_val
            );
        }

        // Special case: if rd == rs1 (and rd != 0), executing CSRRW will overwrite rs1 with
        // old_CSR. Our proof sequence still needs access to the *original* rs1 value.
        //
        // We stash it into a dedicated persistent virtual register before executing.
        if self.operands.rd != 0 && self.operands.rd == self.operands.rs1 {
            let saved = cpu.vr_allocator.csrrw_saved_rs1_register() as usize;
            cpu.x[saved] = cpu.sign_extend(write_val as i64);
        }

        // Execute the CSR operation (updates emulation state)
        let mut ram_access = ();
        self.execute(cpu, &mut ram_access);

        // Generate inline sequence for proof verification
        let mut inline_sequence = self.inline_sequence(&cpu.vr_allocator, cpu.xlen);

        if self.operands.rd == 0 {
            // csrw pseudo-instruction: one advice (new CSR value)
            let mut filled = 0;
            for instr in &mut inline_sequence {
                if let Instruction::VirtualAdvice(v) = instr {
                    v.advice = write_val;
                    filled += 1;
                    break;
                }
            }
            if filled != 1 {
                panic!("CSRRW (rd=0): expected 1 VirtualAdvice, saw {filled}");
            }
        } else {
            // Full csrrw: two advice values (old CSR, then new write value).
            let mut filled = 0;
            for instr in &mut inline_sequence {
                if let Instruction::VirtualAdvice(v) = instr {
                    v.advice = match filled {
                        0 => old_csr_val,
                        1 => write_val,
                        _ => v.advice,
                    };
                    filled += 1;
                    if filled == 2 {
                        break;
                    }
                }
            }
            if filled != 2 {
                panic!("CSRRW (rd!=0): expected 2 VirtualAdvice, saw {filled}");
            }
        }

        // Execute inline sequence to record in trace
        let mut trace = trace;
        for instr in inline_sequence {
            instr.trace(cpu, trace.as_deref_mut());
        }

    }

    /// Generate inline sequence for CSRRW.
    ///
    /// For rd = 0 (csrw pseudo-instruction):
    ///   0: VirtualAdvice(temp_new)      - Get write value as advice
    ///   1: VirtualAssertEQ(temp_new, rs1) - Assert advice matches rs1
    ///   2: ADDI(vr, temp_new, 0)        - Write to CSR virtual register
    ///
    /// For rd != 0 (full csrrw, atomic swap):
    ///   0: ADDI(rs1_copy, rs1, 0)            - Copy rs1 (handles rd == rs1 case)
    ///   1: VirtualAdvice(temp_old)           - Get OLD CSR value as advice
    ///   2: VirtualAssertEQ(temp_old, vr)     - Assert old advice matches current CSR virtual register
    ///   3: ADDI(rd, temp_old, 0)             - Write old value to rd (may clobber rs1)
    ///   4: VirtualAdvice(temp_new)           - Get NEW value (rs1) as advice
    ///   5: VirtualAssertEQ(temp_new, rs1_copy) - Assert new advice matches original rs1
    ///   6: ADDI(vr, temp_new, 0)             - Write new value to CSR virtual register
    fn inline_sequence(
        &self,
        allocator: &VirtualRegisterAllocator,
        xlen: Xlen,
    ) -> Vec<Instruction> {
        let csr_addr = self.csr_address();

        // Map CSR address to virtual register
        let virtual_reg = match csr_addr {
            CSR_MSTATUS => allocator.mstatus_register(),         // mstatus → vr38
            CSR_MTVEC => allocator.trap_handler_register(),      // mtvec → vr33
            CSR_MSCRATCH => allocator.mscratch_register(),       // mscratch → vr34
            CSR_MEPC => allocator.mepc_register(),               // mepc → vr35
            CSR_MCAUSE => allocator.mcause_register(),           // mcause → vr36
            CSR_MTVAL => allocator.mtval_register(),             // mtval → vr37
            _ => panic!(
                "CSRRW: Unsupported CSR 0x{:03x}",
                csr_addr
            ),
        };

        let mut asm = InstrAssembler::new(self.address, self.is_compressed, xlen, allocator);

        if self.operands.rd == 0 {
            // csrw pseudo-instruction: just write new value
            let temp_new = allocator.allocate();

            // Advice provides the rs1 write value.
            asm.emit_j::<VirtualAdvice>(*temp_new, 0);
            // Prove the advice matches rs1 (rd == 0 so rs1 is not clobbered by CSRRW).
            asm.emit_b::<VirtualAssertEQ>(*temp_new, self.operands.rs1, 0);
            // Update CSR virtual register.
            asm.emit_i::<ADDI>(virtual_reg, *temp_new, 0);
        } else {
            // Full csrrw: rd ← old_CSR, CSR ← rs1
            let temp_old = allocator.allocate();
            let temp_new = allocator.allocate();

            let rs1_proof_reg = if self.operands.rd != 0 && self.operands.rd == self.operands.rs1
            {
                allocator.csrrw_saved_rs1_register()
            } else {
                self.operands.rs1
            };

            // OLD CSR value comes from advice; prove it matches the current CSR virtual register.
            asm.emit_j::<VirtualAdvice>(*temp_old, 0);
            asm.emit_b::<VirtualAssertEQ>(*temp_old, virtual_reg, 0);

            // Write old value to rd (may clobber rs1 if rd == rs1).
            asm.emit_i::<ADDI>(self.operands.rd, *temp_old, 0);

            // NEW CSR value comes from advice; prove it matches original rs1, then update CSR VR.
            asm.emit_j::<VirtualAdvice>(*temp_new, 0);
            asm.emit_b::<VirtualAssertEQ>(*temp_new, rs1_proof_reg, 0);
            asm.emit_i::<ADDI>(virtual_reg, *temp_new, 0);
        }

        asm.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::CSRRW;
    use crate::instruction::Instruction;

    /// Test decoding of `csrw mtvec, t0` (csrrw x0, mtvec, t0)
    /// Encoding: csr=0x305, rs1=t0(5), funct3=001, rd=x0(0), opcode=1110011
    #[test]
    fn test_csrrw_mtvec_decode() {
        // csrw mtvec, t0 = csrrw x0, 0x305, t0
        // Encoding: 0x305 << 20 | 5 << 15 | 1 << 12 | 0 << 7 | 0x73
        let instr: u32 = 0x30529073;
        let address: u64 = 0x1000;

        let decoded = Instruction::decode(instr, address, false).expect("Failed to decode CSRRW");

        match decoded {
            Instruction::CSRRW(csrrw) => {
                assert_eq!(csrrw.operands.rd, 0, "rd should be x0");
                assert_eq!(csrrw.operands.rs1, 5, "rs1 should be t0 (x5)");
                assert_eq!(csrrw.csr_address(), 0x305, "CSR should be mtvec (0x305)");
            }
            _ => panic!("Expected CSRRW instruction, got {:?}", decoded),
        }
    }

    /// Test decoding with rd != 0 (full csrrw, not just csrw pseudo-instruction)
    #[test]
    fn test_csrrw_with_rd() {
        // csrrw a0, mtvec, t0 (read old mtvec to a0, write t0 to mtvec)
        // Encoding: 0x305 << 20 | 5 << 15 | 1 << 12 | 10 << 7 | 0x73
        let instr: u32 = 0x30529573; // rd=a0(10)
        let address: u64 = 0x1000;

        let decoded = Instruction::decode(instr, address, false).expect("Failed to decode CSRRW");

        match decoded {
            Instruction::CSRRW(csrrw) => {
                assert_eq!(csrrw.operands.rd, 10, "rd should be a0 (x10)");
                assert_eq!(csrrw.operands.rs1, 5, "rs1 should be t0 (x5)");
                assert_eq!(csrrw.csr_address(), 0x305, "CSR should be mtvec (0x305)");
            }
            _ => panic!("Expected CSRRW instruction, got {:?}", decoded),
        }
    }
}
