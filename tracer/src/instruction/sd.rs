use serde::{Deserialize, Serialize};

use crate::{declare_riscv_instr, emulator::cpu::Cpu};

use super::RAMWrite;

use super::{format::format_s::FormatS, RISCVInstruction, RISCVTrace};

declare_riscv_instr!(
    name   = SD,
    mask   = 0x0000707f,
    match  = 0x00003023,
    format = FormatS,
    ram    = RAMWrite
);

impl SD {
    fn exec(&self, cpu: &mut Cpu, ram_access: &mut <SD as RISCVInstruction>::RAMAccess) {
        let ea = cpu.x[self.operands.rs1 as usize].wrapping_add(self.operands.imm) as u64;
        if ea == 0 {
            eprintln!(
                "SD illegal ea=0 @ {:#x}: rs1=x{}={:#x} imm={:#x} rs2=x{}={:#x} tp(x4)={:#x}",
                self.address,
                self.operands.rs1,
                cpu.x[self.operands.rs1 as usize],
                self.operands.imm,
                self.operands.rs2,
                cpu.x[self.operands.rs2 as usize],
                cpu.x[4],
            );
        }
        // The SD, SW, SH, and SB instructions store 64-bit, 32-bit, 16-bit, and 8-bit values from
        // the low bits of register rs2 to memory respectively.
        *ram_access = cpu
            .mmu
            .store_doubleword(
                ea,
                cpu.x[self.operands.rs2 as usize] as u64,
            )
            .ok()
            .unwrap();
    }
}

impl RISCVTrace for SD {}
