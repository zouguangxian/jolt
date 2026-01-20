//! ECALL (SYSTEM 0x0000_0073) — Environment call for syscalls and special operations.

use serde::{Deserialize, Serialize};

use crate::{
    declare_riscv_instr,
    emulator::cpu::{Cpu, PrivilegeMode, Trap, TrapType, Xlen},
    utils::inline_helpers::InstrAssembler,
    utils::virtual_registers::VirtualRegisterAllocator,
};

use super::{
    addi::ADDI,
    format::format_i::FormatI,
    jalr::JALR,
    lui::LUI,
    mul::MUL,
    sub::SUB,
    virtual_advice::VirtualAdvice,
    virtual_assert_eq::VirtualAssertEQ,
    Cycle, Instruction, RISCVInstruction, RISCVTrace,
};

declare_riscv_instr!(
    name   = ECALL,
    mask   = 0xffff_ffff,
    match  = 0x0000_0073,
    format = FormatI,
    ram    = ()
);

impl ECALL {
    fn exec(&self, cpu: &mut Cpu, _: &mut <ECALL as RISCVInstruction>::RAMAccess) {
        let trap_type = match cpu.privilege_mode {
            PrivilegeMode::User => TrapType::EnvironmentCallFromUMode,
            PrivilegeMode::Supervisor => TrapType::EnvironmentCallFromSMode,
            PrivilegeMode::Machine | PrivilegeMode::Reserved => TrapType::EnvironmentCallFromMMode,
        };

        cpu.raise_trap(
            Trap {
                trap_type,
                value: 0,
            },
            self.address,
        );
    }

}

impl RISCVTrace for ECALL {
    fn trace(&self, cpu: &mut Cpu, trace: Option<&mut Vec<Cycle>>) {
        // First, execute the ECALL to trigger trap handling.
        // This calls cpu.raise_trap() -> handle_trap() -> handle_syscall()
        // which sets cpu.pending_csr_result with the syscall return value.
        let mut ram_access = ();
        self.execute(cpu, &mut ram_access);

        let trap_handler_advice = cpu.x[33] as u64; // Current reg33 value

        let ecall_result = cpu.pending_csr_result.take().unwrap_or(0) as u64;

        // After trap handling, CPU's PC is either:
        // - trap handler address (if trap was taken, e.g., for Linux syscalls with ZeroOS)
        // - self.address + 4 (if trap was not taken, e.g., for Jolt-specific ECALLs)
        let target_pc = cpu.read_pc();

        // Return address for trap handler: ECALL_addr + 4 (ECALL is always 4 bytes)
        // This is passed in t1 so the trap handler can return without using mepc.
        let return_addr = self.address + 4;

        // Determine if trap was taken (target != return address)
        let trap_taken = target_pc != return_addr;
        cpu.vr_allocator.set_last_ecall_trap_taken(trap_taken);

        let mut inline_sequence = self.inline_sequence(&cpu.vr_allocator, cpu.xlen);

        // Fill in the advice values in order of appearance:
        // 1) ecall result (written to a0)
        // 2) return address (written to t1)
        // 3) target PC (jump destination)
        // 4) trap handler address (written to reg33)
        let mut advice_idx = 0;
        for instr in &mut inline_sequence {
            let Instruction::VirtualAdvice(v) = instr else {
                continue;
            };
            match advice_idx {
                0 => v.advice = ecall_result,
                1 => v.advice = return_addr,
                2 => v.advice = target_pc,
                3 => v.advice = trap_handler_advice,
                _ => {}
            }
            advice_idx += 1;
        }
        if advice_idx < 4 {
            panic!("ECALL inline sequence missing VirtualAdvice slots (saw {advice_idx})");
        }

        let mut trace = trace;
        for instr in inline_sequence {
            instr.trace(cpu, trace.as_deref_mut());
        }
    }

    /// ECALL inline sequence: use VirtualAdvice to write ecall return value to a0,
    /// return address to t1, and target PC, then verify and JALR to the target.
    ///
    /// Syscalls return their result in a0 (register 10), but ECALL's encoding has rd=0.
    /// We use VirtualAdvice to provide the ecall result as untrusted advice,
    /// which gets written to a0.
    ///
    /// The return address (ECALL_addr+4) is passed in t1 (register 6). For trap-taking
    /// ECALLs, the trap handler saves t1 and uses it to return, eliminating the need
    /// for mepc CSR operations.
    ///
    /// The target PC is provided via VirtualAdvice and then VERIFIED against proven state.
    /// We assert: (target_pc == return_addr) OR (target_pc == trap_handler)
    /// This is computed as: (target_pc - return_addr) * (target_pc - trap_handler) == 0
    /// - For non-trap ECALLs: target_pc == return_addr, so first diff is 0
    /// - For trap-taking ECALLs: target_pc == trap_handler (from register 33), so second diff is 0
    /// - If prover lies: neither diff is 0, product != 0, assertion fails
    ///
    /// The sequence ends with JALR to avoid the NextUnexpPCUpdateOtherwise constraint
    /// failing when the inline sequence is followed by NoOp padding. JALR has Jump=true,
    /// which makes the constraint guard `!(ShouldBranch || Jump)` false.
    fn inline_sequence(
        &self,
        allocator: &VirtualRegisterAllocator,
        xlen: Xlen,
    ) -> Vec<Instruction> {
        let v_trap_handler_reg = allocator.trap_handler_register();

        let ecall_result = allocator.allocate(); // temporary for ecall result
        let call_id = allocator.allocate(); // saved a0 (call_id) for special-ECALL constraint
        let return_addr = allocator.allocate(); // temporary for return address
        let next_pc = allocator.allocate(); // temporary for target PC
        let trap_handler_advice = allocator.allocate(); // advice for trap handler to write to reg33
        let trap_handler = allocator.allocate(); // copy of register 33 (after write)
        let diff1 = allocator.allocate(); // target_pc - return_addr
        let diff2 = allocator.allocate(); // target_pc - trap_handler
        let print_const = allocator.allocate();
        let cycle_const = allocator.allocate();
        let diff_print = allocator.allocate();
        let diff_cycle = allocator.allocate();
        let product = allocator.allocate();
        // Note: product reuses diff1's register after SUB is done

        let mut asm = InstrAssembler::new(self.address, self.is_compressed, xlen, allocator);

        // Get ecall result as advice and write to temp register
        asm.emit_j::<VirtualAdvice>(*ecall_result, 0);

        // Save current a0 into a temp register.
        // This is meaningful only for non-trap ECALLs (Jolt special ECALLs), because trap-taking
        // ECALLs may overwrite a0 during trap handling. We gate the constraint so it only matters
        // when the trap is NOT taken.
        asm.emit_i::<ADDI>(*call_id, 10, 0);

        // Move result to a0 (register 10)
        asm.emit_i::<ADDI>(10, *ecall_result, 0);

        // Get return address (ECALL_addr+4) as advice and write to temp register
        asm.emit_j::<VirtualAdvice>(*return_addr, 0);

        // Move return address to t1 (register 6) for trap handler to use
        asm.emit_i::<ADDI>(6, *return_addr, 0);

        // Get target PC as advice
        asm.emit_j::<VirtualAdvice>(*next_pc, 0);

        // Get trap handler address as advice
        // - For CSR ECALL: this is a3 (the trap handler address being set)
        // - For regular ECALL: this is current reg33 value (preserves it)
        asm.emit_j::<VirtualAdvice>(*trap_handler_advice, 0);

        // Write trap handler advice to register 33
        // This sets reg33 for CSR ECALL, or preserves it for regular ECALL
        asm.emit_i::<ADDI>(v_trap_handler_reg, *trap_handler_advice, 0);

        // Read trap handler from register 33
        asm.emit_i::<ADDI>(*trap_handler, v_trap_handler_reg, 0);

        // Verify: (target_pc == return_addr) OR (target_pc == trap_handler)
        // Compute: (target_pc - return_addr) * (target_pc - trap_handler) == 0
        // diff1 = target_pc - return_addr
        asm.emit_r::<SUB>(*diff1, *next_pc, *return_addr);
        // diff2 = target_pc - trap_handler
        asm.emit_r::<SUB>(*diff2, *next_pc, *trap_handler);
        // product = diff1 * diff2 (reuse diff1 register)
        asm.emit_r::<MUL>(*diff1, *diff1, *diff2);
        // Assert product == 0
        asm.emit_b::<VirtualAssertEQ>(*diff1, 0, 0);

        // Additional soundness constraint for emulator-intercepted Jolt ECALLs:
        // - If the trap is NOT taken (target_pc == return_addr), then call_id (a0) must be one of:
        //     JOLT_PRINT_ECALL_NUM or JOLT_CYCLE_TRACK_ECALL_NUM.
        // - If the trap IS taken (target_pc == trap_handler), this constraint is gated off.
        //
        // We gate with diff2 = target_pc - trap_handler:
        // - trap taken => diff2 == 0 => product == 0 regardless of call_id
        // - no trap    => diff2 != 0 => require (call_id == PRINT) OR (call_id == CYCLE)
        //
        // Enforced as: diff2 * (call_id - PRINT) * (call_id - CYCLE) == 0
        //
        // Load PRINT constant into a register: 0x505249 = 0x505000 + 0x249
        asm.emit_u::<LUI>(*print_const, 0x505000);
        asm.emit_i::<ADDI>(*print_const, *print_const, 0x249);
        // Load CYCLE constant into a register: 0x0C7C1E = 0x0C8000 - 0x3E2
        asm.emit_u::<LUI>(*cycle_const, 0x0C8000);
        asm.emit_i::<ADDI>(*cycle_const, *cycle_const, (-0x3E2i64) as u64);

        // diff_print = call_id - PRINT
        asm.emit_r::<SUB>(*diff_print, *call_id, *print_const);
        // diff_cycle = call_id - CYCLE
        asm.emit_r::<SUB>(*diff_cycle, *call_id, *cycle_const);
        // product = diff2 * diff_print
        asm.emit_r::<MUL>(*product, *diff2, *diff_print);
        // product = product * diff_cycle
        asm.emit_r::<MUL>(*product, *product, *diff_cycle);
        // Assert product == 0
        asm.emit_b::<VirtualAssertEQ>(*product, 0, 0);

        // Jump to target PC. JALR has Jump=true, so the NextUnexpPCUpdateOtherwise
        // constraint won't fire (guard is !(ShouldBranch || Jump) which is false).
        // Using rd=0 means we don't save the return address.
        asm.emit_i::<JALR>(0, *next_pc, 0);

        asm.finalize()
    }
}
