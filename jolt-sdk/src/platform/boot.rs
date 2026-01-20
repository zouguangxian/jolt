extern "C" {
    static __heap_start: u8;
    static __heap_end: u8;
    static __stack_top: u8;
    static __stack_bottom: u8;
}

#[inline(always)]
#[cfg(feature = "os-linux")]
fn install_trap_vector() {
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    unsafe {
        core::arch::asm!("la t0, _trap_handler", "csrw mtvec, t0", options(nostack));
    }
}

/// Platform initialization hook called by `zeroos-arch-riscv::__bootstrap`.
#[no_mangle]
pub extern "C" fn __platform_bootstrap() {
    // Initialize ZeroOS global kernel ops table for this build.
    zeroos::initialize();

    #[cfg(feature = "memory")]
    {
        let heap_start = core::ptr::addr_of!(__heap_start) as usize;
        let heap_end = core::ptr::addr_of!(__heap_end) as usize;
        let heap_size = heap_end.saturating_sub(heap_start);
        zeroos::foundation::kfn::memory::kinit(heap_start, heap_size);
        // Stack boundaries are defined by the linker script; kept available for debugging.
        let _stack_top = core::ptr::addr_of!(__stack_top) as usize;
        let _stack_bottom = core::ptr::addr_of!(__stack_bottom) as usize;
    }

    cfg_if::cfg_if! {
        if #[cfg(not(target_os = "none"))] {
            #[cfg(feature = "os-linux")]
            {
                install_trap_vector();
            }

            // Thread anchor policy (mirrors spike-platform):
            // - In kernel: keep tp=anchor and mscratch=0.
            // - Before entering libc (musl): park anchor in mscratch and clear tp (TLS owns tp).
            #[cfg(feature = "thread")]
            let boot_thread_anchor: usize = {
                let anchor = zeroos::foundation::kfn::scheduler::kinit();

                #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
                unsafe {
                    core::arch::asm!("mv tp, {0}", in(reg) anchor, options(nostack));
                    core::arch::asm!("csrw mscratch, x0", options(nostack));
                }

                anchor
            };

            #[cfg(feature = "vfs")]
            {
                zeroos::foundation::kfn::vfs::kinit();

                #[cfg(feature = "vfs-device-console")]
                {
                    crate::platform::lib::register_console_fd(1, crate::platform::lib::stdout_fops());
                    crate::platform::lib::register_console_fd(2, crate::platform::lib::stderr_fops());
                }
            }

            #[cfg(feature = "random")]
            {
                // SECURITY: fixed seed for deterministic zk proofs.
                zeroos::foundation::kfn::random::kinit(0);
            }

            #[cfg(all(feature = "thread", feature = "os-linux"))]
            {
                #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
                unsafe {
                    core::arch::asm!("csrw mscratch, {0}", in(reg) boot_thread_anchor, options(nostack));
                    // NOTE: On real Linux, the kernel initializes `tp` for TLS before entering user
                    // code. In our Jolt/unikernel environment, leaving `tp` as zero causes TLS
                    // accesses to target address 0, which the emulator rejects. Keep `tp` as the
                    // thread anchor so TLS-relative accesses land in mapped memory.
                }
            }
        }
    }
}

