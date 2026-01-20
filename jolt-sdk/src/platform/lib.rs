//! Platform ABI surface for Jolt guests (analogous to spike-platform's `lib.rs`).

/// Guest-friendly exit.
///
/// - With `os-linux`: issues SYS_exit via `ecall` (handled by the guest trap path).
/// - Without `os-linux`: spins with `j .` which the emulator treats as termination.
#[no_mangle]
pub extern "C" fn platform_exit(code: i32) -> ! {
    cfg_if::cfg_if! {
        if #[cfg(feature = "os-linux")] {
            const SYS_EXIT: usize = 93;
            unsafe {
                core::arch::asm!(
                    "ecall",
                    in("a7") SYS_EXIT,
                    in("a0") code,
                    options(noreturn)
                );
            }
        } else {
            let _ = code;
            unsafe { core::arch::asm!("j .", options(noreturn)); }
        }
    }
}

#[inline(always)]
pub fn exit(code: i32) -> ! {
    platform_exit(code)
}

/// Debug crate hook (optional).
#[no_mangle]
pub unsafe extern "C" fn __debug_write(msg: *const u8, len: usize) {
    if !msg.is_null() && len > 0 {
        let slice = core::slice::from_raw_parts(msg, len);
        for &byte in slice {
            crate::platform::ecall::putchar(byte);
        }
    }
}

/// Syscall shim used by ZeroOS Linux syscall layer.
#[cfg(feature = "os-linux")]
#[no_mangle]
pub extern "C" fn jolt_syscall(
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    nr: usize,
) -> isize {
    ::zeroos::os::linux::linux_handle(a0, a1, a2, a3, a4, a5, nr)
}

// Console FD registration when VFS + console is enabled.
#[cfg(feature = "vfs-device-console")]
use zeroos::vfs::{self};

#[cfg(feature = "vfs-device-console")]
fn jolt_console_write(_file: *mut u8, buf: *const u8, count: usize) -> isize {
    unsafe {
        let slice = core::slice::from_raw_parts(buf, count);
        for &byte in slice {
            crate::platform::ecall::putchar(byte);
        }
    }
    count as isize
}

#[cfg(feature = "vfs-device-console")]
pub(crate) fn register_console_fd(fd: i32, ops: &'static vfs::FileOps) {
    let _ = vfs::register_fd(
        fd,
        vfs::FdEntry {
            ops,
            private_data: core::ptr::null_mut(),
        },
    );
}

#[cfg(feature = "vfs-device-console")]
static STDOUT_FOPS: vfs::FileOps = vfs::devices::console::stdout_fops(jolt_console_write);

#[cfg(feature = "vfs-device-console")]
static STDERR_FOPS: vfs::FileOps = vfs::devices::console::stderr_fops(jolt_console_write);

#[cfg(feature = "vfs-device-console")]
pub(crate) fn stdout_fops() -> &'static vfs::FileOps {
    &STDOUT_FOPS
}

#[cfg(feature = "vfs-device-console")]
pub(crate) fn stderr_fops() -> &'static vfs::FileOps {
    &STDERR_FOPS
}

