//! Layer 5 runtime anti-tamper gates (Linux, `anti-tamper` feature only).
//!
//! Called in a fixed order from [`crate::harden`]: anti-debug (5.2), anti-injection
//! (5.3), self-ptrace (5.7), non-dumpable (5.1), then the decode-key init, then
//! `mseal` (5.4). The key is assembled only *after* a debugger has been refused,
//! so a live debugger cannot lift it before the gates run (round-11 lesson).
//!
//! Every failure is a **silent** exit (no output, so no oracle result reaches
//! stdout) rather than a diagnostic -- fail closed without telling the attacker
//! which gate tripped. All literal paths/env names go through `obfstr!` so they
//! do not sit in `.rodata` as a cluster pointing at the defence (Layer 2.2).

use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use obfstr::obfstr;

/// Silent fail-closed exit. `_exit` so no destructors/flushes run and nothing is
/// printed -- the absence of the stdout result is the signal to a human. The exit
/// code stays **honest** (non-zero = failure): masking it with 0 would fake
/// success and hide real crashes in CI (Layer 1.3 note), for ~0 defensive gain.
fn die() -> ! {
    unsafe { libc::_exit(1) }
}

// -- 5.2 anti-debug: refuse under a pre-existing tracer ----------------------

pub fn refuse_if_traced() {
    if let Ok(status) = std::fs::read_to_string(obfstr!("/proc/self/status")) {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix(obfstr!("TracerPid:")) {
                if rest.trim().parse::<i64>().unwrap_or(0) != 0 {
                    die();
                }
                break;
            }
        }
    }
}

// -- 5.3 anti-injection: LD_PRELOAD / LD_AUDIT / foreign executable .so -------

fn is_system_path(p: &str) -> bool {
    // Trailing slash is required: a bare "/lib" prefix would wave through
    // "/libevil.so" or "/lib_hack/x.so" as if they were system libraries.
    p.starts_with(obfstr!("/lib/"))
        || p.starts_with(obfstr!("/usr/"))
        || p.starts_with(obfstr!("/lib64/"))
}

pub fn refuse_if_injected() {
    if std::env::var_os(obfstr!("LD_PRELOAD")).is_some() {
        die();
    }
    if std::env::var_os(obfstr!("LD_AUDIT")).is_some() {
        die();
    }
    // Scan our own memory map for an executable shared object mapped from outside
    // the system library directories -- an injected .so the env check missed.
    if let Ok(maps) = std::fs::read_to_string(obfstr!("/proc/self/maps")) {
        for line in maps.lines() {
            let mut f = line.split_whitespace();
            let _range = f.next();
            let perms = f.next().unwrap_or("");
            if !perms.contains('x') {
                continue;
            }
            let path = match line.split_whitespace().nth(5) {
                Some(p) if p.starts_with('/') => p,
                _ => continue,
            };
            // Only shared objects; our own exe (no ".so") is naturally skipped.
            if !path.contains(".so") {
                continue;
            }
            if !is_system_path(path) {
                die();
            }
        }
    }
}

// -- 5.1 non-dumpable --------------------------------------------------------

pub fn set_nondumpable() {
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
        // Re-read: an LD_PRELOAD shim that no-ops the set would be caught here.
        if libc::prctl(libc::PR_GET_DUMPABLE) != 0 {
            die();
        }
    }
}

// -- 5.7 self-ptrace: sentinel child holds the tracer slot, with a watchdog ---

static SENTINEL_PID: AtomicI32 = AtomicI32::new(-1);
static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);

/// Marked before a clean exit so the watchdog does not treat the sentinel's
/// normal departure (following the parent out) as an attack.
pub fn mark_shutting_down() {
    SHUTTING_DOWN.store(true, Ordering::SeqCst);
}

pub fn self_ptrace() {
    unsafe {
        let mut go = [0i32; 2];
        let mut confirm = [0i32; 2];
        if libc::pipe(go.as_mut_ptr()) != 0 || libc::pipe(confirm.as_mut_ptr()) != 0 {
            return;
        }
        let pid = libc::fork();
        if pid < 0 {
            return;
        }
        if pid == 0 {
            // ---- sentinel (child) ----
            libc::close(go[1]);
            libc::close(confirm[0]);
            let ppid = libc::getppid();
            // Wait until the parent has authorised us as its ptracer (Yama).
            let mut b = 0u8;
            let _ = libc::read(go[0], &mut b as *mut _ as *mut libc::c_void, 1);
            let r = libc::ptrace(
                libc::PTRACE_SEIZE,
                ppid,
                core::ptr::null_mut::<libc::c_void>(),
                core::ptr::null_mut::<libc::c_void>(),
            );
            if r != 0 {
                // Slot already taken -> a debugger is attached -> take the parent down.
                libc::kill(ppid, libc::SIGKILL);
                libc::_exit(0);
            }
            let ok = 1u8;
            let _ = libc::write(confirm[1], &ok as *const _ as *const libc::c_void, 1);
            // Stay attached for the whole run, transparently continuing the tracee
            // past every signal-stop, until it exits.
            loop {
                let mut status = 0i32;
                let w = libc::waitpid(ppid, &mut status, libc::__WALL);
                if w < 0 || libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    libc::_exit(0);
                }
                if libc::WIFSTOPPED(status) {
                    let sig = libc::WSTOPSIG(status);
                    let deliver = if sig == libc::SIGTRAP || sig == libc::SIGSTOP {
                        0
                    } else {
                        sig
                    };
                    libc::ptrace(
                        libc::PTRACE_CONT,
                        ppid,
                        core::ptr::null_mut::<libc::c_void>(),
                        deliver as *mut libc::c_void,
                    );
                }
            }
        } else {
            // ---- parent ----
            libc::close(go[0]);
            libc::close(confirm[1]);
            SENTINEL_PID.store(pid, Ordering::SeqCst);
            // Authorise the sentinel to trace us even under Yama ptrace_scope=1.
            libc::prctl(libc::PR_SET_PTRACER, pid as libc::c_ulong);
            let go_byte = 1u8;
            let _ = libc::write(go[1], &go_byte as *const _ as *const libc::c_void, 1);
            // Block until seize is confirmed before any key material is touched;
            // under a debugger the sentinel kills us before this returns.
            let mut b = 0u8;
            let n = libc::read(confirm[0], &mut b as *mut _ as *mut libc::c_void, 1);
            libc::close(go[1]);
            libc::close(confirm[0]);
            if n != 1 {
                die();
            }
            // Watchdog: if the sentinel is killed mid-run to free the slot, follow it out.
            std::thread::spawn(move || {
                let sp = SENTINEL_PID.load(Ordering::SeqCst);
                loop {
                    let mut status = 0i32;
                    let w = libc::waitpid(sp, &mut status, 0);
                    if w == sp && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
                        if !SHUTTING_DOWN.load(Ordering::SeqCst) {
                            // Sentinel killed mid-run to free the tracer slot: an
                            // attack. Fail closed with an honest non-zero code.
                            libc::_exit(1);
                        }
                        return;
                    }
                    if w < 0 {
                        return;
                    }
                }
            });
        }
    }
}

// -- 5.4 mseal our own .text (last) ------------------------------------------

/// mseal every executable `PT_LOAD` segment of our own image, so its protection
/// cannot be changed at runtime (no softbreakpoint / detour in the live process).
///
/// The segments are located via the aux vector (the same phdr walk `keying` uses),
/// deliberately **not** via `std::env::current_exe()` or `/proc/self/maps`:
/// `current_exe` drags std's cleartext `"/proc/self/exe"` literal into the binary
/// (a needless string cluster), and the auxv is self-contained.
pub fn seal_text() {
    unsafe {
        let phdr = libc::getauxval(libc::AT_PHDR) as *const libc::Elf64_Phdr;
        let phnum = libc::getauxval(libc::AT_PHNUM) as usize;
        if phdr.is_null() || phnum == 0 {
            return;
        }
        // Load bias = (phdrs in memory) - (their recorded vaddr in PT_PHDR).
        let mut bias: u64 = 0;
        let mut have_bias = false;
        for i in 0..phnum {
            let p = &*phdr.add(i);
            if p.p_type == libc::PT_PHDR {
                bias = (phdr as u64).wrapping_sub(p.p_vaddr);
                have_bias = true;
                break;
            }
        }
        if !have_bias {
            return;
        }
        let page = libc::sysconf(libc::_SC_PAGESIZE) as u64;
        if page == 0 {
            return;
        }
        for i in 0..phnum {
            let p = &*phdr.add(i);
            if p.p_type == libc::PT_LOAD && (p.p_flags & libc::PF_X) != 0 {
                let start = bias.wrapping_add(p.p_vaddr) & !(page - 1);
                let end = (bias.wrapping_add(p.p_vaddr) + p.p_memsz + page - 1) & !(page - 1);
                // mseal(addr, len, flags): asm-generic syscall 462 (kernel >= 6.10).
                // Best-effort: a failure must not break a clean run.
                libc::syscall(
                    462,
                    start as libc::c_ulong,
                    (end - start) as libc::c_ulong,
                    0 as libc::c_ulong,
                );
            }
        }
    }
}
