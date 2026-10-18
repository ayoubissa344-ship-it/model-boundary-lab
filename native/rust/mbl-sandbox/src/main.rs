use std::{
    env, io,
    os::unix::process::CommandExt,
    process::{Command, ExitCode},
};

use std::ffi::c_void;
use std::os::raw::{c_int, c_long, c_ulong};

const PR_SET_NO_NEW_PRIVS: c_int = 38;
const PR_SET_SECCOMP: c_int = 22;
const SECCOMP_MODE_FILTER: c_ulong = 2;

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;

const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_KILL_THREAD: u32 = 0;
const EPERM: u32 = 1;

#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;
#[cfg(target_arch = "aarch64")]
const SYS_GETPPID: c_long = 173;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "x86_64")]
const SYS_GETPPID: c_long = 110;

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("The seccomp probe supports only aarch64 and x86_64.");

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

unsafe extern "C" {
    fn prctl(
        option: c_int,
        arg2: c_ulong,
        arg3: *mut c_void,
        arg4: c_ulong,
        arg5: c_ulong,
    ) -> c_int;

    fn syscall(number: c_long, ...) -> c_long;
}

fn probe_filter() -> [SockFilter; 7] {
    [
        SockFilter {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: 4,
        },
        SockFilter {
            code: BPF_JMP_JEQ_K,
            jt: 1,
            jf: 0,
            k: AUDIT_ARCH,
        },
        SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL_THREAD,
        },
        SockFilter {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        },
        SockFilter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: SYS_GETPPID as u32,
        },
        SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | EPERM,
        },
        SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
    ]
}

fn install_probe_filter() -> io::Result<()> {
    let nnp = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, std::ptr::null_mut(), 0, 0) };

    if nnp != 0 {
        return Err(io::Error::last_os_error());
    }

    let filter = probe_filter();
    let program = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    let result = unsafe {
        prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &program as *const SockFprog as *mut c_void,
            0,
            0,
        )
    };

    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn probe_child() -> ExitCode {
    let result = unsafe { syscall(SYS_GETPPID) };

    if result == -1 {
        let error = io::Error::last_os_error().raw_os_error();

        if error == Some(EPERM as i32) {
            println!("RESULT=SECCOMP_BLOCK_CONFIRMED");
            return ExitCode::SUCCESS;
        }

        eprintln!("FAIL: syscall returned errno={error:?}, expected EPERM");
        return ExitCode::from(1);
    }

    eprintln!("FAIL: getppid was not blocked; result={result}");
    ExitCode::from(1)
}

fn self_test() -> ExitCode {
    let executable = match env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("Cannot locate executable: {error}");
            return ExitCode::from(70);
        }
    };

    let mut command = Command::new(executable);
    command.arg("--internal-probe-child");

    unsafe {
        command.pre_exec(install_probe_filter);
    }

    match command.status() {
        Ok(status) if status.success() => {
            println!("RESULT=RUST_SECCOMP_SELF_TEST_PASS");
            println!("SCOPE=NO_NEW_PRIVS_AND_GETPPID_DENIAL_ONLY");
            ExitCode::SUCCESS
        }
        Ok(status) => {
            eprintln!("FAIL: child exited with {status}");
            ExitCode::from(1)
        }
        Err(error) => {
            eprintln!("FAIL: child launch or filter installation failed: {error}");
            ExitCode::from(70)
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.as_slice() == ["--internal-probe-child"] {
        return probe_child();
    }

    if args.as_slice() == ["--self-test"] {
        return self_test();
    }

    eprintln!("Usage: mbl-sandbox --self-test");
    eprintln!("This build is a seccomp probe, NOT a complete sandbox.");
    eprintln!("It does not isolate filesystem access or network access.");
    ExitCode::from(64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_checks_architecture_before_syscall_number() {
        let filter = probe_filter();

        assert_eq!(filter.len(), 7);
        assert_eq!(filter[0].k, 4);
        assert_eq!(filter[1].k, AUDIT_ARCH);
        assert_eq!(filter[3].k, 0);
        assert_eq!(filter[4].k, SYS_GETPPID as u32);
    }

    #[test]
    fn filter_denies_target_and_allows_other_syscalls() {
        let filter = probe_filter();

        assert_eq!(filter[5].k, SECCOMP_RET_ERRNO | EPERM);
        assert_eq!(filter[6].k, SECCOMP_RET_ALLOW);
    }
}
