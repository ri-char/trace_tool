use std::{
    collections::{HashMap, HashSet},
    ffi::CString,
    io::Read,
    process::exit,
    sync::RwLock,
};

use anyhow::Result;
use clap::__macro_refs::once_cell::sync::OnceCell;
use nix::{
    libc::{close, open},
    sys::{
        ptrace::{self, AddressType},
        signal::{sigaction, SaFlags, SigAction, SigHandler, Signal},
        signalfd::SigSet,
        wait::{wait, WaitStatus},
    },
    unistd::{alarm, execv, fork, ForkResult, Pid},
};
use redis::Commands;
use serde_json::json;

use crate::{
    error::{MutexError, PtraceError},
    RunArgs,
};

#[derive(serde::Deserialize, serde::Serialize, Clone, Copy)]
enum ExitState {
    Ok,
    Crash,
    Timeout,
}

static RECORD_MAP: OnceCell<RwLock<HashMap<String, HashSet<usize>>>> = OnceCell::new();
static EXIT_STATE: RwLock<ExitState> = RwLock::new(ExitState::Ok);

pub fn cmd_run(args: RunArgs) -> Result<()> {
    let mut cstr_args: Vec<CString> = Vec::new();
    for arg in args.cmd {
        cstr_args.push(CString::new(arg)?)
    }
    RECORD_MAP.get_or_init(|| RwLock::new(HashMap::new()));

    let sa = SigAction::new(
        SigHandler::Handler(signal_handler),
        SaFlags::SA_RESTART,
        SigSet::empty(),
    );

    unsafe {
        sigaction(Signal::SIGALRM, &sa)?;
        sigaction(Signal::SIGTERM, &sa)?;
    }

    alarm::set(600);

    match unsafe { fork() }? {
        ForkResult::Parent { child } => {
            let exit_code = debug(child, args.db.as_str())?;
            output_exit(exit_code);
        }
        ForkResult::Child => {
            let null = CString::new("/dev/null").unwrap();
            unsafe {
                close(0);
                close(1);
                close(2);
                open(null.as_ptr(), 2, 0);
                open(null.as_ptr(), 0, 0);
                open(null.as_ptr(), 0, 0);
            }
            ptrace::traceme()?;
            execv(cstr_args[0].as_c_str(), cstr_args.as_slice())?;
            Ok(())
        }
    }
}

const ERROR_ADDR: [(&str, usize); 2] = [
    // KCrashHandler::TerminateHandler
    ("libkso.so", 0x03519150),
    // KCrashHandler::UnexpectedHandler
    ("libkso.so", 0x03519180),
];

const NORMAL_ADDR: [(&str, usize); 2] = [
    // KApplication::exec
    ("libetmain.so", 0x26b1266),
    // KxApplication::messageBox
    ("libkso.so", 0x2891c40),
];

extern "C" fn signal_handler(_: nix::libc::c_int) {
    *EXIT_STATE.write().unwrap() = ExitState::Timeout;
    output_exit(0xff);
}

fn output_exit(code: i32) -> ! {
    let eexit_state = *EXIT_STATE.read().unwrap();
    let rrecord_map = &*RECORD_MAP.get().unwrap().read().unwrap();
    serde_json::to_writer(
        std::io::stdout(),
        &json!({
            "state": eexit_state,
            "map": rrecord_map,
        }),
    )
    .unwrap();
    exit(code);
}

fn debug(child: Pid, db: &str) -> Result<i32> {
    let client = redis::Client::open(db)?;
    let mut conn = client.get_connection()?;

    let mut exit_code = 0i32;
    let mut active_pid: HashSet<Pid> = HashSet::new();
    active_pid.insert(child);

    let wait_status = wait()?;
    if let WaitStatus::Stopped(_, Signal::SIGTRAP) = wait_status {
    } else {
        log::error!("Ptrace error");
        return Err(PtraceError {}.into());
    }
    ptrace::setoptions(
        child,
        ptrace::Options::PTRACE_O_TRACECLONE
            | ptrace::Options::PTRACE_O_TRACEEXEC
            | ptrace::Options::PTRACE_O_TRACEFORK
            | ptrace::Options::PTRACE_O_TRACEVFORK,
    )?;
    ptrace::cont(child, None)?;

    loop {
        let wait_status = wait()?;
        match wait_status {
            WaitStatus::Exited(pid, code) => {
                log::debug!("[{pid}] Exited with {code}");
                active_pid.remove(&pid);
                if pid == child {
                    exit_code = code;
                }
                if active_pid.is_empty() {
                    break;
                }
            }
            WaitStatus::Signaled(pid, sig, _) => {
                log::debug!("[{pid}] Exited with {sig}");
                active_pid.remove(&pid);
                if pid == child {
                    exit_code = 0xff;
                }
                if active_pid.is_empty() {
                    break;
                }
            }
            WaitStatus::Stopped(pid, Signal::SIGTRAP) => {
                let mut fix = false;
                let mut reg = ptrace::getregs(pid)?;
                reg.rip -= 1;
                if let Some((module, offset)) = get_module_and_offset(pid, reg.rip)? {
                    if let Some(initial_byte) = get_initial_byte(&module, offset, &mut conn)? {
                        let aligned_ip = reg.rip & !7u64;
                        let mut code_bytes: [u8; 8] =
                            ptrace::read(pid, aligned_ip as AddressType)?.to_ne_bytes();
                        code_bytes[(reg.rip - aligned_ip) as usize] = initial_byte;
                        let new_bytes = u64::from_ne_bytes(code_bytes);
                        log::trace!("[{pid}] patch bytes {initial_byte:02x} {module}@{offset:x}");

                        unsafe {
                            ptrace::write(
                                pid,
                                aligned_ip as AddressType,
                                new_bytes as *mut std::ffi::c_void,
                            )
                        }?;
                        ptrace::setregs(pid, reg)?;
                        let mut rrecord_map = RECORD_MAP
                            .get()
                            .ok_or(MutexError {})?
                            .write()
                            .map_err(|_| MutexError {})?;

                        if let Some(trigger_set) = (*rrecord_map).get_mut(&module) {
                            trigger_set.insert(offset);
                        } else {
                            let mut trigger_set = HashSet::new();
                            trigger_set.insert(offset);
                            rrecord_map.insert(module.clone(), trigger_set);
                        }
                        fix = true;
                    }
                    for (target_module, target_addr) in ERROR_ADDR {
                        if module.ends_with(target_module) && offset == target_addr {
                            log::debug!("[{pid}] crash at {module}@{offset:x}");
                            let mut eexit_state = EXIT_STATE.write().map_err(|_| MutexError {})?;
                            *eexit_state = ExitState::Crash;
                            let _ = ptrace::kill(pid);
                            return Ok(exit_code);
                        }
                    }
                    for (target_module, target_addr) in NORMAL_ADDR {
                        if module.ends_with(target_module) && offset == target_addr {
                            log::debug!("[{pid}] normal exit {module}@{offset:x}");
                            let mut eexit_state = EXIT_STATE.write().map_err(|_| MutexError {})?;
                            *eexit_state = ExitState::Ok;
                            let _ = ptrace::kill(pid);
                            return Ok(exit_code);
                        }
                    }
                    if !fix {
                        log::debug!("[{pid}] Unknow addr {module}@{offset:x}");
                    }
                }
                ptrace::cont(pid, if fix { None } else { Some(Signal::SIGTRAP) })?;
            }
            WaitStatus::Stopped(pid, Signal::SIGSTOP) => {
                log::debug!("[{pid}] Stoped by SIGSTOP");
                ptrace::cont(pid, None)?;
            }
            WaitStatus::Stopped(pid, signal) => {
                // pass other signal to process
                if signal == Signal::SIGSEGV {
                    let regs = ptrace::getregs(pid)?;
                    log::debug!("[{pid}] Stoped by {signal} rip: {:x}", regs.rip);
                    if log::log_enabled!(log::Level::Trace) {
                        let mut buf: String = String::new();
                        std::fs::OpenOptions::new()
                            .read(true)
                            .open(format!("/proc/{pid}/maps"))?
                            .read_to_string(&mut buf)?;
                        log::trace!("{buf}");
                    }
                } else {
                    log::debug!("[{pid}] Stoped by {signal}");
                }
                if let Err(nix::errno::Errno::ESRCH) = ptrace::cont(pid, Some(signal)) {
                    active_pid.remove(&pid);
                    if pid == child {
                        exit_code = 0xff;
                    }
                    if active_pid.is_empty() {
                        break;
                    }
                }
            }
            WaitStatus::PtraceEvent(pid, _, event) => match event {
                nix::libc::PTRACE_EVENT_FORK
                | nix::libc::PTRACE_EVENT_VFORK
                | nix::libc::PTRACE_EVENT_CLONE
                | nix::libc::PTRACE_EVENT_EXEC => {
                    let new_pid = ptrace::getevent(pid)? as i32;
                    log::debug!(
                        "[{pid}] PtraceEvent {} {new_pid}",
                        match event {
                            nix::libc::PTRACE_EVENT_FORK => "fork",
                            nix::libc::PTRACE_EVENT_VFORK => "vfork",
                            nix::libc::PTRACE_EVENT_CLONE => "clone",
                            nix::libc::PTRACE_EVENT_EXEC => "exec",
                            _ => unreachable!(),
                        }
                    );
                    active_pid.insert(Pid::from_raw(new_pid));
                    ptrace::cont(pid, None)?;
                }
                _ => {
                    let content = ptrace::getevent(pid)?;
                    log::debug!("[{pid}] PtraceEvent {event}({content})",);
                    ptrace::cont(pid, None)?;
                }
            },
            WaitStatus::Continued(pid) | WaitStatus::PtraceSyscall(pid) => {
                ptrace::cont(pid, None)?;
            }
            WaitStatus::StillAlive => {}
        }
    }
    Ok(exit_code)
}

fn get_module_and_offset(pid: Pid, addr: u64) -> Result<Option<(String, usize)>> {
    let maps = procmaps::Mappings::from_pid(pid.as_raw())?;
    let map = maps
        .iter()
        .find(|map| addr as usize >= map.base && map.ceiling > addr as usize);
    if let Some(map) = map {
        if let procmaps::Path::MappedFile(file) = &map.pathname {
            let offset = (addr as usize) - maps.iter().find(|a| a.inode == map.inode).unwrap().base;
            return Ok(Some((file.clone(), offset)));
        }
    }
    Ok(None)
}

fn get_initial_byte(
    module: &String,
    offset: usize,
    conn: &mut redis::Connection,
) -> Result<Option<u8>> {
    Ok(conn.hget(module, offset)?)
}
