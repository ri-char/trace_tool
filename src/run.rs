use std::{
    collections::{HashMap, HashSet},
    ffi::CString,
    io::Read,
    process::exit,
    sync::RwLock,
};

use anyhow::Result;
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
use once_cell::sync::OnceCell;
use redis::Commands;
use serde::{Deserialize, Serialize};

use crate::{procmaps, RunArgs};

#[derive(Deserialize, Serialize, Debug, Default)]
struct RunResult {
    map: HashMap<String, HashSet<usize>>,
    state: ExitState,
}

#[derive(Deserialize, Serialize, Clone, Copy, PartialEq, Debug, Default)]
enum ExitState {
    #[default]
    Ok,
    Crash,
    Timeout,
    Oom,
}

static RUN_RESULT: OnceCell<RwLock<RunResult>> = OnceCell::new();

pub fn cmd_run(args: RunArgs) -> Result<()> {
    let mut cstr_args: Vec<CString> = Vec::new();
    for arg in args.cmd {
        cstr_args.push(CString::new(arg)?)
    }
    RUN_RESULT.get_or_init(RwLock::default);

    let sa_timeout = SigAction::new(
        SigHandler::Handler(signal_handler_timeout),
        SaFlags::SA_RESTART,
        SigSet::empty(),
    );
    unsafe {
        sigaction(Signal::SIGALRM, &sa_timeout)?;
        sigaction(Signal::SIGTERM, &sa_timeout)?;
    }

    if let Some(timeout) = args.timeout {
        alarm::set(timeout);
    }

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

const ERROR_ADDR: [(&str, usize); 3] = [
    // KCrashHandler::TerminateHandler
    ("libkso.so", 0x03519150),
    // KCrashHandler::UnexpectedHandler
    ("libkso.so", 0x03519180),
    // KCrashHandler::SignalHandler
    ("libkso.so", 0x35191b0),
];

const NORMAL_ADDR: [(&str, usize); 2] = [
    // KApplication::exec
    ("libetmain.so", 0x26b1266),
    // KxApplication::messageBox
    ("libkso.so", 0x2891c40),
];

extern "C" fn signal_handler_timeout(_: nix::libc::c_int) {
    RUN_RESULT.get().unwrap().write().unwrap().state = ExitState::Timeout;
    output_exit(0xff);
}

fn output_exit(code: i32) -> ! {
    bincode::serialize_into(std::io::stdout(), RUN_RESULT.get().unwrap()).unwrap();
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
        return Err(anyhow::anyhow!("ptrace spwan error"));
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
                if sig == Signal::SIGKILL {
                    RUN_RESULT.get().unwrap().write().unwrap().state = ExitState::Oom;
                    output_exit(0xff);
                }
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
                    for (target_module, target_addr) in ERROR_ADDR {
                        if module.ends_with(target_module) && offset == target_addr {
                            log::debug!("[{pid}] crash at {module}@{offset:x}");
                            let mut eexit_state = RUN_RESULT
                                .get()
                                .unwrap()
                                .write()
                                .map_err(|_| anyhow::anyhow!("ptrace swpan error"))?;
                            eexit_state.state = ExitState::Crash;
                            let _ = ptrace::kill(pid);
                            return Ok(exit_code);
                        }
                    }
                    for (target_module, target_addr) in NORMAL_ADDR {
                        if module.ends_with(target_module) && offset == target_addr {
                            log::debug!("[{pid}] normal exit {module}@{offset:x}");
                            let mut eexit_state = RUN_RESULT
                                .get()
                                .unwrap()
                                .write()
                                .map_err(|_| anyhow::anyhow!("ptrace swpan error"))?;
                            eexit_state.state = ExitState::Ok;
                            let _ = ptrace::kill(pid);
                            return Ok(exit_code);
                        }
                    }
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
                        let mut rrecord_map = RUN_RESULT
                            .get()
                            .ok_or(anyhow::anyhow!("ptrace swpan error"))?
                            .write()
                            .map_err(|_| anyhow::anyhow!("ptrace swpan error"))?;

                        if let Some(trigger_set) = rrecord_map.map.get_mut(&module) {
                            trigger_set.insert(offset);
                        } else {
                            let mut trigger_set = HashSet::new();
                            trigger_set.insert(offset);
                            rrecord_map.map.insert(module.clone(), trigger_set);
                        }
                        fix = true;
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
    let maps = procmaps::Mappings::from_pid(pid)?;
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
