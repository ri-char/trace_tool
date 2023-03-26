use std::{
    collections::{HashMap, HashSet},
    ffi::CString,
    io::Read,
    path::PathBuf,
    process::exit,
};

use anyhow::Result;
use nix::{
    sys::{
        ptrace::{self, AddressType},
        signal::Signal,
        wait::{wait, WaitStatus},
    },
    unistd::{execv, fork, ForkResult, Pid},
};
use redis::Commands;

use crate::{error::PtraceError, RunArgs};

pub fn cmd_run(args: RunArgs) -> Result<()> {
    let mut cstr_args: Vec<CString> = Vec::new();
    for arg in args.cmd {
        cstr_args.push(CString::new(arg)?)
    }

    match unsafe { fork() }? {
        ForkResult::Parent { child } => {
            let exit_code = debug(child, args.output, args.db)?;
            exit(exit_code);
        }
        ForkResult::Child => {
            ptrace::traceme()?;
            execv(cstr_args[0].as_c_str(), cstr_args.as_slice())?;
            Ok(())
        }
    }
}

fn debug(child: Pid, output_path: Option<PathBuf>, db: String) -> Result<i32> {
    let client = redis::Client::open(db)?;
    let mut conn = client.get_connection()?;

    let mut record_map: HashMap<String, HashSet<usize>> = HashMap::new();
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
                        if code_bytes[(reg.rip - aligned_ip) as usize] == 0xcc {
                            code_bytes[(reg.rip - aligned_ip) as usize] = initial_byte;
                            let new_bytes = u64::from_ne_bytes(code_bytes);
                            log::trace!("[{pid}] new bytes {initial_byte:02x} {:x}", offset);

                            unsafe {
                                ptrace::write(
                                    pid,
                                    aligned_ip as AddressType,
                                    new_bytes as *mut std::ffi::c_void,
                                )
                            }?;
                            ptrace::setregs(pid, reg)?;
                            if let Some(trigger_set) = record_map.get_mut(&module) {
                                trigger_set.insert(offset);
                            } else {
                                let mut trigger_set = HashSet::new();
                                trigger_set.insert(offset);
                                record_map.insert(module.clone(), trigger_set);
                            }
                            fix = true;
                        }
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
                    let mut buf: String = String::new();
                    std::fs::OpenOptions::new()
                        .read(true)
                        .open(format!("/proc/{pid}/maps"))?
                        .read_to_string(&mut buf)?;
                    log::trace!("{buf}");
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
    print_coverage(&record_map, &mut conn)?;

    if let Some(output) = output_path {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(output)?;
        serde_json::to_writer(file, &record_map)?;
    }
    Ok(exit_code)
}

fn print_coverage(
    record_map: &HashMap<String, HashSet<usize>>,
    conn: &mut redis::Connection,
) -> Result<()> {
    for (module, bbs) in record_map {
        let total_bb = conn.hvals::<_, Vec<String>>(module)?.len();
        let trigger_bb = bbs.len();
        log::info!(
            "{}\t{}/{}\t{:.2}%",
            module,
            trigger_bb,
            total_bb,
            (trigger_bb as f32) / (total_bb as f32) * 100f32
        );
    }
    Ok(())
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
