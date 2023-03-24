use std::{
    collections::{HashMap, HashSet},
    ffi::CString,
    path::PathBuf, process::exit,
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

use crate::{RunArgs, patch::PatchDB};

pub fn cmd_run(args: RunArgs) -> Result<()> {
    let initial_byte_map: PatchDB = crate::patch::read_patch_db(&args.db)?;
    let mut cstr_args: Vec<CString> = Vec::new();
    for arg in args.cmd {
        cstr_args.push(CString::new(arg)?)
    }

    match unsafe { fork() }? {
        ForkResult::Parent { child } => {
            let exit_code=debug(child, &initial_byte_map, args.output)?;
            exit(exit_code);
        },
        ForkResult::Child => {
            ptrace::traceme()?;
            execv(cstr_args[0].as_c_str(), cstr_args.as_slice())?;
            Ok(())
        }
    }
}

fn debug(
    child: Pid,
    initial_byte_map: &PatchDB,
    output_path: Option<PathBuf>,
) -> Result<i32> {
    let mut record_map: HashMap<String, HashSet<usize>> = HashMap::new();
    let mut first_event = true;
    let mut exit_code=0i32;
    let mut active_pid: HashSet<Pid> = HashSet::new();
    active_pid.insert(child);
    loop {
        let wait_status = wait()?;
        if first_event {
            ptrace::setoptions(
                child,
                ptrace::Options::PTRACE_O_TRACECLONE
                    | ptrace::Options::PTRACE_O_TRACEEXEC
                    | ptrace::Options::PTRACE_O_TRACEFORK
                    | ptrace::Options::PTRACE_O_TRACEVFORK,
            )?;
            first_event = false;
        }
        match wait_status {
            WaitStatus::Exited(pid, code) => {
                active_pid.remove(&pid);
                if pid==child {
                    exit_code=code;
                }
                if active_pid.len() == 0 {
                    break;
                }
            }
            WaitStatus::Signaled(pid, _, _) => {
                active_pid.remove(&pid);
                if pid==child {
                    exit_code=0xff;
                }
                if active_pid.len() == 0 {
                    break;
                }
            }
            WaitStatus::Stopped(pid, Signal::SIGTRAP) => {
                let mut reg = ptrace::getregs(pid)?;
                reg.rip -= 1;
                if let Some((module, offset)) = get_module_and_offset(pid, reg.rip)? {
                    if let Some(initial_byte) = get_initial_byte(&module, offset, initial_byte_map)
                    {
                        let aligned_ip = reg.rip & !7u64;
                        let mut code_bytes: [u8; 8] =
                            ptrace::read(pid, aligned_ip as AddressType)?.to_ne_bytes();
                        code_bytes[(reg.rip - aligned_ip) as usize] = initial_byte;
                        let new_bytes = u64::from_ne_bytes(code_bytes);
                        unsafe {
                            ptrace::write(
                                pid,
                                aligned_ip as AddressType,
                                new_bytes as *mut std::ffi::c_void,
                            )
                        }?;
                        ptrace::setregs(pid, reg)?;
                    }
                    if let Some(trigger_set) = record_map.get_mut(&module) {
                        trigger_set.insert(offset);
                    } else {
                        let mut trigger_set = HashSet::new();
                        trigger_set.insert(offset);
                        record_map.insert(module.clone(), trigger_set);
                    }
                }
                ptrace::cont(pid, None)?;
            }
            WaitStatus::Stopped(pid, Signal::SIGSTOP) => {
                ptrace::cont(pid, None)?;
            }
            WaitStatus::Stopped(pid, signal) => {
                // pass other signal to process
                ptrace::cont(pid, Some(signal))?;
            }
            WaitStatus::PtraceEvent(pid, _, event) => {
                match event {
                    nix::libc::PTRACE_EVENT_FORK
                    | nix::libc::PTRACE_EVENT_VFORK
                    | nix::libc::PTRACE_EVENT_CLONE => {
                        active_pid.insert(Pid::from_raw(ptrace::getevent(pid)? as i32));
                        ptrace::cont(pid, None)?;
                    }
                    // nix::libc::PTRACE_EVENT_EXEC => {
                    //     // Not trace exec
                    //     let cpid = Pid::from_raw(ptrace::getevent(pid)? as i32);
                    //     ptrace::detach(cpid, None)?;
                    //     active_pid.remove(&cpid);
                    // }
                    _ => {
                        ptrace::cont(pid, None)?;
                    }
                }
            }
            WaitStatus::Continued(pid) | WaitStatus::PtraceSyscall(pid) => {
                ptrace::cont(pid, None)?;
            }
            WaitStatus::StillAlive => {}
        }
    }
    print_coverage(initial_byte_map, &record_map);

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
    initial_byte_map: &HashMap<String, HashMap<usize, u8>>,
    record_map: &HashMap<String, HashSet<usize>>,
) {
    for (module, bbs) in initial_byte_map {
        let total_bb = bbs.len();
        let trigger_bb = record_map.get(module).map_or(0, |s| s.len());
        eprintln!(
            "{}\t{}/{}\t{:.2}%",
            module,
            trigger_bb,
            total_bb,
            (trigger_bb as f32) / (total_bb as f32) * 100f32
        )
    }
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
    initial_byte_map: &PatchDB,
) -> Option<u8> {
    return initial_byte_map
        .get(module)
        .and_then(|byte_map| byte_map.get(&offset))
        .map(|n| *n);
}
