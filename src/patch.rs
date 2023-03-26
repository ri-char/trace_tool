use std::collections::HashSet;

use crate::{error::R2Error, PatchArgs};
use anyhow::Result;
use redis::Commands;

macro_rules! json_get_some {
    ($json:expr, $jtype: tt) => {
        if let ::core::option::Option::Some(serde_json::Value::$jtype(var)) = $json {
            var
        } else {
            return Err(R2Error {}.into());
        }
    };
}

macro_rules! json_get {
    ($json:expr, $jtype: tt) => {
        if let serde_json::Value::$jtype(var) = $json {
            var
        } else {
            return Err(R2Error {}.into());
        }
    };
}

pub fn cmd_patch(args: PatchArgs) -> Result<()> {
    let client = redis::Client::open(args.db)?;
    let mut con = client.get_connection()?;

    let full_path = std::fs::canonicalize(args.elf.as_str())?
        .to_str()
        .unwrap()
        .to_string();
    con.del(full_path.as_str())?;

    std::env::set_var("R2_LOG_LEVEL", "0");
    let mut r2 = r2pipe::R2Pipe::spawn(
        args.elf.as_str(),
        Some(r2pipe::R2PipeSpawnOptions {
            exepath: args.r2,
            args: vec!["-w"],
        }),
    )?;
    r2.cmd("aa")?;
    let mut patched_bytes = HashSet::new();
    let sections = json_get!(r2.cmdj("iSj")?, Array)
        .iter()
        .find(|v| {
            v.get("name")
                .and_then(|n| n.as_str())
                .map_or(false, |s| s == ".text")
        })
        .ok_or(R2Error {})?
        .clone();
    let text_start = json_get_some!(sections.get("vaddr"), Number)
        .as_u64()
        .unwrap();
    let text_size = json_get_some!(sections.get("vsize"), Number)
        .as_u64()
        .unwrap();

    let funcs = json_get!(r2.cmdj("aflj")?, Array);
    for fun in funcs {
        if json_get_some!(fun.get("size"), Number).as_u64().unwrap() > 0x1000 {
            continue;
        }
        let offset = json_get_some!(fun.get("offset"), Number).as_u64().unwrap();

        for raw_bbs in json_get!(r2.cmdj(format!("agfj @ {offset}").as_str())?, Array) {
            for bb in json_get_some!(raw_bbs.get("blocks"), Array) {
                let bb_offset = json_get_some!(bb.get("offset"), Number).as_u64().unwrap();
                if bb_offset < text_start || bb_offset > text_start + text_size {
                    continue;
                }
                if patched_bytes.insert(bb_offset) {
                    let old_byte = u8::from_str_radix(
                        r2.cmd(format!("pB 1 @ {bb_offset}").as_str())?
                            .as_str()
                            .trim(),
                        2,
                    )?;
                    con.hset(&full_path, format!("{bb_offset}"), format!("{old_byte}"))?;
                }
            }
        }
    }
    for bb_offset in patched_bytes {
        r2.cmd(format!("wx cc @ {bb_offset}").as_str())?;
    }

    Ok(())
}
