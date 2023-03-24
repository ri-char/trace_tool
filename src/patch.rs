use std::{collections::HashMap, path::PathBuf};

use crate::{error::R2Error, PatchArgs};
use anyhow::Result;

pub type PatchDB = HashMap<String, HashMap<usize, u8>>;

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
    let mut patch_byte: HashMap<usize, u8> = HashMap::new();

    let mut r2 = r2pipe::R2Pipe::spawn(
        &args.elf,
        Some(r2pipe::R2PipeSpawnOptions {
            exepath: args.r2,
            args: vec!["-w"],
        }),
    )?;
    r2.cmd("aa")?;
    let funcs=json_get!(r2.cmdj("aflj")?, Array);
    for fun in funcs {
        if json_get_some!(fun.get("size"), Number).as_i64() == Some(0) {
            continue;
        }
        let offset = json_get_some!(fun.get("offset"), Number);
        r2.cmd(format!("s {}", offset).as_str())?;
        for raw_bbs in json_get!(r2.cmdj("agfj")?, Array){
            for bb in json_get_some!(raw_bbs.get("blocks"), Array) {
                let bb_offset = json_get_some!(bb.get("offset"), Number);
                r2.cmd(format!("s {}", bb_offset).as_str())?;
                let old_byte = u8::from_str_radix(r2.cmd("pB 1")?.as_str().trim(), 2)?;
                patch_byte.insert(bb_offset.as_u64().ok_or(R2Error {})? as usize, old_byte);
                r2.cmd("wx cc")?;
            }
        }
    }

    let full_path = std::fs::canonicalize(args.elf)?
        .to_str()
        .unwrap()
        .to_string();
    let mut db: PatchDB = read_patch_db(&args.db).unwrap_or_default();
    db.insert(full_path, patch_byte);
    write_patch_db(&args.db, &db)?;
    Ok(())
}

pub fn read_patch_db(path: &PathBuf) -> Result<PatchDB> {
    Ok(serde_json::from_reader(
        std::fs::OpenOptions::new()
            .read(true)
            .open(std::path::PathBuf::from(path))?,
    )?)
}

fn write_patch_db(path: &PathBuf, db: &PatchDB) -> Result<()> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    serde_json::to_writer(file, db)?;
    Ok(())
}
