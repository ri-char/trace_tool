use std::fs::File;
use std::io::Read;
use std::ops::{Deref, DerefMut};
use std::{error, fmt, result};

use nix::unistd::Pid;
use nom::bytes::complete::{take, take_until};
use nom::combinator::{map_res, opt};
use nom::sequence::tuple;
use nom::IResult;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    InvalidInput,
    IoError,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::InvalidInput => write!(f, "Invalid input"),
            Error::IoError => write!(f, "IO Error"),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::InvalidInput => "Incorrect input data for memory mapping",
            Error::IoError => "I/O error",
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}

impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Error {
        Error::IoError
    }
}

impl<'a> From<Error> for nom::Err<&'a str> {
    fn from(_: Error) -> nom::Err<&'a str> {
        nom::Err::Incomplete(nom::Needed::Unknown)
    }
}

impl<T> From<nom::Err<T>> for Error {
    fn from(_: nom::Err<T>) -> Error {
        Error::InvalidInput
    }
}

/// Represents the privacy of a mapping.
#[derive(PartialEq, Debug)]
pub enum Privacy {
    /// This mapping is shared
    Shared,
    /// This mapping is private (copy on write)
    Private,
}

/// Represents the permissions of for a memory mapping.
#[derive(Debug)]
pub struct Permissions {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub privacy: Privacy,
}

impl Permissions {
    fn from_str(input: &str) -> Result<Self> {
        if input.len() != 4 {
            return Err(Error::InvalidInput);
        }
        let input = input.as_bytes();
        let readable = input[0] == b'r';
        let writable = input[1] == b'w';
        let executable = input[2] == b'x';

        let privacy = match input[3] {
            b'p' => Privacy::Private,
            b's' => Privacy::Shared,
            _e => return Err(Error::InvalidInput),
        };

        Ok(Permissions {
            readable,
            writable,
            executable,
            privacy,
        })
    }
}

/// This enum represents the pathname field of a given process.
/// Usually this is a file that backs up a given mapping.
#[derive(PartialEq, Debug)]
pub enum Path {
    /// A file backs up this mapping
    MappedFile(String),
    /// This mapping is the main thread stack
    Stack,
    /// This mapping is the virtual dynamically linked shared object
    Vdso,
    /// This mapping is the process's heap
    Heap,
    /// This mapping holds variables updated by the kernel
    Vvar,
    /// This region is the vsyscall mapping
    Vsyscall,
    /// This region does not have name
    Unkown,
}

impl From<&str> for Path {
    fn from(input: &str) -> Self {
        match input {
            "[heap]" => Path::Heap,
            "[stack]" => Path::Stack,
            "[vdso]" => Path::Vdso,
            "[vvar]" => Path::Vvar,
            "[vsyscall]" => Path::Vsyscall,
            "" => Path::Unkown,
            s => Path::MappedFile(s.to_string()),
        }
    }
}

/// Holds data for a given memory mapped region.
/// [For more information.](http://man7.org/linux/man-pages/man5/proc.5.html)
#[derive(Debug)]
pub struct Map {
    /// Base of mapped region in process
    pub base: usize,
    /// Ceiling of mapped region in process
    pub ceiling: usize,
    /// Access permissions of memory region
    pub perms: Permissions,
    /// If this mapping is backed by a file, this is the offset into the file.
    pub offset: usize,
    /// Major device number
    pub dev_major: usize,
    /// Minor device number
    pub dev_minor: usize,
    /// The inode on the above device
    pub inode: usize,
    /// If there is no pathname, this mapping was obtained via mmap(2)
    pub pathname: Path,
}

impl Map {
    fn from_str(input: &str) -> Result<Map> {
        let res = parse_map(input);

        match res {
            Ok(val) => Ok(val.1),
            Err(_e) => Err(Error::InvalidInput),
        }
    }
}

fn parse_map(input: &str) -> IResult<&str, Map> {
    map_res(
        tuple((
            map_res(take_until("-"), |b| usize::from_str_radix(b, 16)),
            take(1usize),
            map_res(take_until(" "), |b| usize::from_str_radix(b, 16)),
            take(1usize),
            map_res(take_until(" "), Permissions::from_str),
            take(1usize),
            map_res(take_until(" "), |b| usize::from_str_radix(b, 16)),
            take(1usize),
            map_res(take_until(":"), |b| usize::from_str_radix(b, 16)),
            take(1usize),
            map_res(take_until(" "), |b| usize::from_str_radix(b, 16)),
            take(1usize),
            map_res(take_until(" "), |b| usize::from_str_radix(b, 16)),
            take(1usize),
            opt(take_until("\n")),
        )),
        |(
            base,
            _,
            ceiling,
            _,
            perms,
            _,
            offset,
            _,
            dev_major,
            _,
            dev_minor,
            _,
            inode,
            _,
            pathname,
        )| {
            std::result::Result::<_, ()>::Ok(Map {
                base,
                ceiling,
                perms,
                offset,
                dev_major,
                dev_minor,
                inode,
                pathname: pathname.unwrap_or("").trim().into(),
            })
        },
    )(input)
}

/// A collection of memory mapped regions.
#[derive(Debug)]
pub struct Mappings(Vec<Map>);

impl Mappings {
    /// Returns mappings for a given pid
    pub fn from_pid(pid: Pid) -> Result<Mappings> {
        let path = format!("/proc/{}/maps", pid);
        let mut file = File::open(path)?;
        let mut input = String::new();
        file.read_to_string(&mut input)?;
        Mappings::from_str(&input)
    }

    pub fn from_str(raw: &str) -> Result<Mappings> {
        let input = String::from(raw);
        let mut res: Vec<Map> = Vec::new();
        let mut iter: Vec<&str> = input.split('\n').collect();
        iter.pop();
        for s in iter {
            let map = Map::from_str(&format!("{}\n", &s))?;
            res.push(map);
        }

        Ok(Mappings(res))
    }
}

impl Deref for Mappings {
    type Target = Vec<Map>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Mappings {
    fn deref_mut(&mut self) -> &mut Vec<Map> {
        &mut self.0
    }
}
