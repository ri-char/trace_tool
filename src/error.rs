pub struct R2Error {}

impl std::fmt::Display for R2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("parse r2 response error")
    }
}

impl std::fmt::Debug for R2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("R2Error").finish()
    }
}

impl std::error::Error for R2Error {}

pub struct PtraceError {}

impl std::fmt::Display for PtraceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ptrace swpan error")
    }
}

impl std::fmt::Debug for PtraceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtraceError").finish()
    }
}

impl std::error::Error for PtraceError {}

pub struct MutexError {}

impl std::fmt::Display for MutexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("mutex error")
    }
}

impl std::fmt::Debug for MutexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MutexError").finish()
    }
}

impl std::error::Error for MutexError {}
