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
