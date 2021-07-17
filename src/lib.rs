use std::fmt;

pub use ark_std::rand;

pub mod hiciap;
pub mod hl;
mod hww;
mod util;

/// An error type for anything that can go wrong when computing or verifying a HiCIAP proof
pub enum HiciapError {
    VerificationFailed,
    InvalidInput,
    ArkError(Box<dyn std::error::Error>),
}

// Arkworks errors are just dyn ErrorTrait
impl From<Box<dyn ark_std::error::Error>> for HiciapError {
    fn from(err: Box<dyn ark_std::error::Error>) -> HiciapError {
        HiciapError::ArkError(err)
    }
}

impl fmt::Display for HiciapError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HiciapError::VerificationFailed => write!(f, "HiCIAP verification failed"),
            HiciapError::InvalidInput => unimplemented!(),
            HiciapError::ArkError(e) => write!(f, "Error in arkworks: {}", e),
        }
    }
}

impl fmt::Debug for HiciapError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        <HiciapError as fmt::Display>::fmt(self, f)
    }
}
