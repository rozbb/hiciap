use std::fmt;

pub use ark_std::rand;

pub mod hiciap;
mod hl;
mod hww;
pub mod linkage;
mod util;

pub use hiciap::*;

#[cfg(test)]
mod test_circuit;

/// An error type for anything that can go wrong when computing or verifying a HiCIAP proof
pub enum HiciapError {
    VerificationFailed,
    NoCsmAvailable,
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
            HiciapError::NoCsmAvailable => {
                write!(f, "Was expecting a CSM proof but did not get one")
            }
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
