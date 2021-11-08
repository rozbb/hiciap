pub use ark_std::rand;
pub use merlin;

mod hiciap;
mod hl;
mod hww;
pub mod linkage;
mod util;

pub use crate::hiciap::*;

#[cfg(test)]
mod test_circuit;

/// An error type for anything that can go wrong when computing or verifying a HiCIAP proof
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("HiCIAP verification failed")]
    VerificationFailed,
    #[error("was expecting a CSM proof but did not get one")]
    NoCsmAvailable,
    #[error("error in arkworks: {0:?}")]
    ArkError(#[from] Box<dyn std::error::Error>),
}
