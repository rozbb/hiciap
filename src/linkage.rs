use crate::{
    hiciap::{hiciap_verify, HiciapProof, HiddenInputOpening, VerifierCtx},
    hl::{prove_hl, verify_hl, HlProof},
    util::get_pedersen_generators,
    HiciapError,
};

use std::io::{Read, Write};

use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::rand::{CryptoRng, RngCore};
use merlin::Transcript;

/// A proof that a set of HiCIAP proofs are linked
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct LinkageProof<P: PairingEngine>(HlProof<P::G1Projective>);

/// Computes a proof that all the given HiCIAP proofs share the same hidden input. Note:
/// verification of the proof is sensitive to the order of the inputs.
///
/// Panics
/// ======
/// Panics if the given HiCIAP proofs don't share the same hidden input
pub fn hiciap_link<P, R>(
    rng: &mut R,
    proof_data: &[&(HiciapProof<P>, HiddenInputOpening<P>)],
) -> LinkageProof<P>
where
    P: PairingEngine,
    R: CryptoRng + RngCore,
{
    // Baseline checks: Make sure we have at least 1 proof, and make sure that every proof uses the
    // same common input
    assert!(proof_data.len() != 0);

    let hidden_input = proof_data.first().unwrap().1.hidden_input;
    for opening in proof_data.iter().map(|t| &t.1) {
        assert_eq!(hidden_input, opening.hidden_input);
    }

    // Now run hl_prove to link these HiCIAP proofs together

    // Get 3 generators. These are the same 3 Pedersen bases used in HiCIAP
    let gens = get_pedersen_generators(3);

    // Collect all the pieces of the HL proof
    let coms: Vec<P::G1Projective> = proof_data.iter().map(|t| t.0.com_a0).collect();
    let z1s: Vec<P::Fr> = proof_data.iter().map(|t| t.1.z1).collect();
    let z3s: Vec<P::Fr> = proof_data.iter().map(|t| t.1.z3).collect();

    let mut transcript = Transcript::new(b"HiCIAP link");
    let hl_proof = prove_hl(
        rng,
        &mut transcript,
        &coms,
        &gens[0],
        &gens[1],
        &gens[2],
        &hidden_input,
        &z1s,
        &z3s,
    );

    LinkageProof(hl_proof)
}

/// Verifies that the given HiCIAP proofs are valid and share a common input. `ads` contains the
/// associated data of each proof.
pub fn hiciap_verify_linked<P: PairingEngine>(
    ctxs: &mut [VerifierCtx<P>],
    hiciap_proofs: &[HiciapProof<P>],
    linkage_proof: &LinkageProof<P>,
) -> Result<bool, HiciapError> {
    assert_eq!(
        ctxs.len(),
        hiciap_proofs.len(),
        "# verif contexts must be equal to # proofs"
    );

    // Check the HL proof first.
    // Get the hidden wire commitments and 3 generators. These are the same 3 Pedersen bases used
    // in HiCIAP.
    let coms: Vec<P::G1Projective> = hiciap_proofs.iter().map(|t| t.com_a0).collect();
    let gens = get_pedersen_generators(3);

    let mut transcript = Transcript::new(b"HiCIAP link");
    if !verify_hl(
        &mut transcript,
        &linkage_proof.0,
        &coms,
        &gens[0],
        &gens[1],
        &gens[2],
    ) {
        return Err(HiciapError::VerificationFailed);
    }

    // Now check the HiCIAP proofs
    for (ctx, proof) in ctxs.iter_mut().zip(hiciap_proofs.iter()) {
        // Check the proof
        if !hiciap_verify(ctx, proof)? {
            return Err(HiciapError::VerificationFailed);
        }
    }

    Ok(true)
}
