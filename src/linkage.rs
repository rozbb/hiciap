use crate::{
    hiciap::{HiciapProof, HiddenInputOpening},
    hl::{prove_hl, verify_hl, HlProof},
    util::get_pedersen_generators,
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
    proof_data: &[(&HiciapProof<P>, &HiddenInputOpening<P>)],
) -> LinkageProof<P>
where
    P: PairingEngine,
    R: CryptoRng + RngCore,
{
    // Baseline checks: Make sure we have at least 1 proof, and make sure that every proof uses the
    // same common input
    assert!(!proof_data.is_empty());

    let hidden_input = proof_data.first().unwrap().1.hidden_input;
    for opening in proof_data.iter().map(|t| &t.1) {
        assert_eq!(hidden_input, opening.hidden_input);
    }

    // Now run hl_prove to link these HiCIAP proofs together

    // Get 3 generators. These are the same 3 Pedersen bases used in HiCIAP
    let gens = {
        let v = get_pedersen_generators(3);
        [v[0], v[1], v[2]]
    };

    // Collect all the pieces of the HL proof
    let coms: Vec<P::G1Projective> = proof_data.iter().map(|t| t.0.com_a0).collect();
    let z1s: Vec<P::Fr> = proof_data.iter().map(|t| t.1.z1).collect();
    let z3s: Vec<P::Fr> = proof_data.iter().map(|t| t.1.z3).collect();

    let mut transcript = Transcript::new(b"HiCIAP link");
    let hl_proof = prove_hl(
        rng,
        &mut transcript,
        &coms,
        &gens,
        &hidden_input,
        &z1s,
        &z3s,
    );

    LinkageProof(hl_proof)
}

/// Verifies that the given HiCIAP proofs share a common input. Note: **This does not verify the
/// HiCIAP proofs themselves**. To do that, you must run `hiciap_verify` on each of the proofs
/// separately.
#[must_use]
pub fn hiciap_verify_linkage<P: PairingEngine>(
    hiciap_proofs: &[HiciapProof<P>],
    linkage_proof: &LinkageProof<P>,
) -> bool {
    // Check the HL proof first.
    // Get the hidden wire commitments and 3 generators. These are the same 3 Pedersen bases used
    // in HiCIAP.
    let coms: Vec<P::G1Projective> = hiciap_proofs.iter().map(|t| t.com_a0).collect();
    let gens = {
        let v = get_pedersen_generators(3);
        [v[0], v[1], v[2]]
    };

    let mut hl_transcript = Transcript::new(b"HiCIAP link");
    verify_hl(&mut hl_transcript, &linkage_proof.0, &coms, &gens)
}
