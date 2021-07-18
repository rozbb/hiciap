use crate::{
    hiciap::{hiciap_verify, HiciapProof, HiddenInputOpening, VerifierInputs},
    hl::{prove_hl, verify_hl, HlProof},
    util::get_pedersen_generators,
    HiciapError,
};

use std::io::{Read, Write};

use ark_ec::PairingEngine;
use ark_groth16::{self, VerifyingKey as CircuitVerifyingKey};
use ark_ip_proofs::tipa::VerifierSRS;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::rand::{CryptoRng, RngCore};

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct LinkedHiciapProofs<P: PairingEngine> {
    hiciap_proofs: Vec<HiciapProof<P>>,
    hl_proof: HlProof<P::G1Projective>,
}

/// Links together several HiCIAP proofs, all of which share the same first hidden input
///
/// Panics
/// ======
/// Panics if the given HiCIAP proofs don't share the same hidden input
pub fn hiciap_link<P, R>(
    rng: &mut R,
    proof_data: &[&(HiciapProof<P>, HiddenInputOpening<P>)],
) -> LinkedHiciapProofs<P>
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

    let hl_proof = prove_hl(
        rng,
        &coms,
        &gens[0],
        &gens[1],
        &gens[2],
        &hidden_input,
        &z1s,
        &z3s,
    );

    // Now return the HiCIAP + Linkage proofs
    let hiciap_proofs: Vec<HiciapProof<P>> = proof_data.iter().map(|t| &t.0).cloned().collect();
    LinkedHiciapProofs {
        hiciap_proofs,
        hl_proof,
    }
}

pub fn hiciap_verify_linked<P: PairingEngine>(
    ip_verifier_srss: &[VerifierSRS<P>],
    circuit_vks: &[CircuitVerifyingKey<P>],
    all_verifier_inputs: &[VerifierInputs<P>],
    proofs: &LinkedHiciapProofs<P>,
) -> Result<(), HiciapError> {
    let LinkedHiciapProofs {
        hiciap_proofs,
        hl_proof,
    } = proofs;

    // Check the HL proof first.
    // Get the hidden wire commitments and 3 generators. These are the same 3 Pedersen bases used
    // in HiCIAP.
    let coms: Vec<P::G1Projective> = hiciap_proofs.iter().map(|t| t.com_a0).collect();
    let gens = get_pedersen_generators(3);
    verify_hl(hl_proof, &coms, &gens[0], &gens[1], &gens[2])
        .map_err(|_| HiciapError::VerificationFailed)?;

    // Now check the HiCIAP proofs
    all_verifier_inputs
        .iter()
        .zip(hiciap_proofs.iter())
        .zip(circuit_vks.iter())
        .zip(ip_verifier_srss.iter())
        .map(
            |(((verifier_inputs, proof), circuit_vk), ip_verifier_srs)| {
                hiciap_verify(&ip_verifier_srs, &circuit_vk, verifier_inputs, proof)
            },
        )
        .reduce(Result::and)
        .unwrap()
}
