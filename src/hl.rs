use crate::util::TranscriptProtocol;

use core::iter;
use std::io::{Read, Write};

use ark_ec::group::Group;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    rand::{CryptoRng, Rng},
    UniformRand,
};
use merlin::Transcript;

const HL_DOMAIN_STR: &[u8] = b"HL";

/// HiCIAP-linkage proof. Encodes a sigma proof for the relation
/// ZK { ((Uᵢ)_{i=1}^k, G₁, G₂, G₃ ; w, (xᵢ, yᵢ)_{i=1}^n) : ∀i Uᵢ = wG₁+xᵢG₂+yᵢG₃ }
#[derive(CanonicalDeserialize, CanonicalSerialize, Clone)]
pub struct HlProof<G>
where
    G: Group + CanonicalSerialize + CanonicalDeserialize,
{
    pub(crate) com: Vec<G>,
    pub(crate) resp_r: G::ScalarField,
    pub(crate) resp_ss: Vec<G::ScalarField>,
    pub(crate) resp_ts: Vec<G::ScalarField>,
}

/// Proves ZK { ((Uᵢ)_{i=1}^k, G₁, G₂, G₃ ; w, (xᵢ, yᵢ)_{i=1}^n) : ∀i Uᵢ = wG₁+xᵢG₂+yᵢG₃ }. Uses
/// the context provided by `transcript` to create the ZK challenge.
///
/// Panics
/// ======
/// Panics if the relation does not hold wrt the given values.
pub fn prove_hl<G, R>(
    rng: &mut R,
    transcript: &mut Transcript,
    us: &[G],
    basis: &[G; 3],
    w: &G::ScalarField,
    xs: &[G::ScalarField],
    ys: &[G::ScalarField],
) -> HlProof<G>
where
    G: Group + CanonicalSerialize + CanonicalDeserialize,
    R: CryptoRng + Rng,
{
    // Destructure the basis
    let g1 = &basis[0];
    let g2 = &basis[1];
    let g3 = &basis[2];

    // Make sure the statement is true
    assert_eq!(us.len(), xs.len());
    assert_eq!(xs.len(), ys.len());
    for ((u, x), y) in us.iter().zip(xs.iter()).zip(ys.iter()) {
        assert_eq!(u, &(g1.mul(w) + g2.mul(x) + g3.mul(y)));
    }

    // Domain-separate this protocol
    transcript.append_message(b"dom-sep", HL_DOMAIN_STR);

    let k = us.len();

    // Pick random α, (βᵢ,γᵢ)_{i=1}^k
    let alpha = G::ScalarField::rand(rng);
    let betas: Vec<G::ScalarField> = iter::repeat_with(|| G::ScalarField::rand(rng))
        .take(k)
        .collect();
    let gammas: Vec<G::ScalarField> = iter::repeat_with(|| G::ScalarField::rand(rng))
        .take(k)
        .collect();

    // Construct the commitment com = (αG₁+βᵢG₂+γᵢG₃)_{i=1}^k
    let com: Vec<G> = betas
        .iter()
        .zip(gammas.iter())
        .map(|(beta, gamma)| g1.mul(&alpha) + g2.mul(beta) + g3.mul(gamma))
        .collect();

    // Update the transcript
    transcript.append_serializable(b"us", us);
    transcript.append_serializable(b"g1", g1);
    transcript.append_serializable(b"g2", g2);
    transcript.append_serializable(b"g3", g3);
    transcript.append_serializable(b"com", &com);

    // Get a challenge from the transcript hash
    let c: G::ScalarField = transcript.challenge_scalar(b"c");

    // Respond with r = α-cw and ∀i (sᵢ, tᵢ) = (βᵢ-cxᵢ, γᵢ-cyᵢ)
    let resp_r = alpha - &(c * w);
    let resp_ss: Vec<G::ScalarField> = betas
        .iter()
        .zip(xs.iter())
        .map(|(&beta, x)| beta - &(c * x))
        .collect();
    let resp_ts: Vec<G::ScalarField> = gammas
        .iter()
        .zip(ys.iter())
        .map(|(&gamma, y)| gamma - &(c * y))
        .collect();

    HlProof {
        com,
        resp_r,
        resp_ss,
        resp_ts,
    }
}

/// Verifies ZK { ((Uᵢ)_{i=1}^k, G₁, G₂, G₃ ; w, (xᵢ, yᵢ)_{i=1}^n) : ∀i Uᵢ = wG₁+xᵢG₂+yᵢG₃ }. Uses
/// the context provided by `transcript` to create the ZK challenge.
pub fn verify_hl<G>(
    transcript: &mut Transcript,
    proof: &HlProof<G>,
    us: &[G],
    basis: &[G; 3],
) -> bool
where
    G: Group + CanonicalSerialize + CanonicalDeserialize,
{
    // Destructure the basis
    let g1 = &basis[0];
    let g2 = &basis[1];
    let g3 = &basis[2];

    // Domain-separate this protocol
    transcript.append_message(b"dom-sep", HL_DOMAIN_STR);

    let HlProof {
        com,
        resp_r,
        resp_ss,
        resp_ts,
        ..
    } = proof;

    // Update the transcript
    transcript.append_serializable(b"us", us);
    transcript.append_serializable(b"g1", g1);
    transcript.append_serializable(b"g2", g2);
    transcript.append_serializable(b"g3", g3);
    transcript.append_serializable(b"com", com);

    // Get a challenge from the transcript hash
    let c: G::ScalarField = transcript.challenge_scalar(b"c");

    // Check that com == (rG₁+sᵢG₂+tᵢG₃+cUᵢ)_{i=1}^k
    for (((com_val, s), t), u) in com
        .iter()
        .zip(resp_ss.iter())
        .zip(resp_ts.iter())
        .zip(us.iter())
    {
        let derived_val = g1.mul(&resp_r) + g2.mul(&s) + g3.mul(&t) + u.mul(&c);
        // It doesn't matter that this isn't constant time. This is a public-verifier proof.
        if com_val != &derived_val {
            return false;
        }
    }

    true
}

#[test]
fn test_hl_correctness() {
    use ark_ec::PairingEngine;

    type F = <G as Group>::ScalarField;
    type G = <ark_bls12_381::Bls12_381 as PairingEngine>::G1Projective;

    // Get some arbitrary generators and field elements
    let mut rng = ark_std::test_rng();
    let (g1, g2, g3) = (G::rand(&mut rng), G::rand(&mut rng), G::rand(&mut rng));
    let basis = [g1, g2, g3];
    let (w, x1, y1, x2, y2) = (
        F::rand(&mut rng),
        F::rand(&mut rng),
        F::rand(&mut rng),
        F::rand(&mut rng),
        F::rand(&mut rng),
    );

    // Define U₁, U₂ such that they satisfy the HL relation
    let u1 = g1.mul(&w) + g2.mul(&x1) + g3.mul(&y1);
    let u2 = g1.mul(&w) + g2.mul(&x2) + g3.mul(&y2);

    // Collect the variables
    let us = &[u1, u2];
    let xs = &[x1, x2];
    let ys = &[y1, y2];

    // Make an empty transcript for proving, and prove the relation
    let mut proving_transcript = Transcript::new(b"test_hl_correctness");
    let proof = prove_hl(&mut rng, &mut proving_transcript, us, &basis, &w, xs, ys);

    // Now make an empty transcript for verifying, and verify the relation
    let mut verifying_transcript = Transcript::new(b"test_hl_correctness");
    assert!(verify_hl(&mut verifying_transcript, &proof, us, &basis,));
}
