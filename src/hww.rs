use crate::util::get_field_chal;

use std::io::{Read, Write};

use ark_ec::group::Group;
use ark_ff::{to_bytes, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::rand::{CryptoRng, Rng};
use merlin::Transcript;

const HWW_DOMAIN_STR: &[u8] = b"HWW";

/// Hidden Wire Well-formedness proof. Encodes a sigma proof for the relation
/// ZK { (U, V, G₁, G₂, G₃, G₄, G₅ ; w, x, y) : U = wG₁+xG₂+yG₃  ∧  V = wG₄+xG₅ }
#[derive(CanonicalDeserialize, CanonicalSerialize, Clone)]
pub(crate) struct HwwProof<G>
where
    G: Group + CanonicalSerialize + CanonicalDeserialize,
{
    pub(crate) com: (G, G),
    pub(crate) resp: (G::ScalarField, G::ScalarField, G::ScalarField),
}

/// Proves ZK { (U, V, G₁, G₂, G₃, G₄, G₅ ; w, x, y) : U = wG₁+xG₂+yG₃  ∧  V = wG₄+xG₅ }. Uses the
/// context provided by `transcript` to create the ZK challenge.
///
/// Panics
/// ======
/// Panics if the relation does not hold wrt the given values.
pub(crate) fn prove_hww<G, R>(
    rng: &mut R,
    transcript: &mut Transcript,
    u: &G,
    v: &G,
    g1: &G,
    g2: &G,
    g3: &G,
    g4: &G,
    g5: &G,
    w: &G::ScalarField,
    x: &G::ScalarField,
    y: &G::ScalarField,
) -> HwwProof<G>
where
    G: Group + CanonicalSerialize + CanonicalDeserialize,
    R: CryptoRng + Rng,
{
    // Make sure the statement is true
    assert_eq!(u, &(g1.mul(w) + g2.mul(x) + g3.mul(y)));
    assert_eq!(v, &(g4.mul(w) + g5.mul(x)));

    // Pick random α,β,γ
    let (alpha, beta, gamma) = (
        G::ScalarField::rand(rng),
        G::ScalarField::rand(rng),
        G::ScalarField::rand(rng),
    );
    // Construct the commitment K = (αG₁+βG₂+γG₃, αG₄+βG₅)
    let com = (
        g1.mul(&alpha) + g2.mul(&beta) + g3.mul(&gamma),
        g4.mul(&alpha) + g5.mul(&beta),
    );

    // Update the transcript
    transcript.append_message(b"HWW domain", HWW_DOMAIN_STR);
    transcript.append_message(b"u", &to_bytes!(u).unwrap());
    transcript.append_message(b"v", &to_bytes!(v).unwrap());
    transcript.append_message(b"g1", &to_bytes!(g1).unwrap());
    transcript.append_message(b"g2", &to_bytes!(g2).unwrap());
    transcript.append_message(b"g3", &to_bytes!(g3).unwrap());
    transcript.append_message(b"g4", &to_bytes!(g4).unwrap());
    transcript.append_message(b"g5", &to_bytes!(g5).unwrap());
    transcript.append_message(b"com.0", &to_bytes!(com.0).unwrap());
    transcript.append_message(b"com.1", &to_bytes!(com.1).unwrap());

    // Get a challenge from the transcript hash
    let c: G::ScalarField = get_field_chal(b"c", transcript);

    // Respond with (r₁, r₃, r₃) = (α-cw, β-cx, γ-cz)
    let resp = (alpha - &(c * w), beta - &(c * x), gamma - &(c * y));

    HwwProof { com, resp }
}

/// Verifies ZK { (U, V, G₁, G₂, G₃, G₄, G₅ ; w, x, y) : U = wG₁+xG₂+yG₃  ∧  V = wG₄+xG₅ }. Uses
/// the context provided by `transcript` to create the ZK challenge.
#[must_use]
pub(crate) fn verify_hww<G>(
    transcript: &mut Transcript,
    proof: &HwwProof<G>,
    u: &G,
    v: &G,
    g1: &G,
    g2: &G,
    g3: &G,
    g4: &G,
    g5: &G,
) -> bool
where
    G: Group + CanonicalSerialize + CanonicalDeserialize,
{
    let com = proof.com;

    // Update the transcript
    transcript.append_message(b"HWW domain", HWW_DOMAIN_STR);
    transcript.append_message(b"u", &to_bytes!(u).unwrap());
    transcript.append_message(b"v", &to_bytes!(v).unwrap());
    transcript.append_message(b"g1", &to_bytes!(g1).unwrap());
    transcript.append_message(b"g2", &to_bytes!(g2).unwrap());
    transcript.append_message(b"g3", &to_bytes!(g3).unwrap());
    transcript.append_message(b"g4", &to_bytes!(g4).unwrap());
    transcript.append_message(b"g5", &to_bytes!(g5).unwrap());
    transcript.append_message(b"com.0", &to_bytes!(com.0).unwrap());
    transcript.append_message(b"com.1", &to_bytes!(com.1).unwrap());

    // Get a challenge from the transcript hash
    let c: G::ScalarField = get_field_chal(b"c", transcript);

    // Check that com == (r₁G₁+r₂G₂+r₃G₃+cU,  r₁G₄+r₂G₅+cV)
    let (r1, r2, r3) = proof.resp;
    let val1 = g1.mul(&r1) + g2.mul(&r2) + g3.mul(&r3) + u.mul(&c);
    let val2 = g4.mul(&r1) + g5.mul(&r2) + v.mul(&c);

    proof.com == (val1, val2)
}

#[test]
fn test_hww_correctness() {
    use ark_ec::PairingEngine;

    type F = <G as Group>::ScalarField;
    type G = <ark_bls12_381::Bls12_381 as PairingEngine>::G1Projective;

    // Get some arbitrary generators and field elements
    let mut rng = ark_std::test_rng();
    let (g1, g2, g3, g4, g5) = (
        G::rand(&mut rng),
        G::rand(&mut rng),
        G::rand(&mut rng),
        G::rand(&mut rng),
        G::rand(&mut rng),
    );
    let (w, x, y) = (F::rand(&mut rng), F::rand(&mut rng), F::rand(&mut rng));

    // Define U, V such that they satisfy the HWW relation
    let u = g1.mul(&w) + g2.mul(&x) + g3.mul(&y);
    let v = g4.mul(&w) + g5.mul(&x);

    // Make an empty transcript for proving, and prove the relation
    let mut proving_transcript = Transcript::new(b"test_hww_correctness");
    let proof = prove_hww(
        &mut rng,
        &mut proving_transcript,
        &u,
        &v,
        &g1,
        &g2,
        &g3,
        &g4,
        &g5,
        &w,
        &x,
        &y,
    );

    // Now make an empty transcript for verifying, and verify the relation
    let mut verifying_transcript = Transcript::new(b"test_hww_correctness");
    assert!(verify_hww(
        &mut verifying_transcript,
        &proof,
        &u,
        &v,
        &g1,
        &g2,
        &g3,
        &g4,
        &g5
    ));
}
