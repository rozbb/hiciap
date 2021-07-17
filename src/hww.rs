use crate::util::hash_to_field;

use std::io::{Read, Write};

use ark_ec::group::Group;
use ark_ff::{to_bytes, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::rand::{CryptoRng, Rng};

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

/// Proves ZK { (U, V, G₁, G₂, G₃, G₄, G₅ ; w, x, y) : U = wG₁+xG₂+yG₃  ∧  V = wG₄+xG₅ }
///
/// Panics
/// ======
/// Panics if the relation does not hold wrt the given values.
pub(crate) fn prove_hww<G, R>(
    rng: &mut R,
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

    // Let the challenge be the hash of the transcript
    let c: G::ScalarField =
        hash_to_field(&to_bytes![HWW_DOMAIN_STR, u, v, g1, g2, g3, g4, g5, com.0, com.1].unwrap());

    // Respond with (r₁, r₃, r₃) = (α-cw, β-cx, γ-cz)
    let resp = (alpha - &(c * w), beta - &(c * x), gamma - &(c * y));

    HwwProof { com, resp }
}

/// Verifies ZK { (U, V, G₁, G₂, G₃, G₄, G₅ ; w, x, y) : U = wG₁+xG₂+yG₃  ∧  V = wG₄+xG₅ }
pub(crate) fn verify_hww<G>(
    proof: &HwwProof<G>,
    u: &G,
    v: &G,
    g1: &G,
    g2: &G,
    g3: &G,
    g4: &G,
    g5: &G,
) -> Result<(), ()>
where
    G: Group + CanonicalSerialize + CanonicalDeserialize,
{
    // Let the challenge be the hash of the transcript
    let com = proof.com;
    let c: G::ScalarField =
        hash_to_field(&to_bytes![HWW_DOMAIN_STR, u, v, g1, g2, g3, g4, g5, com.0, com.1].unwrap());

    // Check that com == (r₁G₁+r₂G₂+r₃G₃+cU,  r₁G₄+r₂G₅+cV)
    let (r1, r2, r3) = proof.resp;
    let val1 = g1.mul(&r1) + g2.mul(&r2) + g3.mul(&r3) + u.mul(&c);
    let val2 = g4.mul(&r1) + g5.mul(&r2) + v.mul(&c);
    if proof.com == (val1, val2) {
        Ok(())
    } else {
        Err(())
    }
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

    // Prove the relation and ensure that it verifies
    let proof = prove_hww(&mut rng, &u, &v, &g1, &g2, &g3, &g4, &g5, &w, &x, &y);
    assert!(verify_hww(&proof, &u, &v, &g1, &g2, &g3, &g4, &g5).is_ok());
}
