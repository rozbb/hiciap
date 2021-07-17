use crate::util::hash_to_field;

use core::iter;
use std::io::{Read, Write};

use ark_ec::group::Group;
use ark_ff::{to_bytes, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::rand::{CryptoRng, Rng};

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

/// Proves ZK { ((Uᵢ)_{i=1}^k, G₁, G₂, G₃ ; w, (xᵢ, yᵢ)_{i=1}^n) : ∀i Uᵢ = wG₁+xᵢG₂+yᵢG₃ }
///
/// Panics
/// ======
/// Panics if the relation does not hold wrt the given values.
pub fn prove_hl<G, R>(
    rng: &mut R,
    us: &[G],
    g1: &G,
    g2: &G,
    g3: &G,
    w: &G::ScalarField,
    xs: &[G::ScalarField],
    ys: &[G::ScalarField],
) -> HlProof<G>
where
    G: Group + CanonicalSerialize + CanonicalDeserialize,
    R: CryptoRng + Rng,
{
    // Make sure the statement is true
    assert_eq!(us.len(), xs.len());
    assert_eq!(xs.len(), ys.len());
    for ((u, x), y) in us.iter().zip(xs.iter()).zip(ys.iter()) {
        assert_eq!(u, &(g1.mul(w) + g2.mul(x) + g3.mul(y)));
    }

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

    // Let the challenge be the hash of the transcript
    let c: G::ScalarField = hash_to_field(&to_bytes![HL_DOMAIN_STR, us, g1, g2, g3, com].unwrap());

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

/// Verifies ZK { ((Uᵢ)_{i=1}^k, G₁, G₂, G₃ ; w, (xᵢ, yᵢ)_{i=1}^n) : ∀i Uᵢ = wG₁+xᵢG₂+yᵢG₃ }
pub fn verify_hl<G>(proof: &HlProof<G>, us: &[G], g1: &G, g2: &G, g3: &G) -> Result<(), ()>
where
    G: Group + CanonicalSerialize + CanonicalDeserialize,
{
    let HlProof {
        com,
        resp_r,
        resp_ss,
        resp_ts,
        ..
    } = proof;

    // Let the challenge be the hash of the transcript
    let c: G::ScalarField = hash_to_field(&to_bytes![HL_DOMAIN_STR, us, g1, g2, g3, com].unwrap());

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
            return Err(());
        }
    }

    Ok(())
}

#[test]
fn test_hl_correctness() {
    use ark_ec::PairingEngine;

    type F = <G as Group>::ScalarField;
    type G = <ark_bls12_381::Bls12_381 as PairingEngine>::G1Projective;

    // Get some arbitrary generators and field elements
    let mut rng = ark_std::test_rng();
    let (g1, g2, g3) = (G::rand(&mut rng), G::rand(&mut rng), G::rand(&mut rng));
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

    // Prove the relation and ensure that it verifies
    let us = &[u1, u2];
    let xs = &[x1, x2];
    let ys = &[y1, y2];
    let proof = prove_hl(&mut rng, us, &g1, &g2, &g3, &w, xs, ys);
    assert!(verify_hl(&proof, us, &g1, &g2, &g3).is_ok());
}
