use crate::{
    hww::{prove_hww, verify_hww, HwwProof},
    util::{get_pedersen_generators, TranscriptProtocol},
    HiciapError,
};

use std::io::{Read, Write};

use ark_dh_commitments::{
    afgho16::{AFGHOCommitmentG1, AFGHOCommitmentG2},
    identity::{HomomorphicPlaceholderValue, IdentityCommitment, IdentityOutput},
};
use ark_ec::{group::Group, msm::VariableBaseMSM, AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_groth16::{self, Proof as Groth16Proof, VerifyingKey as CircuitVerifyingKey};
use ark_inner_products::{
    ExtensionFieldElement, InnerProduct, MultiexponentiationInnerProduct, PairingInnerProduct,
};
use ark_ip_proofs::{
    tipa::{
        structured_scalar_message::{structured_scalar_power, TIPAWithSSM, TIPAWithSSMProof},
        TIPAProof, TIPA,
    },
    Error,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    rand::{CryptoRng, Rng},
    UniformRand,
};
use merlin::Transcript;
use rayon::prelude::*;

pub use ark_ip_proofs::tipa::{VerifierSRS as HiciapVerifKey, SRS as HiciapProvingKey};

const HICIAP_DOMAIN_STR: &[u8] = b"HiCIAP";

// TODO: Update RIPP to use Merlin instead of their own Blake2 thing
// The RIPP crates uses Blake2 for noninteractive protocol challenges
type D = blake2::Blake2s;

/// A single group element representing all the public inputs to a circuit
pub type PreparedCircuitInput<P> = <P as PairingEngine>::G1Projective;

/// Represents A*B = Π e(Aᵢ, Bᵢ)
type PairingInnerProductAB<P> = TIPA<
    PairingInnerProduct<P>,
    AFGHOCommitmentG1<P>,
    AFGHOCommitmentG2<P>,
    IdentityCommitment<ExtensionFieldElement<P>, <P as PairingEngine>::Fr>,
    P,
    D,
>;

/// A short proof that C = A*B, given commitments to A and B
type PairingInnerProductABProof<P> = TIPAProof<
    PairingInnerProduct<P>,
    AFGHOCommitmentG1<P>,
    AFGHOCommitmentG2<P>,
    IdentityCommitment<ExtensionFieldElement<P>, <P as PairingEngine>::Fr>,
    P,
    D,
>;

/// Represents A^b = Σ bᵢ·Aᵢ
type MultiExpInnerProductC<P> = TIPAWithSSM<
    MultiexponentiationInnerProduct<<P as PairingEngine>::G1Projective>,
    AFGHOCommitmentG1<P>,
    IdentityCommitment<<P as PairingEngine>::G1Projective, <P as PairingEngine>::Fr>,
    P,
    D,
>;

/// A short proof that C = A^b given b and a commitment to C
type MultiExpInnerProductCProof<P> = TIPAWithSSMProof<
    MultiexponentiationInnerProduct<<P as PairingEngine>::G1Projective>,
    AFGHOCommitmentG1<P>,
    IdentityCommitment<<P as PairingEngine>::G1Projective, <P as PairingEngine>::Fr>,
    P,
    D,
>;

/// The opening of a commitment to a hidden input (called com_{a_0} in the paper)
#[derive(Clone)]
pub struct HiddenInputOpening<P: PairingEngine> {
    pub(crate) hidden_input: <P as PairingEngine>::Fr,
    pub(crate) z1: <P as PairingEngine>::Fr,
    pub(crate) z3: <P as PairingEngine>::Fr,
}

/// The components of a client-side multiexponentiation proof
#[derive(CanonicalDeserialize, CanonicalSerialize, Clone)]
struct CsmData<P: PairingEngine> {
    /// A commitment to the cirucit input elements
    com_inputs: ExtensionFieldElement<P>,
    /// The aggregated circuit input elements
    agg_inputs: P::G1Projective,
    /// Transcript of the MIPP_k protocol execution on `prepared_inputs`
    mipp_proof_agg_inputs: Mipp<P>,
}

/// The components of a HiCIAP proof
#[derive(CanonicalDeserialize, CanonicalSerialize, Clone)]
pub struct HiciapProof<P: PairingEngine> {
    pub(crate) com_a0: P::G1Projective,
    com_a: ExtensionFieldElement<P>,
    com_b: ExtensionFieldElement<P>,
    com_c: ExtensionFieldElement<P>,
    ip_ab: ExtensionFieldElement<P>,
    agg_c: P::G1Projective,
    /// Called W in the paper
    hidden_wire_com: P::G1Projective,
    /// Transcript of an HWW protocol execution
    hidden_input_proof: HwwProof<P::G1Projective>,
    /// Transcript of a structured TIPP protocol execution
    tipa_proof_ab: PairingInnerProductABProof<P>,
    /// Transcript of a HideMIPP_k protocol execution on C
    hide_mipp_proof_c: HideMipp<P>,
    /// Optional client-side multiexponentiation optimization
    csm_data: Option<CsmData<P>>,
}

/// Transcript of an execution of the HideMIPP protocol
#[derive(CanonicalDeserialize, CanonicalSerialize, Clone)]
pub struct HideMipp<P: PairingEngine> {
    // The names below correspond to the names in the paper
    com_q: ExtensionFieldElement<P>,
    agg_q: P::G1Projective,
    rho_prime: P::Fr,
    mipp_proof_c: MultiExpInnerProductCProof<P>,
}

/// Transcript of an execution of the MIPP protocol
type Mipp<P> = MultiExpInnerProductCProof<P>;

/// Constructs a short random string that's used as a commitment key in HiCIAP. Supports up to
/// `num_proofs` many Groth16 proofs.
pub fn hiciap_setup<P, R>(rng: &mut R, num_proofs: usize) -> Result<HiciapProvingKey<P>, Error>
where
    P: PairingEngine,
    R: Rng + CryptoRng,
{
    // There's a num_proofs + 2 elements in the A and B vectors in HiCIAP
    let srs_size = num_proofs + 2;
    let (srs, _) = PairingInnerProductAB::<P>::setup(rng, srs_size)?;
    Ok(srs)
}

/// Helper function which computes e(blind, G₂) + (v * ck_right), where (*) denotes inner pairing
/// product.
fn blinded_com<P>(
    v: &[P::G1Projective],
    ck_right: &[P::G2Projective],
    blind: &P::Fr,
) -> Result<ExtensionFieldElement<P>, Error>
where
    P: PairingEngine,
{
    let non_hiding_com = PairingInnerProduct::<P>::inner_product(v, ck_right)?;

    let g = P::G1Projective::prime_subgroup_generator();
    let g2elem = get_pedersen_generators::<P::G2Projective>(1)[0];
    let blinded_g = g.mul(blind.into_repr());
    let blinding_factor = P::pairing(blinded_g, g2elem);

    Ok(ExtensionFieldElement(blinding_factor * non_hiding_com.0))
}

/// Given log(#proofs), return the indices of the proof elements we want to randomize
fn masking_set(logn: u32) -> Vec<usize> {
    // The 0-indexed masking set is
    //     {0, 1, 2} ∪ {2^i-1, 2^i, 2^i+1}_{i=2}^{ℓ-1} ∪ {2^ℓ-3, 2^ℓ-4, 2^ℓ-5}
    // where ℓ is log(n) and n is the number of proofs
    let mut m = vec![0, 1, 2];
    for i in 2..logn {
        m.push(2usize.pow(i) - 1);
        m.push(2usize.pow(i));
        m.push(2usize.pow(i) + 1);
    }
    m.extend_from_slice(&[
        2usize.pow(logn) - 3,
        2usize.pow(logn) - 4,
        2usize.pow(logn) - 5,
    ]);

    m
}

// TODO: Automatically pad out the inputs
// TODO: Figure out what gets mutated if an error occurs
/// Aggregates multiple proofs over the same circuit, also proving that each proof shares the same
/// first witness value, `hidden_input`. This function will rerandomize a subset of `proofs`.
///
/// Panics
/// ======
/// This panics if `proofs.len() != 2^k - 2 for some k > 4` or if `prepared_public_inputs.len !=
/// proofs.len()`.
pub fn hiciap_prove<P, R>(
    rng: &mut R,
    transcript: &mut Transcript,
    hiciap_pk: &HiciapProvingKey<P>,
    circuit_vk: &CircuitVerifyingKey<P>,
    proofs: &mut [Groth16Proof<P>],
    mut prepared_public_inputs: Option<&mut Vec<PreparedCircuitInput<P>>>,
    hidden_input: P::Fr,
) -> Result<(HiciapProof<P>, HiddenInputOpening<P>), HiciapError>
where
    P: PairingEngine,
    R: CryptoRng + Rng,
{
    // Domain-separate this protocol
    transcript.append_message(b"dom-sep", HICIAP_DOMAIN_STR);

    let num_proofs = proofs.len();

    // HiCIAP is only implemented for 2-minus-power-of-two many proofs. Further, HiCIAP is only
    // zero-knowledge for 16 or more proofs (14 inputs + 2 we tack on).
    if !(num_proofs + 2).is_power_of_two() || num_proofs < 14 {
        panic!("HiCIAP must have #proofs = 2^k - 2 for some k > 4");
    }

    if prepared_public_inputs.is_some()
        && prepared_public_inputs.as_ref().map(|v| v.len()).unwrap() != proofs.len()
    {
        panic!("HiCIAP must have #inputs = #proofs");
    }

    // We use the client-side multiexponentiation optimization iff we're given the preprocessed
    // inputs
    let use_csm = prepared_public_inputs.is_some();

    // First thing: rerandomize all the proofs according to the masking set
    let logn = (num_proofs + 2).trailing_zeros();
    for idx in masking_set(logn) {
        let proof = &mut proofs[idx];
        *proof = ark_groth16::rerandomize_proof(rng, circuit_vk, proof);
    }

    // Initialize blinding factors
    let z1 = P::Fr::rand(rng);
    let z2 = P::Fr::rand(rng);
    let z3 = P::Fr::rand(rng);
    let z4 = P::Fr::rand(rng);

    // Compute z₁·G₁ and z₂·G₁
    let (z1_g1, z2_g1) = {
        let g = P::G1Projective::prime_subgroup_generator();
        (g.mul(z1.into_repr()), g.mul(z2.into_repr()))
    };

    // Get 2 generators in G₁ and Pedersen commit to a₀
    let gens: Vec<P::G1Projective> = get_pedersen_generators(3);
    let (p1, p2, p3) = (gens[0], gens[1], gens[2]);
    let com_a0 = p1.mul(hidden_input.into_repr()) + p2.mul(z1.into_repr()) + p3.mul(z3.into_repr());

    // Add identities to the preprocessed proof inputs so that it's the appropriate length for MIPP
    prepared_public_inputs.as_mut().map(|v| {
        v.push(P::G1Projective::zero());
        v.push(P::G1Projective::zero());
    });

    // 𝐀 = A_1 || ... || A_n || z₁·G₁ || z₂·G₁
    let a = {
        // Accumulate the A part of the proofs
        let mut buf = proofs
            .par_iter()
            .map(|proof| proof.a.into_projective())
            .collect::<Vec<P::G1Projective>>();

        // Add z₁·G₁ and z₂·G₁ to the end of the accumulated A's
        buf.push(z1_g1);
        buf.push(z2_g1);

        buf
    };

    // 𝐁 = B_1 || ... || B_n || γ·G₂ || δ·G₂
    let b = {
        let mut buf = proofs
            .par_iter()
            .map(|proof| proof.b.into_projective())
            .collect::<Vec<P::G2Projective>>();
        buf.push(circuit_vk.gamma_g2.into_projective());
        buf.push(circuit_vk.delta_g2.into_projective());

        buf
    };

    // 𝐂 = C_1 || ... || C_n || O || z₂·G₁
    let c = {
        let mut buf = proofs
            .par_iter()
            .map(|proof| proof.c.into_projective())
            .collect::<Vec<P::G1Projective>>();

        // Append O and z₂·G₁
        buf.push(P::G1Projective::zero());
        buf.push(z2_g1);
        buf
    };

    let (ck_1, ck_2) = hiciap_pk.get_commitment_keys();

    let com_a = PairingInnerProduct::<P>::inner_product(&a, &ck_1)?;
    let com_b = PairingInnerProduct::<P>::inner_product(&ck_2, &b)?;

    // Make a hiding commitment to C
    let com_c = blinded_com(&c, &ck_1, &z4)?;

    // If client-side multiexponentiation is enabled, commit to the preprocessed inputs
    let com_inputs = if use_csm {
        Some(PairingInnerProduct::<P>::inner_product(
            prepared_public_inputs.as_ref().unwrap(),
            &ck_1,
        )?)
    } else {
        None
    };

    // This is the hashed transcript, used for the Fiat-Shamir transform. We update as the protocol
    // goes along
    transcript.append_serializable(b"com_a0", &com_a0);
    transcript.append_serializable(b"com_a", &com_a);
    transcript.append_serializable(b"com_b", &com_b);
    transcript.append_serializable(b"com_c", &com_c);
    transcript.append_serializable(b"com_inputs", &com_inputs);

    // Random linear combination of proofs

    let r: P::Fr = transcript.challenge_scalar(b"r");
    let r_vec = structured_scalar_power(num_proofs + 2, &r);

    let a_r = a
        .par_iter()
        .zip(&r_vec)
        .map(|(a, r)| a.mul(r))
        .collect::<Vec<P::G1Projective>>();
    let ip_ab = PairingInnerProduct::<P>::inner_product(&a_r, &b)?;
    let agg_c = MultiexponentiationInnerProduct::<P::G1Projective>::inner_product(&c, &r_vec)?;

    // If client-side multiexponentiation is enabled, compute the aggregated inputs
    let agg_inputs = if use_csm {
        Some(
            MultiexponentiationInnerProduct::<P::G1Projective>::inner_product(
                prepared_public_inputs.as_ref().unwrap(),
                &r_vec,
            )?,
        )
    } else {
        None
    };

    // Update the transcript
    transcript.append_serializable(b"agg_c", &agg_c);
    transcript.append_serializable(b"agg_inputs", &agg_inputs);

    // The hidden common input commitment is
    //     (z₁rⁿ)·G + Σ_{i=0}^{n-1} (hidden_input · rⁱ) · W_{i,1}
    // where W_{i,1} is the first public input wire base, in the CRS of the i-th circuit. Here, we
    // compute the commitment as well as the proof of knowledge of the coefficients of G and W₁
    // that were used to construct this commitment.
    let (hidden_wire_com, hidden_input_proof) = {
        // Calculate (z₁rⁿ)·G
        let g = P::G1Projective::prime_subgroup_generator();
        let g_coeff: P::Fr = z1 * &r_vec[num_proofs];
        let blinding_factor = g.mul(g_coeff.into_repr());

        // Calculate wire_val_sum = Σ_{i=0}^{n-1} (hidden_input · rⁱ) · W_{i,1}. It's more
        // efficient to sum the appropriate powers of r for each identical W_{i,1}, sum up the
        // results, and then scalar multiply by hidden_input.
        // We also need to collect the other bases of the HWW proof. G₃ = Σ_{i=0} r_i · W_{i,1}.
        // This is actually a partial result to the calculation of the above sum.
        let g1 = {
            let w1 = &circuit_vk.gamma_abc_g1[1];
            let r_sum =
                (r.pow(&[num_proofs as u64]) - &<P::Fr>::one()) / &(r.clone() - &<P::Fr>::one());
            w1.mul(r_sum.into_repr())
        };
        let wire_val_sum = g1.mul(hidden_input.into_repr());

        // The other base used in the HWW proof. G₄ = r^{n+1} · G
        let g2 = g.mul(r_vec[num_proofs].into_repr());

        // Calculate the commitment (z₁r^{n+1})G + wire_val_sum
        let hidden_wire_com = blinding_factor + &wire_val_sum;

        // Update the transcript
        transcript.append_serializable(b"hidden_wire_com", &hidden_wire_com);

        // Construct the proof of well-formedness wrt the commitment to a₀
        let proof = prove_hww(
            rng,
            transcript,
            &com_a0,
            &hidden_wire_com,
            &p1,
            &p2,
            &p3,
            &g1,
            &g2,
            &hidden_input,
            &z1,
            &z3,
        );

        (hidden_wire_com, proof)
    };

    let ck_1_r = ck_1
        .par_iter()
        .zip(&r_vec)
        .map(|(ck, r)| ck.mul(&r.inverse().unwrap()))
        .collect::<Vec<P::G2Projective>>();

    debug_assert_eq!(
        com_a,
        PairingInnerProduct::<P>::inner_product(&a_r, &ck_1_r)?
    );

    // Prove that com_a and com_b represent commitments to A, B such that Aʳ * B = ip_ab where (*)
    // represents an inner pairing product operation, and Aʳ = Σ rᵢ·Aᵢ
    let tipa_proof_ab = PairingInnerProductAB::prove_with_srs_shift(
        &hiciap_pk,
        (&a_r, &b),
        (&ck_1_r, &ck_2, &HomomorphicPlaceholderValue),
        &r,
    )?;

    // Prove that com_c represents a C such that Cʳ = agg_c
    let hide_mipp_proof_c = {
        // Make a vector of random elements
        // NOTE: HKR19 says this can actually be mostly 0s. You only need logarithmically many such
        // elements.
        let q: Vec<P::G1Projective> = core::iter::repeat_with(|| P::G1Projective::rand(rng))
            .take(c.len())
            .collect();
        let rho = P::Fr::rand(rng);
        let agg_q = MultiexponentiationInnerProduct::<P::G1Projective>::inner_product(&q, &r_vec)?;
        let com_q = blinded_com(&q, &ck_1, &rho)?;

        // Update the transcript for the upcoming MIPP proof
        transcript.append_serializable(b"agg_q", &agg_q);
        transcript.append_serializable(b"com_q", &com_q);

        // Generate a challenge by hashing the transcript so far
        let hide_mipp_chal: P::Fr = transcript.challenge_scalar(b"hide_mipp_chal");

        // ρ' := chal·z₄ + ρ
        // C' := chal·C + Q
        let rho_prime = hide_mipp_chal * z4 + rho;
        let c_prime: Vec<P::G1Projective> = c
            .iter()
            .zip(q.iter())
            .map(|(c, q)| c.mul(&hide_mipp_chal) + q)
            .collect();

        let mipp_proof_c = MultiExpInnerProductC::prove_with_structured_scalar_message(
            &hiciap_pk,
            (&c_prime, &r_vec),
            (&ck_1, &HomomorphicPlaceholderValue),
        )?;

        HideMipp {
            com_q,
            agg_q,
            rho_prime,
            mipp_proof_c,
        }
    };

    // If the client-side multiexponentiation optim is enabled, prove MIPP on the aggregated inputs
    let mipp_proof_agg_inputs = if use_csm {
        Some(MultiExpInnerProductC::prove_with_structured_scalar_message(
            &hiciap_pk,
            (prepared_public_inputs.as_ref().unwrap(), &r_vec),
            (&ck_1, &HomomorphicPlaceholderValue),
        )?)
    } else {
        None
    };

    // Build the CSM struct if it's been calculated
    let csm_data = if use_csm {
        Some(CsmData {
            com_inputs: com_inputs.unwrap(),
            agg_inputs: agg_inputs.unwrap(),
            mipp_proof_agg_inputs: mipp_proof_agg_inputs.unwrap(),
        })
    } else {
        None
    };

    // Undo the appending of 2 identity elems
    prepared_public_inputs.map(|v| v.truncate(num_proofs));

    // Finally, save the opening to com_a0 so that it can be used in a linkage proof
    let hi_opening = HiddenInputOpening {
        hidden_input,
        z1,
        z3,
    };
    let proof = HiciapProof {
        com_a0,
        com_a,
        com_b,
        com_c,
        ip_ab,
        agg_c,
        hidden_wire_com,
        hidden_input_proof,
        tipa_proof_ab,
        hide_mipp_proof_c,
        csm_data,
    };

    Ok((proof, hi_opening))
}

/// Prepares the public inputs of a circuit. This is used in [`hiciap_prove`] and
/// [`hiciap_verify`].
///
/// Panics
/// ======
/// Panics if the number of proof inputs does not match the number of proof inputs expected by the
/// circuit.
pub fn prepare_circuit_input<P>(
    vk: &CircuitVerifyingKey<P>,
    proof_inputs: &[P::Fr],
) -> Result<PreparedCircuitInput<P>, HiciapError>
where
    P: PairingEngine,
{
    // For each circuit, the aggregated input wires are Σ_{j=0}^{m-1} aⱼ·Wⱼ, where aⱼ is a wire
    // value and Wⱼ is the CRS point corresponding to the j-th wire.  We aggregate everything but
    // W₁, since W₁ is the hidden input wire. Also, a₀ = 1 for all circuits, so we just add in W₀
    // for every circuit.
    let w_0 = vk.gamma_abc_g1[0].into_projective();
    let circuit_input_vars = &vk.gamma_abc_g1[2..];

    // Optimization: For padding circuits, proof_inputs is empty. In this case, exit early with w_0
    if proof_inputs.is_empty() {
        return Ok(w_0);
    }

    // Assert that the number of proof inputs is correct
    assert_eq!(circuit_input_vars.len(), proof_inputs.len());

    // Aggregate
    let inputs_as_bigints = proof_inputs
        .par_iter()
        .map(|b| b.into_repr())
        .collect::<Vec<_>>();
    let wire_agg = w_0 + VariableBaseMSM::multi_scalar_mul(circuit_input_vars, &inputs_as_bigints);
    Ok(wire_agg)
}

/// Contains either the prepared public inputs of several proofs (of the same circuit), or a
/// commitment thereto.
pub enum VerifierInputs<'a, P: PairingEngine> {
    /// Contains the prepared public inputs to all the circuits
    List(&'a mut Vec<PreparedCircuitInput<P>>),
    /// Contains a commitment to the prepared public inputs to all the circuit, as well as the
    /// number of elements committed to
    Com(ExtensionFieldElement<P>, usize),
}

impl<'a, P: PairingEngine> VerifierInputs<'a, P> {
    fn num_proofs(&self) -> usize {
        match self {
            VerifierInputs::List(v) => v.len(),
            VerifierInputs::Com(_, len) => *len,
        }
    }
}

impl<'a, P: PairingEngine> From<&'a mut Vec<PreparedCircuitInput<P>>> for VerifierInputs<'a, P> {
    fn from(inputs: &'a mut Vec<PreparedCircuitInput<P>>) -> VerifierInputs<'a, P> {
        VerifierInputs::List(inputs)
    }
}

impl<'a, P: PairingEngine> VerifierInputs<'a, P> {
    /// Computes the commitment to the given prepared public inputs. After this operation, this
    /// `VerifierInputs` can be used with `hiciap_verify` on CSM proofs for fast verification.
    pub fn compress(&mut self, hiciap_pk: &HiciapProvingKey<P>) -> Result<(), HiciapError> {
        // If we're a list, commit to the list. Otherwise, we're already a commitment so do nothing
        if let VerifierInputs::List(preprocessed_public_inputs) = self {
            // Commit to the inputs. That is, compute ck₁*preprocessed_public_inputs where (*)
            // is the inner pairing product operation.
            let num_proofs = preprocessed_public_inputs.len();
            let (ck_1, _) = hiciap_pk.get_commitment_keys();
            let com = PairingInnerProduct::<P>::inner_product(
                &preprocessed_public_inputs,
                &ck_1[..num_proofs],
            )?;

            *self = VerifierInputs::Com(com, num_proofs);
        }

        Ok(())
    }
}

/// Contians all the info a verifier needs in order to verify a HiCIAP proof
pub struct VerifierCtx<'a, P: PairingEngine> {
    /// The HiCIAP srs
    pub hiciap_vk: &'a HiciapVerifKey<P>,
    /// The Groth16 verifier key
    pub circuit_vk: &'a CircuitVerifyingKey<P>,
    /// Public inputs to the underlying proofs
    pub pub_input: VerifierInputs<'a, P>,
    /// The protocol transcript up to this point (if you don't know what this is, use
    /// `Transcript::new("your-label-here")`)
    pub verif_transcript: Transcript,
}

/// Aggregates proofs which share the same verifying key. `ad` is (non-secret) associated data the
/// the proof is bound to.
pub fn hiciap_verify<P>(
    ctx: &mut VerifierCtx<P>,
    proof: &HiciapProof<P>,
) -> Result<bool, HiciapError>
where
    P: PairingEngine,
{
    // Unwrap the context
    let VerifierCtx {
        hiciap_vk,
        circuit_vk,
        pub_input,
        verif_transcript,
    } = ctx;

    // Domain-separate this protocol
    let transcript = verif_transcript;
    transcript.append_message(b"dom-sep", HICIAP_DOMAIN_STR);

    // Get 2 generators in G₁ to check the Pedersen commitment to a₀
    let gens: Vec<P::G1Projective> = get_pedersen_generators(3);
    let (p1, p2, p3) = (gens[0], gens[1], gens[2]);

    let num_proofs = pub_input.num_proofs();
    let com_inputs = proof.csm_data.as_ref().map(|d| d.com_inputs.clone());

    // This is the hashed transcript, used for the Fiat-Shamir transform. We update as the protocol
    // goes along
    transcript.append_serializable(b"com_a0", &proof.com_a0);
    transcript.append_serializable(b"com_a", &proof.com_a);
    transcript.append_serializable(b"com_b", &proof.com_b);
    transcript.append_serializable(b"com_c", &proof.com_c);
    transcript.append_serializable(b"com_inputs", &com_inputs);

    // Random linear combination of proofs
    let r = transcript.challenge_scalar(b"r");

    // Check that com_a and com_b represent commitments to A, B such that Aʳ * B = ip_ab where (*)
    // represents an inner pairing product operation, and Aʳ = Σ rᵢ·Aᵢ
    let tipa_proof_ab_valid = PairingInnerProductAB::verify_with_srs_shift(
        hiciap_vk,
        &HomomorphicPlaceholderValue,
        (
            &proof.com_a,
            &proof.com_b,
            &IdentityOutput(vec![proof.ip_ab.clone()]),
        ),
        &proof.tipa_proof_ab,
        &r,
    )?;

    // Σ_{i=0}^{n-2} rⁱ = (r^{n-1} - 1) / (r - 1)
    let r_sum = (r.pow(&[num_proofs as u64]) - &<P::Fr>::one()) / &(r.clone() - &<P::Fr>::one());

    // Update the transcript
    let agg_inputs = proof.csm_data.as_ref().map(|d| d.agg_inputs.clone());
    transcript.append_serializable(b"agg_c", &proof.agg_c);
    transcript.append_serializable(b"agg_inputs", &agg_inputs);
    transcript.append_serializable(b"hidden_wire_com", &proof.hidden_wire_com);

    // Check the well-formedness of the given hidden input commitment. Calculate the bases G₃, G₄
    // used in the HWW proof.
    let g = P::G1Projective::prime_subgroup_generator();
    let g1 = {
        let w1 = &circuit_vk.gamma_abc_g1[1];
        w1.mul(r_sum.into_repr())
    };
    let g2 = g.mul(r.pow(&[num_proofs as u64]).into_repr());

    if !verify_hww(
        transcript,
        &proof.hidden_input_proof,
        &proof.com_a0,
        &proof.hidden_wire_com,
        &p1,
        &p2,
        &p3,
        &g1,
        &g2,
    ) {
        return Ok(false);
    }

    // Update the transcript
    transcript.append_serializable(b"agg_q", &proof.hide_mipp_proof_c.agg_q);
    transcript.append_serializable(b"com_q", &proof.hide_mipp_proof_c.com_q);

    // Check that com_c represents a C such that Cʳ = agg_c
    let tipa_proof_c_valid = {
        // Generate a challenge by hashing the transcript so far
        let hide_mipp_chal: P::Fr = transcript.challenge_scalar(b"hide_mipp_chal");

        // Compute e(G^{-ρ'}, H) where H is some element from P::G2
        let g_neg_rho_prime = {
            let g = P::G1Projective::prime_subgroup_generator();
            g.mul((-proof.hide_mipp_proof_c.rho_prime).into_repr())
        };
        let blinding_factor = {
            let g2elem: P::G2Projective = get_pedersen_generators(1)[0];
            P::pairing(g_neg_rho_prime, g2elem)
        };

        // Compute the new commitment and aggregation that we'll run MIPP on
        let com_prime = ExtensionFieldElement(
            proof.com_c.0.pow(hide_mipp_chal.into_repr())
                * proof.hide_mipp_proof_c.com_q.0
                * blinding_factor,
        );
        let agg_prime = proof.agg_c.mul(hide_mipp_chal.into_repr()) + proof.hide_mipp_proof_c.agg_q;

        // Verify MIPP wrt com', agg', and the given MIPP transcript
        MultiExpInnerProductC::verify_with_structured_scalar_message(
            hiciap_vk,
            &HomomorphicPlaceholderValue,
            (&com_prime, &IdentityOutput(vec![agg_prime])),
            &r,
            &proof.hide_mipp_proof_c.mipp_proof_c,
        )?
    };

    // If CSM data is given and we have an input commitment, verify the given MIPP proof.
    // Otherwise, compute agg_inputs yourself.
    let agg_inputs = match pub_input {
        VerifierInputs::Com(com_inputs, _) => {
            if let Some(ref csm_data) = proof.csm_data {
                // Check that the input commitment matches our input commitment
                // TODO: This is technically public inputs but it wouldn't hurt to make this
                // constant time
                if com_inputs != &csm_data.com_inputs {
                    return Err(HiciapError::VerificationFailed);
                }

                // Check that agg_inputs is correctly computed
                MultiExpInnerProductC::verify_with_structured_scalar_message(
                    hiciap_vk,
                    &HomomorphicPlaceholderValue,
                    (
                        &csm_data.com_inputs,
                        &IdentityOutput(vec![csm_data.agg_inputs]),
                    ),
                    &r,
                    &csm_data.mipp_proof_agg_inputs,
                )?;

                csm_data.agg_inputs
            } else {
                // Error: We have been given a commitment, but no CSM to use it on. We can't verify
                // this proof
                return Err(HiciapError::NoCsmAvailable);
            }
        }
        VerifierInputs::List(prepared_public_inputs) => {
            let r_vec = structured_scalar_power(num_proofs + 2, &r);
            MultiexponentiationInnerProduct::<P::G1Projective>::inner_product(
                &prepared_public_inputs,
                &r_vec[..num_proofs],
            )?
        }
    };

    let p1 = P::pairing(
        circuit_vk.alpha_g1.into_projective().mul(r_sum.into_repr()),
        circuit_vk.beta_g2,
    );
    let p2 = P::pairing(agg_inputs, circuit_vk.gamma_g2);
    let p3 = P::pairing(proof.agg_c, circuit_vk.delta_g2);
    let p4 = P::pairing(proof.hidden_wire_com, circuit_vk.gamma_g2);

    // Ensure that Aʳ * B = Z where Z is the product of all the above factors
    let ppe_valid = proof.ip_ab.0 == ((p1 * &p2) * &p3) * &p4;

    Ok(tipa_proof_ab_valid && tipa_proof_c_valid && ppe_valid)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_circuit::{gen_preimage_circuit_params, gen_preimage_proof};

    use core::iter;

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_groth16::Proof as Groth16Proof;
    use ark_std::UniformRand;

    type P = Bls12_381;

    #[test]
    fn test_hiciap_correctness() {
        let mut rng = ark_std::test_rng();

        // Fix all the constants
        let num_proofs = 2usize.pow(7) - 2;
        let num_extra_circuit_inputs = 10;
        let mut proof_transcript = Transcript::new(b"test_hiciap_correctness");

        // Generate all the (short) common random strings
        let hiciap_pk = hiciap_setup(&mut rng, num_proofs).unwrap();
        let hiciap_vk = hiciap_pk.get_verifier_key();
        let circuit_pk = gen_preimage_circuit_params(&mut rng, num_extra_circuit_inputs);
        let circuit_vk = &circuit_pk.vk;

        // Construct a bunch of Groth16 proofs wrt the same hidden input
        let hidden_input = Fr::rand(&mut rng);
        let groth16_proofs_and_inputs: Vec<(Groth16Proof<P>, Vec<Fr>)> = iter::repeat_with(|| {
            gen_preimage_proof(
                &mut rng,
                &circuit_pk,
                &hidden_input,
                num_extra_circuit_inputs,
            )
        })
        .take(num_proofs)
        .collect();

        // Separate out the proofs and their public inputs
        let mut groth16_proofs: Vec<Groth16Proof<P>> = groth16_proofs_and_inputs
            .iter()
            .map(|e| e.0.clone())
            .collect();
        let mut prepared_public_inputs: Vec<PreparedCircuitInput<P>> = groth16_proofs_and_inputs
            .iter()
            .map(|e| prepare_circuit_input(&circuit_vk, &e.1).unwrap())
            .collect();

        // Compute a HiCIAP proof with CSM
        let (hiciap_proof, _) = hiciap_prove(
            &mut rng,
            &mut proof_transcript,
            &hiciap_pk,
            &circuit_vk,
            &mut groth16_proofs,
            Some(&mut prepared_public_inputs),
            hidden_input,
        )
        .unwrap();

        // Now verify using CSM as well. First collect and compress the inputs
        let mut verifier_inputs: VerifierInputs<P> = (&mut prepared_public_inputs).into();
        verifier_inputs.compress(&hiciap_pk).unwrap();
        // Make the verif transcript the same as the prover's
        let verif_transcript = Transcript::new(b"test_hiciap_correctness");
        // Now collect everything for the verifier's context
        let mut ctx = VerifierCtx {
            hiciap_vk: &hiciap_vk,
            circuit_vk: &circuit_vk,
            pub_input: verifier_inputs,
            verif_transcript,
        };
        assert!(hiciap_verify(&mut ctx, &hiciap_proof,).unwrap());
    }
}

/*
#[cfg(test)]
mod test {
    use crate::{
        blocklist::{BlocklistElem, ChunkNonMembershipCircuit},
        credential::PrivateId,
        groth16::{circuit_specific_setup, ToxicWaste},
        hiciap::{
            hiciap_preprocess_input, hiciap_prove, hiciap_pub_input_com, hiciap_verify,
            setup_inner_product, PreparedCircuitInput,
        },
        test_util::{gen_blocklist, make_blocklist_circuit},
    };

    use core::iter;

    use ark_bls12_381::fr::Fr;
    use ark_bls12_381::Bls12_381;
    use ark_crypto_primitives::snark::SNARK;
    use ark_ff::UniformRand;
    use ark_groth16::{Groth16, Proof};
    use ark_r1cs_std::fields::fp::FpVar;
    use blake2::Blake2s;

    // BLS12-381's scalar field var
    type FrV = FpVar<Fr>;

    // Runs HICIAP on a bunch of circuits
    #[test]
    fn test_hiciap_correctness() {
        let chunk_size = 10;
        let num_chunks = 5;
        let max_num_proofs = 128 - 2;

        let mut rng = rand::thread_rng();

        // The priv_id is the hidden common input wire across all proofs
        let priv_id = PrivateId::rand(&mut rng);

        // Generate 5 chunks
        let chunks: Vec<Vec<BlocklistElem<Fr>>> =
            iter::repeat_with(|| gen_blocklist(&mut rng, chunk_size))
                .take(num_chunks)
                .collect();

        let chunk_circuits_and_inputs: Vec<(ChunkNonMembershipCircuit<_, _>, Vec<Fr>)> = chunks
            .iter()
            .map(|chunk| make_blocklist_circuit::<_, FrV>(priv_id, chunk))
            .collect();

        // Generate some toxic waste (i.e., CRS generation secrets that we need to throw away) and
        // use it to make 6 proving/verifying keys for our 6 circuits
        let waste = ToxicWaste::rand(&mut rng);
        let (chunk_pk, chunk_vk) = circuit_specific_setup(
            chunk_circuits_and_inputs.first().unwrap().clone().0,
            &waste,
            &mut rng,
        )
        .unwrap();

        let chunk_proofs: Vec<Proof<Bls12_381>> = chunk_circuits_and_inputs
            .iter()
            .map(|(chunk_circuit, _)| {
                Groth16::prove(&chunk_pk, chunk_circuit.clone(), &mut rng)
                    .expect("couldn't prove chunk")
            })
            .collect();
        let prepared_inputs: Vec<PreparedCircuitInput<Bls12_381>> =
            chunk_circuits_and_inputs
                .iter()
                .map(|(_, input)| {
                    hiciap_preprocess_input(&chunk_vk, input).expect("couldn't preprocess input")
                })
                .collect();

        // The number of proofs has to be two less than a power of two
        let padding_size = max_num_proofs - num_chunks;
        let mut padded_proofs = chunk_proofs;
        padded_proofs
            .extend(iter::repeat(padded_proofs.last().unwrap().clone()).take(padding_size));
        let mut padded_inputs = prepared_inputs;
        padded_inputs
            .extend(iter::repeat(padded_inputs.last().unwrap().clone()).take(padding_size));

        // Now do the HiCIAP setup and proof
        let hiciap_srs_size = max_num_proofs + 2;
        let srs = setup_inner_product::<Blake2s, _, _>(&mut rng, hiciap_srs_size).unwrap();

        let (proof, _) = hiciap_prove::<Blake2s, _, _>(
            &mut rng,
            &chunk_vk,
            &srs,
            &mut padded_proofs,
            Some(&mut padded_inputs),
            priv_id.0,
        )
        .unwrap();

        // Do HiCIAP verification and ensure that a valid proof verifies
        let com_inputs =
            hiciap_pub_input_com(&srs, &padded_inputs).expect("couldn't commit to public inputs");
        // Make sure it verifies with and without CSM
        assert!(hiciap_verify(
            &srs.get_verifier_key(),
            &chunk_vk,
            &padded_inputs,
            &com_inputs,
            &proof,
            true,
        )
        .is_ok());
        assert!(hiciap_verify(
            &srs.get_verifier_key(),
            &chunk_vk,
            &padded_inputs,
            &com_inputs,
            &proof,
            false,
        )
        .is_ok());
    }
}
*/
