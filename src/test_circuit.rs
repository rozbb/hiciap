use core::marker::PhantomData;

use ark_crypto_primitives::crh::{constraints::CRHGadget, CRH};
use ark_ff::{to_bytes, Field, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::ToBytesGadget,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use arkworks_gadgets::poseidon::{
    constraints::{CRHGadget as PoseidonGadget, PoseidonParametersVar},
    PoseidonParameters, Rounds as PoseidonRounds, CRH as PoseidonCRH,
};

/// A simple preimage circuit that takes a single hidden input, representing the preimage of a
/// hash, a public input representing the hash, and then an arbitrary number of public inputs which
/// all must be 0. Since this is HiCIAP-compatible, the hidden input is represented as a public
/// input.
#[derive(Clone)]
pub(crate) struct HashPreimageCircuit<ConstraintF, P>
where
    ConstraintF: Field,
    P: PoseidonRounds,
{
    num_extra_inputs: usize,
    // Hidden common input
    preimage: Option<ConstraintF>,
    // Public inputs
    expected_hash: ConstraintF,
    extra_inputs: Option<Vec<ConstraintF>>,
    // Constant
    hash_params: PoseidonParameters<ConstraintF>,
    // Marker
    _marker: PhantomData<P>,
}

impl<ConstraintF, P> ConstraintSynthesizer<ConstraintF> for HashPreimageCircuit<ConstraintF, P>
where
    ConstraintF: PrimeField,
    P: PoseidonRounds,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // Get the Poseidon parameters. This is a constant, not an input
        let params_var =
            PoseidonParametersVar::new_constant(ns!(cs, "poseidon param"), &self.hash_params)?;

        // Get the preimage and convert it to bytes
        let preimage_var = FpVar::<ConstraintF>::new_input(ns!(cs, "preimage"), || {
            self.preimage
                .as_ref()
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let preimage_bytes_var = preimage_var.to_bytes()?;

        // Get the expected output
        let expected_hash_var =
            FpVar::<ConstraintF>::new_input(ns!(cs, "image"), || Ok(self.expected_hash))?;

        // Hash the input and assert it equals the expected output
        let hash_var =
            PoseidonGadget::<ConstraintF, P>::evaluate(&params_var, &preimage_bytes_var)?;
        expected_hash_var.enforce_equal(&hash_var)?;

        // Make all the extra input vars
        let extra_input_vars: Vec<FpVar<ConstraintF>> = match self.extra_inputs {
            Some(inputs) => {
                assert_eq!(inputs.len(), self.num_extra_inputs);
                inputs
                    .iter()
                    .map(|v| FpVar::<ConstraintF>::new_input(ns!(cs, "extra input"), || Ok(v)))
                    .collect()
            }
            None => (0..self.num_extra_inputs)
                .map(|_| {
                    FpVar::<ConstraintF>::new_input(ns!(cs, "extra input"), || {
                        let v: Result<ConstraintF, SynthesisError> =
                            Err(SynthesisError::AssignmentMissing);
                        v
                    })
                })
                .collect::<Result<Vec<_>, SynthesisError>>(),
        }?;

        // Now assert all the extra input vars are 0
        let zero_var = FpVar::<ConstraintF>::zero();
        for v in extra_input_vars {
            v.enforce_equal(&zero_var)?;
        }

        Ok(())
    }
}

fn compute_hash<F, P>(params: &PoseidonParameters<F>, preimage: &F) -> F
where
    F: PrimeField,
    P: PoseidonRounds,
{
    let hash_input = to_bytes![preimage].unwrap();
    PoseidonCRH::<F, P>::evaluate(params, &hash_input).unwrap()
}

#[cfg(test)]
mod test {
    use super::*;

    use core::marker::PhantomData;

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::ToConstraintField;
    use ark_groth16::{
        generator::generate_random_parameters,
        prover::create_random_proof,
        verifier::{prepare_verifying_key, verify_proof},
    };
    use ark_relations::r1cs::{ConstraintSystem, OptimizationGoal};
    use ark_std::{UniformRand, Zero};
    use arkworks_gadgets::setup::common::{
        setup_params_x5_3 as setup_params, Curve, PoseidonRounds_x5_3 as PoseidonRounds,
    };

    const NUM_EXTRA_INPUTS: usize = 10;

    // Tests that a correctly constructed HashPreimageCircuit will satisfy its constraints
    #[test]
    fn test_correctness() {
        let mut rng = ark_std::test_rng();

        let hash_params = setup_params::<Fr>(Curve::Bls381);
        let preimage = Fr::rand(&mut rng);
        let hash = compute_hash::<_, PoseidonRounds>(&hash_params, &preimage);
        let zeros = vec![Fr::zero(); NUM_EXTRA_INPUTS];

        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        let circuit = HashPreimageCircuit::<_, PoseidonRounds> {
            num_extra_inputs: NUM_EXTRA_INPUTS,
            preimage: Some(preimage),
            expected_hash: hash,
            extra_inputs: Some(zeros),
            hash_params,
            _marker: PhantomData,
        };
        circuit.generate_constraints(cs.clone()).unwrap();

        println!("num constraints: {}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());
    }

    // Same as above but runs a Groth16 prover and verifier
    #[test]
    fn test_groth16_correctness() {
        let mut rng = ark_std::test_rng();

        let hash_params = setup_params::<Fr>(Curve::Bls381);
        let preimage = Fr::rand(&mut rng);
        let hash = compute_hash::<_, PoseidonRounds>(&hash_params, &preimage);
        let zeros = vec![Fr::zero(); NUM_EXTRA_INPUTS];

        // This is the circuit we'll prove
        let real_circuit = HashPreimageCircuit::<_, PoseidonRounds> {
            num_extra_inputs: NUM_EXTRA_INPUTS,
            preimage: Some(preimage),
            expected_hash: hash,
            extra_inputs: Some(zeros.clone()),
            hash_params: hash_params.clone(),
            _marker: PhantomData,
        };
        // This is a placeholder circuit used for CRS generation. It contains no secrets.
        let param_gen_circuit = HashPreimageCircuit::<_, PoseidonRounds> {
            num_extra_inputs: NUM_EXTRA_INPUTS,
            preimage: None,
            expected_hash: hash,
            extra_inputs: None,
            hash_params,
            _marker: PhantomData,
        };

        // Generate the CRS
        let pk =
            generate_random_parameters::<Bls12_381, _, _>(param_gen_circuit, &mut rng).unwrap();
        let pvk = prepare_verifying_key(&pk.vk);

        // Compute the proof
        let proof =
            create_random_proof::<Bls12_381, _, _>(real_circuit.clone(), &pk, &mut rng).unwrap();

        // Verify the proof
        let public_inputs = [
            preimage.to_field_elements().unwrap(),
            hash.to_field_elements().unwrap(),
            zeros,
        ]
        .concat();
        assert!(verify_proof(&pvk, &proof, &public_inputs).unwrap());
    }
}
