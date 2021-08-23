use std::io::Write;

use ark_ec::group::Group;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use rand_chacha::ChaCha20Rng;

// A nothing-up-my-sleeve seed for generating Pedersen bases
const PEDERSEN_SEED: &[u8] = b"HiCIAP-gen-pedersen";

// Convenience functions for generateing Fiat-Shamir challenges
pub(crate) trait TranscriptProtocol {
    /// Appends a CanonicalSerialize-able element to the transcript. Panics on serialization error.
    fn append_serializable<S>(&mut self, label: &'static [u8], val: &S)
    where
        S: CanonicalSerialize + ?Sized;

    /// Produces a pseudorandom field element from the current transcript
    fn challenge_scalar<F: PrimeField>(&mut self, label: &'static [u8]) -> F;
}

impl TranscriptProtocol for merlin::Transcript {
    /// Appends a CanonicalSerialize-able element to the transcript. Panics on serialization error.
    fn append_serializable<S>(&mut self, label: &'static [u8], val: &S)
    where
        S: CanonicalSerialize + ?Sized,
    {
        // Serialize the input and give it to the transcript
        let mut buf = Vec::new();
        val.serialize(&mut buf)
            .expect("serialization error in transcript");
        self.append_message(label, &buf);
    }

    /// Produces a pseudorandom field element from the current transcript
    fn challenge_scalar<F: PrimeField>(&mut self, label: &'static [u8]) -> F {
        // Fill a buf with random bytes
        let mut buf = <<StdRng as SeedableRng>::Seed as Default>::default();
        self.challenge_bytes(label, &mut buf);

        // Use the buf to make an RNG. Then use that RNG to generate a field element
        let mut rng = StdRng::from_seed(buf);
        F::rand(&mut rng)
    }
}

/// Returns `num_gens` many deterministic unrelated group elements. This is used to construct
/// bases for Pedersen commitments.
pub fn get_pedersen_generators<G>(num_gens: usize) -> Vec<G>
where
    G: Group,
{
    // Construct the RNG seed
    let mut seed = [0u8; 32];
    {
        let mut writer = &mut seed[..];
        writer.write(PEDERSEN_SEED).unwrap();
    }
    let mut seeded_rng = ChaCha20Rng::from_seed(seed);

    // Use the seed to generate the desired number of unrelated group elements
    (0..num_gens).map(|_| G::rand(&mut seeded_rng)).collect()
}
