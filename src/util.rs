use std::io::Write;

use ark_ec::group::Group;
use ark_ff::Field;
use ark_std::rand::SeedableRng;
use merlin::Transcript;
use rand_chacha::ChaCha20Rng;

// A nothing-up-my-sleeve seed for generating Pedersen bases
const PEDERSEN_SEED: &[u8] = b"HiCIAP-gen-pedersen";

/// Uses the given protocol transcript to create a challenge field element
pub(crate) fn get_field_chal<F>(label: &'static [u8], transcript: &mut Transcript) -> F
where
    F: Field,
{
    // Hash the transcript into a 256 bit RNG seed
    let mut seed = [0u8; 32];
    transcript.challenge_bytes(label, &mut seed);

    // Use the seed to get a random field element
    let mut seeded_rng = ChaCha20Rng::from_seed(seed.into());
    F::rand(&mut seeded_rng)
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
