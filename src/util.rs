use std::io::Write;

use ark_ec::group::Group;
use ark_ff::Field;
use ark_std::rand::SeedableRng;
use blake2::{Blake2s, Digest};
use rand_chacha::ChaCha20Rng;

// A nothing-up-my-sleeve seed for generating Pedersen bases
const PEDERSEN_SEED: &[u8] = b"HiCIAP-gen-pedersen";
// Domain separator for hash-to-field
const HASH_TO_FIELD_DOMAIN_STR: &[u8] = b"HiCIAP-h";

// The digest use for hash-to-field is Blake2s, since it has 32-byte digests which is exactly the
// seed size for ChaCha20Rng.
type D = Blake2s;

/// Returns a deterministically generated field element from the given input
pub fn hash_to_field<F>(input: &[u8]) -> F
where
    F: Field,
{
    // Hash the input into an RNG seed
    let mut hasher = D::with_params(&[], HASH_TO_FIELD_DOMAIN_STR, &[]);
    hasher.update(input);
    let seed = hasher.finalize();

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
