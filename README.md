# Hidden Common Input Aggregate Proofs

This repo is the Rust implementation of the HICIAP protocol described by the SNARKBlock anonymous blocklisting system ([paper](https://eprint.iacr.org/2021/1577)). In short, this crate allows you to
1. Aggregate multiple Groth16 proofs into a single succinct aggregate proof
2. Show that each aggregated Groth16 proof shares a common input. This means that you can aggregate proofs of the form "`k` is signed by Bob and `P(k, xᵢ)`" where `k` is the (hidden) common input, `P` is some predicate, and `xᵢ` is the public input to the i-th proof.
3. *Link* multiple aggregate HICIAP proofs together, i.e., show that several HICIAP proofs all use the same `k` value

For example usage, see the `test_hiciap_correctness` test in [`src/hiciap.rs`](src/hiciap.rs).

How to construct compatible Groth16 proofs
------------------------------------------

To use HICIAP, the inputted Groth16 proofs need to have the correct format: the "hidden common input" MUST be **the first public input** to the Groth16 proof. Yes, it's a public input, but it's hidden in the aggregate. Thus, the "prepared public inputs" used by the verifier are all the public inputs besides the first one.

See the `HashPreimageCircuit` in [`src/test_circuit.rs`](src/test_circuit.rs) for a concrete example.

To-do
-----
* Use the optimized GIPA protocol for HMIPP rather than the unoptimized one. This would allow us to only blind log-many elements of C rather than all of them
* Make a nice interface for padding proof inputs
* Make a nice interface for updating HICIAP commitment and verification keys

Warning
-------

This code has not been audited in any sense of the word. Use at your own peril.

License
-------

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
