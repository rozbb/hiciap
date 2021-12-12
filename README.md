# Hidden Common Input Aggregate Proofs

This repo is the Rust implementation of the HICIAP protocol described by the SNARKBlock anonymous blocklisting system ([paper](https://eprint.iacr.org/2021/1577)).

For example usage, see the `test_hiciap_correctness` test in [`src/hiciap.rs`](src/hiciap.rs).

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
