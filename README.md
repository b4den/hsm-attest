# HSM attest

A state machine parser for Cavium HSM attestation bundles. See [state_transitions](attest-verify-rs/src/state_transitions.rs) for more information.

## Offline version
You can build a static executable with `cargo build --release --bin hsmattest_bin`, or alternatively just use the WASM client-side only version published at <https://banked.github.io/hsm-attest/wasm>.
