# HSM attest

A state machine parser for Cavium attestation bundles.

## Offline version
You can build a static executable with `cargo build --release --bin hsmattest_bin`, and run `hsmattest_bin <attestation.dat>` or alternatively just use the WASM client-side only version published at <https://b4den.github.io/hsm-attest/wasm/>.
