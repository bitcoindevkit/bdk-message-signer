# `bdk_message_signer`

**Note:** This crate is experimental.

[BIP-322](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki) message
signing for [`bdk_wallet`](https://docs.rs/bdk_wallet). It adds a `MessageSigner`
method to `Wallet` and builds on the [`bip322`](https://github.com/rust-bitcoin/bip322)
crate for the BIP-322 transactions, PSBT fields and verification.

You pass your own `SignersContainer`s, as with `Wallet::sign_with_signers`. No
private keys are passed to this crate directly.

## SignatureFormat

| Format | Prefix | Addresses |
|---|---|---|
| `SignatureFormat::Simple` | `smp` | Native segwit (P2WPKH, P2WSH, P2TR), no timelocks |
| `SignatureFormat::Full(locks)` | `ful` | Any wallet address |
| `SignatureFormat::ProofOfFunds { utxos, locks }` | `pof` | Any wallet address, plus wallet UTXOs to prove |

Legacy (BIP-137) signing is left out: it has no PSBT, so it would need the raw
private key. `verify_message` still verifies legacy signatures.

## Usage

### Signing

```rust,ignore
use bdk_bip322::{MessageProof, MessageSigner, SignatureFormat};

let address = wallet.reveal_next_address(KeychainKind::External).address;

match wallet.sign_message(&address, "Hello Bitcoin", SignatureFormat::Simple, &[&signers])? {
    MessageProof::Signature(signature) => println!("{signature}"),
    // Not finalized, for example a multisig.
    MessageProof::Psbt(psbt) => { /* pass to the other signers */ }
}
```

Every signature is verified with `bip322` before it is returned.

### Hardware signers and multisig

When the PSBT cannot be finalized, `sign_message` returns it. Pass `&[]` as
`signers` to get it unsigned. It carries the BIP-322 message field, so hardware
signers can show it as a message.

A cosigner's wallet signs it with `sign_message_psbt`. That refuses any PSBT
that is not a BIP-322 signing request for one of its addresses, so it cannot be
tricked into signing a transaction. Show the user the request first:

```rust,ignore
let request = bdk_message_signer::detect_bip322_psbt(&psbt).ok_or("not BIP-322")?;
// Show request.message and the address of request.message_challenge, then:
let signed = cosigner.sign_message_psbt(psbt, &format, &[&cosigner_signers])?;
```

If the PSBT was finalized elsewhere, `bdk_message_signer::encode_signature(&psbt, &format)`
encodes it.

### Verifying

Verification does not need a wallet. `verify_message` reads the format from
the signature's prefix, so it handles every format:

```rust,ignore
let verification = bdk_message_signer::verify_message(&address, "Hello Bitcoin", &signature);
assert!(verification.is_valid());
```

An unprefixed signature is read as legacy for a P2PKH address and as simple
otherwise. `bip322` returns `Inconclusive` for scripts outside its templates,
such as timelocked descriptors; see its README for which script types can
return `Valid`. A proof of funds is checked offline only, so confirm its UTXOs
exist and are unspent before trusting the amount it claims.

## Examples

| Example | Shows |
|---|---|
| `sign_and_verify` | Single-key signing and verification |
| `proof_of_funds` | Proving control of wallet UTXOs |
| `multisig` | A 2-of-2 where each cosigner signs with its own wallet |
| `external_signer` | A watch-only wallet with a hardware or other external signer |

Run one with `cargo run --example sign_and_verify`.

## Minimum Supported Rust Version (MSRV)

Rust 1.85.0 or newer.

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing
Found a bug or have a feature request? [Open an issue](https://github.com/bitcoindevkit/bdk-message-signer/issues).
