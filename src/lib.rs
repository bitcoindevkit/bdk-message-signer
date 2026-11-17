//! BIP-322 message signing for [`bdk_wallet`], built on the [`bip322`] crate.
//!
//! [`MessageSigner::sign_message`] builds the BIP-322 PSBT with
//! [`bip322::create_bip322_psbt`], signs it with the signers you pass,
//! finalizes it with the wallet, and encodes the result.
//!
//! Verification needs no wallet: use [`verify_message`], or the typed
//! [`verify_simple`], [`verify_full`], [`verify_pof`] and [`verify_legacy`].
//!
//! [`finalize_bip322_psbt`] is bip322's own finalizer. It handles the standard
//! script types and returns a `ful` or `pof` signature. For other descriptors,
//! or for `smp`, finalize with [`MessageSigner::sign_message_psbt`] instead.
//!
//! The rest of [`bip322`] is re-exported as a module.

pub use bip322::{
    self, Bip322Psbt, FULL_SIGNATURE_PREFIX, LockParams, POF_SIGNATURE_PREFIX,
    SIMPLE_SIGNATURE_PREFIX, Verification, detect_bip322_psbt, finalize_bip322_psbt, verify_full,
    verify_legacy, verify_pof, verify_simple,
};

mod error;
mod sign;
mod verify;
pub use error::*;
pub use sign::*;
pub use verify::*;

use bdk_wallet::{
    bitcoin::{Address, OutPoint, Psbt},
    signer::SignersContainer,
};

/// BIP-322 signature format.
#[derive(Debug, Clone)]
pub enum SignatureFormat {
    /// Witness only, prefixed `smp`. Native segwit addresses only, no timelocks.
    Simple,
    /// The full `to_sign` transaction, prefixed `ful`.
    Full(LockParams),
    /// A finalized PSBT proving control of wallet UTXOs, prefixed `pof`.
    ProofOfFunds {
        /// Wallet UTXOs to prove. At least one.
        utxos: Vec<OutPoint>,
        /// Timelocks of `to_sign`.
        locks: LockParams,
    },
}

/// Result of [`MessageSigner::sign_message`].
#[derive(Debug, Clone)]
pub enum MessageProof {
    /// The encoded signature.
    Signature(String),
    /// The PSBT could not be finalized, for example in a multisig or with no
    /// signers.
    ///
    /// Pass it to the other signers, for example with
    /// [`MessageSigner::sign_message_psbt`].
    Psbt(Psbt),
}

/// BIP-322 message signing for a [`Wallet`](bdk_wallet::Wallet).
pub trait MessageSigner {
    /// Signs `message` for `address`, which must belong to the wallet.
    ///
    /// Pass no `signers` to get the unsigned PSBT, for example for a hardware
    /// signer. Returns [`MessageProof::Psbt`] if the PSBT could not be finalized.
    fn sign_message(
        &self,
        address: &Address,
        message: &str,
        format: SignatureFormat,
        signers: &[&SignersContainer],
    ) -> Result<MessageProof, Error>;

    /// Signs a BIP-322 PSBT from another party, for example a multisig cosigner,
    /// or finalizes one a hardware signer has signed (pass no `signers`).
    ///
    /// Refuses any PSBT that is not a BIP-322 signing request for a wallet
    /// address, so it cannot sign a transaction. Before calling it, show the
    /// user the message and address from [`bip322::detect_bip322_psbt`]. For a
    /// proof of funds, also show the UTXOs in inputs 1 and later: signing proves
    /// the wallet controls them.
    fn sign_message_psbt(
        &self,
        psbt: Psbt,
        format: &SignatureFormat,
        signers: &[&SignersContainer],
    ) -> Result<MessageProof, Error>;
}
