//! A no_std Rust library implementing [BIP‑322: Generic Signed Message Format](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki).
//!
//! This crate provides:
//! - Construction of virtual `to_spend` and `to_sign` transactions
//! - Signing and verification for Simple, Full, and Full Proof-of-Funds BIP‑322 formats
//! - Optional “proof of funds” support via additional UTXO inputs
#![no_std]

#[macro_use]
pub extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod error;
pub mod sign;
pub mod utils;
pub mod verify;

pub use error::*;
#[allow(unused_imports)]
pub use sign::*;
pub use utils::*;
pub use verify::*;

use crate::Error;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use bitcoin::{
    Address, Amount, OutPoint, Psbt,
    base64::{Engine, engine::general_purpose},
};

/// Represents the different formats supported by the message signing protocol.
///
/// BIP322 defines multiple formats for signatures to accommodate different use cases
/// and maintain backward compatibility with legacy signing methods.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureFormat {
    /// Legacy Bitcoin Core message signing format (P2PKH only).
    Legacy,
    /// A simplified version of the format that includes only the witness stack.
    Simple,
    /// Full format with complete transaction data.
    Full,
    /// The Full format with Proof-of-funds capabiility.
    FullProofOfFunds,
}

/// Main trait providing signing and verification functionality.
///
/// This trait is implemented for `bdk_wallet::Wallet` to provide seamless
/// integration with BDK wallets.
///
/// # Examples
///
/// ```no_run
/// use bdk_wallet::{Wallet, KeychainKind};
/// use bdk_message_signer::{MessageSigner, SignatureFormat};
///
/// # fn main() -> Result<(), bdk_message_signer::error::Error> {
/// # let mut wallet: Wallet = unimplemented!();
/// let address = wallet.peek_address(KeychainKind::External, 0).address;
///
/// // Sign a message
/// let proof = wallet.sign_message(
///     "Hello Bitcoin",
///     SignatureFormat::Simple,
///     &address,
///     None,
/// )?;
///
/// // Verify the signature
/// let result = wallet.verify_message(
///     &proof,
///     "Hello Bitcoin",
///     &address,
/// )?;
///
/// assert!(result.valid);
/// # Ok(())
/// # }
/// ```
pub trait MessageSigner {
    /// Sign a message for a specific address.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign (as UTF-8 text)
    /// * `signature_type` - The signature format to use
    /// * `address` - The address to sign with (must be owned by wallet)
    /// * `utxos` - Optional list of specific UTXOs for proof-of-funds (only for `FullProofOfFunds`)
    ///
    /// # Returns
    ///
    /// Returns either a complete signature or a PSBT for external signing or [`Error`] when there's an error
    fn sign_message(
        &mut self,
        message: &str,
        signature_type: SignatureFormat,
        address: &Address,
        utxos: Option<Vec<OutPoint>>,
    ) -> Result<MessageProof, Error>;

    /// Verify message signature.
    ///
    /// # Arguments
    ///
    /// * `proof` - The signature proof to verify
    /// * `message` - The original message that was signed
    /// * `signature_type` - The signature format used
    /// * `address` - The address that supposedly signed the message
    ///
    /// # Returns
    ///
    /// Returns verification result with validity and optional proven amount or [`Error`] when there's an error
    fn verify_message(
        &self,
        proof: &MessageProof,
        message: &str,
        address: &Address,
    ) -> Result<MessageVerificationResult, Error>;
}

/// Result of signature verification.
pub struct MessageVerificationResult {
    /// Whether the signature is valid for the given message and address
    pub valid: bool,
    /// The total amount proven for FullProofOfFunds signatures.
    ///
    /// This is `Some` only when using `FullProofOfFunds` format and
    /// additional UTXOs were included. For other formats, always `None`.
    pub proven_amount: Option<Amount>,
}

/// Result of signing operation.
///
/// Signing can result in either a complete signature (when the wallet has
/// private keys) or a PSBT ready for external signing (e.g., hardware wallets).
#[derive(Debug)]
pub enum MessageProof {
    /// Signature was created successfully.
    ///
    /// Contains the base64-encoded signature string ready for sharing.
    Signed(String),
    /// PSBT ready for external signing.
    Psbt(Psbt),
}

impl MessageProof {
    /// Converts the proof to a base64-encoded string.
    pub fn to_base64(&self) -> String {
        match self {
            // Signed proofs are already in base64 format, just return the string
            MessageProof::Signed(s) => s.clone(),
            // For PSBT proofs, serialize and encode to base64
            MessageProof::Psbt(psbt) => general_purpose::STANDARD.encode(psbt.serialize()),
        }
    }

    /// Parses a base64-encoded string into a [`MessageProof`].
    pub fn from_base64(s: &str) -> Result<Self, Error> {
        // Try to decode as PSBT first - this handles the Full and FullProofOfFunds formats
        if let Ok(bytes) = general_purpose::STANDARD.decode(s) {
            if let Ok(psbt) = Psbt::deserialize(&bytes) {
                return Ok(MessageProof::Psbt(psbt));
            }
        }

        // Otherwise, treat it as a signed proof (Legacy or Simple format)
        // The string is already base64 encoded, so we store it as-is
        Ok(MessageProof::Signed(s.to_string()))
    }
}
