use bdk_wallet::{bitcoin::OutPoint, miniscript, signer::SignerError};
use core::fmt;

/// Errors from [`MessageSigner`](crate::MessageSigner) and [`encode_signature`](crate::encode_signature).
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The address does not belong to the wallet.
    AddressNotInWallet,
    /// The UTXO is not an unspent output of the wallet.
    UtxoNotInWallet(OutPoint),
    /// The simple format requires a native segwit address and no timelocks.
    SimpleNotSupported,
    /// The PSBT is not a BIP-322 signing request.
    NotBip322Psbt,
    /// A proof input's prevout in the PSBT does not match the wallet's UTXO.
    ProofUtxoMismatch(OutPoint),
    /// The format does not match the PSBT's number of inputs.
    FormatMismatch,
    /// A proof of funds needs at least one UTXO.
    NoProofUtxos,
    /// The PSBT has inputs without final scripts.
    NotFinalized,
    /// The wallet descriptor could not produce a script.
    Descriptor(miniscript::Error),
    /// The BIP-322 PSBT could not be built.
    Bip322(bip322::Error),
    /// The wallet failed to sign.
    Signer(SignerError),
    /// The produced signature failed verification.
    InvalidSignature(bip322::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AddressNotInWallet => write!(f, "address does not belong to the wallet"),
            Self::UtxoNotInWallet(outpoint) => write!(f, "{outpoint} is not a wallet UTXO"),
            Self::SimpleNotSupported => {
                write!(
                    f,
                    "simple format requires a native segwit address and no timelocks"
                )
            }
            Self::NotBip322Psbt => write!(f, "PSBT is not a BIP-322 signing request"),
            Self::FormatMismatch => write!(f, "format does not match the PSBT"),
            Self::ProofUtxoMismatch(outpoint) => {
                write!(f, "prevout of {outpoint} does not match the wallet")
            }
            Self::NoProofUtxos => write!(f, "proof of funds needs at least one UTXO"),
            Self::NotFinalized => write!(f, "PSBT is not finalized"),
            Self::Descriptor(error) => write!(f, "descriptor: {error}"),
            Self::Bip322(error) => write!(f, "bip322: {error}"),
            Self::Signer(error) => write!(f, "signer: {error}"),
            Self::InvalidSignature(error) => write!(f, "signature failed verification: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Descriptor(error) => Some(error),
            Self::Bip322(error) | Self::InvalidSignature(error) => Some(error),
            Self::Signer(error) => Some(error),
            _ => None,
        }
    }
}

impl From<miniscript::Error> for Error {
    fn from(error: miniscript::Error) -> Self {
        Self::Descriptor(error)
    }
}

impl From<bip322::Error> for Error {
    fn from(error: bip322::Error) -> Self {
        Self::Bip322(error)
    }
}

impl From<SignerError> for Error {
    fn from(error: SignerError) -> Self {
        Self::Signer(error)
    }
}
