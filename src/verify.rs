use bdk_wallet::bitcoin::{Address, Sequence, absolute::LockTime};
use bip322::{FULL_SIGNATURE_PREFIX, POF_SIGNATURE_PREFIX, SIMPLE_SIGNATURE_PREFIX, Verification};

use crate::Error;

/// Verifies a BIP-322 signature of `message` for `address`.
///
/// The prefix picks the format: `smp`, `ful` or `pof`. An unprefixed
/// signature is legacy (BIP-137) for a P2PKH address and simple otherwise, as
/// BIP-322 allows for signatures made before prefixes.
pub fn verify_message(address: &Address, message: &str, signature: &str) -> Verification {
    let encoded_address = address.to_string();
    let address_str = encoded_address.as_str();

    if signature.starts_with(FULL_SIGNATURE_PREFIX) {
        bip322::verify_full_encoded(address_str, message, signature)
    } else if signature.starts_with(POF_SIGNATURE_PREFIX) {
        bip322::verify_pof_encoded(address_str, message, signature)
    } else if signature.starts_with(SIMPLE_SIGNATURE_PREFIX) || !address.script_pubkey().is_p2pkh()
    {
        bip322::verify_simple_encoded(address_str, message, signature)
    } else {
        match bip322::verify_legacy_encoded(address_str, message, signature) {
            Ok(()) => Verification::Valid {
                time: LockTime::ZERO,
                age: Sequence::ZERO,
            },
            Err(error) => Verification::Invalid(error),
        }
    }
}

/// Verifies a signature produced.
///
/// # Errors
///
/// [`Error::InvalidSignature`] if the signature is invalid.
pub(crate) fn check_signature(
    address: &Address,
    message: &str,
    signature: &str,
) -> Result<(), Error> {
    match verify_message(address, message, signature) {
        Verification::Invalid(error) => Err(Error::InvalidSignature(error)),
        _ => Ok(()),
    }
}
