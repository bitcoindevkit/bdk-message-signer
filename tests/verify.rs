use bdk_message_signer::{
    Error, MessageSigner, SignatureFormat,
    bip322::{self, LockParams},
    verify_message,
};
use bdk_wallet::{
    bitcoin::{OutPoint, hashes::Hash},
    test_utils::*,
};

mod common;
pub use common::*;

#[test]
fn verify_message_accepts_legacy() {
    // Legacy signing is not offered, but legacy signatures still verify.
    let (_, address, _) = wallet(get_test_pkh());
    let wif = get_test_pkh()
        .trim_start_matches("pkh(")
        .trim_end_matches(')');
    let signature = bip322::sign_legacy_encoded(&address.to_string(), MESSAGE, wif).unwrap();
    assert!(verify(&address, &signature).is_valid());
}

#[test]
fn verify_message_picks_the_format() {
    let (wallet, address, signers) = wallet(get_test_wpkh());
    let signed = wallet
        .sign_message(&address, MESSAGE, SignatureFormat::Simple, &[&signers])
        .unwrap();
    let signature = signature(signed);

    // Signatures made before prefixes are read as simple.
    let unprefixed = signature
        .strip_prefix(bip322::SIMPLE_SIGNATURE_PREFIX)
        .unwrap();
    assert!(verify(&address, unprefixed).is_valid());

    assert!(verify_message(&address, "another message", &signature).is_invalid());
}

#[test]
fn errors() {
    let (wallet, address, signers) = wallet(get_test_wpkh());
    let (_, foreign, _) = self::wallet(get_test_tr_single_sig());

    assert!(matches!(
        wallet.sign_message(&foreign, MESSAGE, SignatureFormat::Simple, &[&signers]),
        Err(Error::AddressNotInWallet)
    ));

    let empty = SignatureFormat::ProofOfFunds {
        utxos: vec![],
        locks: LockParams::default(),
    };
    assert!(matches!(
        wallet.sign_message(&address, MESSAGE, empty, &[&signers]),
        Err(Error::NoProofUtxos)
    ));

    let missing = OutPoint::new(Hash::all_zeros(), 7);
    let format = SignatureFormat::ProofOfFunds {
        utxos: vec![missing],
        locks: LockParams::default(),
    };
    assert!(matches!(
        wallet.sign_message(&address, MESSAGE, format, &[&signers]),
        Err(Error::UtxoNotInWallet(outpoint)) if outpoint == missing
    ));
}
