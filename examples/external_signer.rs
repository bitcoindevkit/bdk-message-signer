use bdk_message_signer::{
    MessageProof, MessageSigner, SignatureFormat, bip322::sign_bip322_psbt_input,
    detect_bip322_psbt, verify_message,
};
use bdk_wallet::{
    KeychainKind, Wallet,
    bitcoin::{
        Network, Psbt,
        bip32::{DerivationPath, Xpriv},
        secp256k1::Secp256k1,
    },
};
use core::str::FromStr;

// The wallet only knows the public key.
const DESCRIPTOR: &str = "wpkh(tpubD6NzVbkrYhZ4WWGhiCNyq7EUNpoFdcVrxB4SqRUv55oSXHPAt47E5Et1xYM8S5ZqtwPuPZ5j2s1pFALLGg9uK5emMbKqdi8r2B2SRx9oQSk/0/*)";
// The external signer holds the private key.
const DEVICE_KEY: &str = "tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS";
const MESSAGE: &str = "Hello Bitcoin";

/// Stands in for the device. A real one would show the message and address on
/// its screen and wait for the user to confirm.
fn device_sign(psbt: &mut Psbt) -> Result<(), Box<dyn std::error::Error>> {
    let request = detect_bip322_psbt(psbt).ok_or("not a BIP-322 signing request")?;
    println!("Device shows: {}", String::from_utf8(request.message)?);

    // The key for the wallet's first address, at m/0/0.
    let key = Xpriv::from_str(DEVICE_KEY)?
        .derive_priv(&Secp256k1::new(), &DerivationPath::from_str("m/0/0")?)?
        .to_priv();
    sign_bip322_psbt_input(psbt, &key, 0)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut wallet = Wallet::create_single(DESCRIPTOR)
        .network(Network::Signet)
        .create_wallet_no_persist()?;
    let address = wallet.reveal_next_address(KeychainKind::External).address;
    let format = SignatureFormat::Simple;

    // With no signers, the wallet returns the unsigned BIP-322 PSBT.
    let signed = wallet.sign_message(&address, MESSAGE, format.clone(), &[])?;
    let MessageProof::Psbt(mut psbt) = signed else {
        return Err("nothing signed, nothing to finalize".into());
    };

    device_sign(&mut psbt)?;

    // The wallet finalizes the signed PSBT and encodes the signature. If the
    // device returns a finalized PSBT, use `bdk_bip322::encode_signature`.
    let signed = wallet.sign_message_psbt(psbt, &format, &[])?;
    let MessageProof::Signature(signature) = signed else {
        return Err("the device signature finalizes a single-key address".into());
    };
    println!("Signature: {signature}");

    let verification = verify_message(&address, MESSAGE, &signature);
    println!("Valid: {}", verification.is_valid());
    assert!(verification.is_valid());

    Ok(())
}
