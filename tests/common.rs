use bdk_message_signer::{
    MessageProof, MessageSigner, SignatureFormat, bip322::Verification, verify_message,
};
use bdk_wallet::{
    KeychainKind, Wallet,
    bitcoin::{
        Address, Network, NetworkKind,
        bip32::{Xpriv, Xpub},
        secp256k1::Secp256k1,
    },
    descriptor::IntoWalletDescriptor,
    signer::SignersContainer,
};
use core::str::FromStr;

pub const MESSAGE: &str = "Hello World";
pub const TPRV_A: &str = "tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS";
pub const TPRV_B: &str = "tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L";

pub fn tpub(tprv: &str) -> String {
    Xpub::from_priv(&Secp256k1::new(), &Xpriv::from_str(tprv).unwrap()).to_string()
}

/// Signers for the private keys in `descriptor`, owned by the caller.
pub fn signers(wallet: &Wallet, descriptor: &str) -> SignersContainer {
    let (_, keymap) = descriptor
        .into_wallet_descriptor(wallet.secp_ctx(), NetworkKind::Test)
        .unwrap();
    SignersContainer::build(
        keymap,
        wallet.public_descriptor(KeychainKind::External),
        wallet.secp_ctx(),
    )
}

pub fn wallet(descriptor: &str) -> (Wallet, Address, SignersContainer) {
    let mut wallet = Wallet::create_single(descriptor.to_string())
        .network(Network::Regtest)
        .create_wallet_no_persist()
        .unwrap();
    let address = wallet.reveal_next_address(KeychainKind::External).address;
    let signers = signers(&wallet, descriptor);
    (wallet, address, signers)
}

pub fn verify(address: &Address, signature: &str) -> Verification {
    verify_message(address, MESSAGE, signature)
}

pub fn signature(signed: MessageProof) -> String {
    match signed {
        MessageProof::Signature(signature) => signature,
        MessageProof::Psbt(_) => panic!("expected a finalized signature"),
    }
}

pub fn assert_valid(
    wallet: &Wallet,
    address: &Address,
    signers: &SignersContainer,
    format: SignatureFormat,
    prefix: &str,
) {
    let signed = wallet
        .sign_message(address, MESSAGE, format, &[signers])
        .unwrap();
    let signature = signature(signed);
    assert!(signature.starts_with(prefix), "{signature}");
    let verification = verify(address, &signature);
    assert!(verification.is_valid(), "{verification:?}");
}
