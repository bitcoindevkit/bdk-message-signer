use bdk_message_signer::{MessageProof, MessageSigner, SignatureFormat, verify_message};
use bdk_wallet::{
    KeychainKind, Wallet,
    bitcoin::{Network, NetworkKind},
    descriptor::IntoWalletDescriptor,
    signer::SignersContainer,
};

const DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/84'/1'/0'/0/*)";
const MESSAGE: &str = "Hello Bitcoin";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut wallet = Wallet::create_single(DESCRIPTOR)
        .network(Network::Signet)
        .create_wallet_no_persist()?;
    let address = wallet.reveal_next_address(KeychainKind::External).address;

    // The caller owns the signers. Build them from the descriptor's private keys.
    let (_, keymap) = DESCRIPTOR.into_wallet_descriptor(wallet.secp_ctx(), NetworkKind::Test)?;
    let signers = SignersContainer::build(
        keymap,
        wallet.public_descriptor(KeychainKind::External),
        wallet.secp_ctx(),
    );

    let signed = wallet.sign_message(&address, MESSAGE, SignatureFormat::Simple, &[&signers])?;
    let MessageProof::Signature(signature) = signed else {
        return Err("a single-key wallet finalizes its own signature".into());
    };
    println!("Address:   {address}");
    println!("Message:   {MESSAGE}");
    println!("Signature: {signature}");

    // Verification needs no wallet, only the address, message and signature.
    let verification = verify_message(&address, MESSAGE, &signature);
    println!("Valid:     {}", verification.is_valid());

    // A different message does not verify.
    assert!(verification.is_valid());
    assert!(verify_message(&address, "Hello Litecoin", &signature).is_invalid());

    Ok(())
}
