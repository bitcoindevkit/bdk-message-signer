use bdk_message_signer::{
    MessageProof, MessageSigner, SignatureFormat, detect_bip322_psbt, verify_message,
};
use bdk_wallet::{
    KeychainKind, Wallet,
    bitcoin::{Address, Network, NetworkKind, Psbt},
    descriptor::IntoWalletDescriptor,
    signer::SignersContainer,
};

// Each descriptor holds one private key and the other cosigner's public key.
const ALICE: &str = "wsh(multi(2,tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/0/*,tpubD6NzVbkrYhZ4XS88FM9UegpoPq8MHbNzz5Y8imrsHPVV5Uyhfqe3skHVAaziMyehys4CPCzsB8KQZuYEbmJJ3NQgnhSkfDuAqkW2PGyewpB/0/*))";
const BOB: &str = "wsh(multi(2,tpubD6NzVbkrYhZ4WWGhiCNyq7EUNpoFdcVrxB4SqRUv55oSXHPAt47E5Et1xYM8S5ZqtwPuPZ5j2s1pFALLGg9uK5emMbKqdi8r2B2SRx9oQSk/0/*,tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/0/*))";
const MESSAGE: &str = "Hello Bitcoin";

fn cosigner(
    descriptor: &'static str,
) -> Result<(Wallet, SignersContainer), Box<dyn std::error::Error>> {
    let wallet = Wallet::create_single(descriptor)
        .network(Network::Signet)
        .create_wallet_no_persist()?;
    let (_, keymap) = descriptor.into_wallet_descriptor(wallet.secp_ctx(), NetworkKind::Test)?;
    let signers = SignersContainer::build(
        keymap,
        wallet.public_descriptor(KeychainKind::External),
        wallet.secp_ctx(),
    );
    Ok((wallet, signers))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (mut alice, alice_signers) = cosigner(ALICE)?;
    let (bob, bob_signers) = cosigner(BOB)?;
    let address = alice.reveal_next_address(KeychainKind::External).address;
    let format = SignatureFormat::Simple;

    // Alice signs first. One signature cannot finalize a 2-of-2, so she gets
    // the partially signed PSBT back.
    let signed = alice.sign_message(&address, MESSAGE, format.clone(), &[&alice_signers])?;
    let MessageProof::Psbt(psbt) = signed else {
        return Err("one key cannot finalize a 2-of-2".into());
    };

    // She sends it to Bob as a base64 string.
    let sent = psbt.to_string();
    let psbt: Psbt = sent.parse()?;

    // Bob checks what he is asked to sign before he signs.
    let request = detect_bip322_psbt(&psbt).ok_or("not a BIP-322 signing request")?;
    println!("Message: {}", String::from_utf8(request.message)?);
    println!(
        "Address: {}",
        Address::from_script(&request.message_challenge, Network::Signet)?
    );

    // Bob adds his signature. His wallet finalizes and encodes the result.
    let signed = bob.sign_message_psbt(psbt, &format, &[&bob_signers])?;
    let MessageProof::Signature(signature) = signed else {
        return Err("two signatures finalize a 2-of-2".into());
    };
    println!("Signature: {signature}");

    let verification = verify_message(&address, MESSAGE, &signature);
    println!("Valid: {}", verification.is_valid());
    assert!(verification.is_valid());

    Ok(())
}
