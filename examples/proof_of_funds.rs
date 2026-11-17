use bdk_message_signer::{
    LockParams, MessageProof, MessageSigner, SignatureFormat, verify_message,
};
use bdk_wallet::{
    KeychainKind,
    bitcoin::{Amount, NetworkKind, OutPoint},
    descriptor::IntoWalletDescriptor,
    signer::SignersContainer,
    test_utils::get_funded_wallet_single,
};

const DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/84'/1'/0'/0/*)";
const MESSAGE: &str = "I control these coins";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A real wallet learns its UTXOs by syncing with a chain source. This
    // example uses bdk_wallet's test helper to fund a regtest wallet in memory.
    let (mut wallet, _) = get_funded_wallet_single(DESCRIPTOR);
    let address = wallet.reveal_next_address(KeychainKind::External).address;

    let (_, keymap) = DESCRIPTOR.into_wallet_descriptor(wallet.secp_ctx(), NetworkKind::Test)?;
    let signers = SignersContainer::build(
        keymap,
        wallet.public_descriptor(KeychainKind::External),
        wallet.secp_ctx(),
    );

    // Choose the UTXOs to prove. Here, all of them.
    let utxos: Vec<OutPoint> = wallet.list_unspent().map(|utxo| utxo.outpoint).collect();
    let amount: Amount = wallet.list_unspent().map(|utxo| utxo.txout.value).sum();
    println!("Proving {} UTXO(s) worth {amount}", utxos.len());

    let format = SignatureFormat::ProofOfFunds {
        utxos,
        locks: LockParams::default(),
    };
    let signed = wallet.sign_message(&address, MESSAGE, format, &[&signers])?;
    let MessageProof::Signature(proof) = signed else {
        return Err("a single-key wallet finalizes its own proof".into());
    };
    println!("Proof: {proof}");

    // This check is offline. It proves the signer can spend the listed
    // outputs. The verifier must still check on chain that they exist, are
    // unspent and hold the claimed amounts.
    let verification = verify_message(&address, MESSAGE, &proof);
    println!("Valid: {}", verification.is_valid());
    assert!(verification.is_valid());

    Ok(())
}
