//! The signature generation implementation for message signing
//! according to the BIP-322 standard.

use crate::{
    Error, MessageProof, MessageSigner, MessageVerificationResult, SignatureFormat,
    configure_p2sh_input, derive_tx_params, to_sign, to_spend, validate_witness, verify_psbt_proof,
    verify_signed_proof,
};
use alloc::{string::ToString, vec::Vec};

use bdk_wallet::{SignOptions, Wallet};
use bitcoin::{
    Address, EcdsaSighashType, OutPoint, Psbt, ScriptBuf, Sequence, TapSighashType, Transaction,
    TxIn, Witness,
    absolute::LockTime,
    base64::{Engine, engine::general_purpose},
    consensus::Encodable,
    psbt::PsbtSighashType,
    transaction::Version,
};

impl MessageSigner for Wallet {
    fn sign_message(
        &mut self,
        message: &str,
        signature_type: SignatureFormat,
        address: &Address,
        utxos: Option<Vec<OutPoint>>,
    ) -> Result<MessageProof, Error> {
        if signature_type == SignatureFormat::Legacy {
            return Err(Error::InvalidFormat(
                "Legacy format is verify-only. Use Simple or Full for P2PKH addresses".to_string(),
            ));
        }

        let script_pubkey = address.script_pubkey();
        let to_spend = to_spend(&script_pubkey, message);

        let (version, lock_time, sequence) = match signature_type {
            SignatureFormat::Simple => (Version(0), LockTime::ZERO, Sequence::ZERO),
            SignatureFormat::Full | SignatureFormat::FullProofOfFunds => {
                derive_tx_params(self, &script_pubkey)
            }
            SignatureFormat::Legacy => unreachable!(),
        };

        let mut to_sign = to_sign(&to_spend, version, lock_time, sequence);

        // Handle proof-of-funds by adding additional inputs
        if signature_type == SignatureFormat::FullProofOfFunds {
            let specific_utxos = utxos.ok_or(Error::InvalidFormat(
                "UTXOs must be provided for FullProofOfFunds format".to_string(),
            ))?;
            add_proof_of_funds_inputs(&mut to_sign, self, &specific_utxos)?;
        } else if utxos.is_some() {
            return Err(Error::InvalidFormat(
                "UTXOs parameter only supported for FullProofOfFunds format".to_string(),
            ));
        }

        let mut psbt = Psbt::from_unsigned_tx(to_sign)?;

        configure_psbt_inputs(&mut psbt, self, &script_pubkey, &to_spend)?;

        let sign_options = SignOptions {
            trust_witness_utxo: true,
            ..Default::default()
        };

        let finalized = self.sign(&mut psbt, sign_options.clone())?;

        if finalized {
            encode_signature(&psbt, signature_type, &script_pubkey)
        } else {
            Ok(MessageProof::Psbt(psbt))
        }
    }

    fn verify_message(
        &self,
        proof: &MessageProof,
        message: &str,
        address: &Address,
    ) -> Result<MessageVerificationResult, Error> {
        match proof {
            MessageProof::Signed(signature_base64) => {
                verify_signed_proof(self, message, address, signature_base64)
            }
            MessageProof::Psbt(psbt) => {
                // If every input is finalized, extract and do full cryptographic verification
                let is_finalized = psbt.inputs.iter().all(|input| {
                    input.final_script_witness.is_some() || input.final_script_sig.is_some()
                });

                if is_finalized {
                    let tx = psbt.clone().extract_tx()?;
                    let mut buf = Vec::new();
                    tx.consensus_encode(&mut buf)?;
                    let signature_base64 = general_purpose::STANDARD.encode(&buf);
                    verify_signed_proof(self, message, address, &signature_base64)
                } else {
                    // Unfinalized PSBT: structural validation + amount check only.
                    // Cryptographic signatures are NOT verified in this path.
                    verify_psbt_proof(psbt, message, address)
                }
            }
        }
    }
}

/// Adds proof-of-funds inputs to the to_sign transaction.
///
/// Collects UTXOs belonging to the signing address and adds them as
/// additional inputs to prove control over funds.
fn add_proof_of_funds_inputs(
    to_sign: &mut Transaction,
    wallet: &Wallet,
    utxos: &[OutPoint],
) -> Result<(), Error> {
    if utxos.is_empty() {
        return Err(Error::InvalidFormat(
            "No UTXOs available for proof-of-funds".to_string(),
        ));
    }

    // Add each UTXO as an input
    for &outpoint in utxos {
        let _utxo = wallet
            .get_utxo(outpoint)
            .ok_or(Error::UtxoNotFound(outpoint))?;

        if to_sign.input.iter().any(|i| i.previous_output == outpoint) {
            return Err(Error::InvalidFormat(format!(
                "Duplicate proof-of-funds input: {}",
                outpoint
            )));
        }

        to_sign.input.push(TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        });
    }

    Ok(())
}

/// Configures PSBT inputs with necessary witness/non-witness UTXO data.
///
/// Resolves each input's script type and derivation independently, supporting
/// mixed script types across proof-of-funds inputs.
fn configure_psbt_inputs(
    psbt: &mut Psbt,
    wallet: &Wallet,
    script_pubkey: &ScriptBuf,
    to_spend: &Transaction,
) -> Result<(), Error> {
    for (i, (psbt_input, tx_input)) in psbt
        .inputs
        .iter_mut()
        .zip(psbt.unsigned_tx.input.iter())
        .enumerate()
    {
        // Resolve the prevout and derivation for this specific input
        let (txout, input_spk, keychain, derivation_index) = if i == 0 {
            let (kc, idx) =
                wallet
                    .derivation_of_spk(script_pubkey.clone())
                    .ok_or(Error::InvalidFormat(
                        "Address not found in wallet".to_string(),
                    ))?;
            (to_spend.output[0].clone(), script_pubkey.clone(), kc, idx)
        } else {
            let utxo = wallet
                .get_utxo(tx_input.previous_output)
                .ok_or(Error::UtxoNotFound(tx_input.previous_output))?;
            let spk = utxo.txout.script_pubkey.clone();
            let (kc, idx) = wallet
                .derivation_of_spk(spk.clone())
                .ok_or(Error::InvalidFormat(
                    "Proof-of-funds UTXO not owned by wallet".to_string(),
                ))?;
            (utxo.txout, spk, kc, idx)
        };

        psbt_input.sighash_type = if input_spk.is_p2tr() {
            Some(PsbtSighashType::from(TapSighashType::All))
        } else {
            Some(PsbtSighashType::from(EcdsaSighashType::All))
        };

        let descriptor = wallet.public_descriptor(keychain);
        let derived_descriptor = descriptor
            .at_derivation_index(derivation_index)
            .map_err(|e| Error::InvalidFormat(e.to_string()))?;

        if input_spk.is_p2tr() || input_spk.is_p2wpkh() {
            psbt_input.witness_utxo = Some(txout);
        } else if input_spk.is_p2wsh() {
            psbt_input.witness_utxo = Some(txout);

            let script = derived_descriptor
                .explicit_script()
                .map_err(|e| Error::InvalidFormat(e.to_string()))?;
            psbt_input.witness_script = Some(script);
        } else if script_pubkey.is_p2sh() {
            psbt_input.witness_utxo = Some(txout);
            configure_p2sh_input(psbt_input, &derived_descriptor)?;
        } else if input_spk.is_p2pkh() {
            // P2PKH requires full transaction as non-witness UTXO
            if i == 0 {
                psbt_input.non_witness_utxo = Some(to_spend.clone());
            } else {
                let tx = wallet
                    .get_tx(tx_input.previous_output.txid)
                    .ok_or(Error::TransactionNotFound(tx_input.previous_output.txid))?;
                psbt_input.non_witness_utxo = Some(tx.tx_node.tx.as_ref().clone());
            }
        } else {
            return Err(Error::UnsupportedScriptType(alloc::format!(
                "Unsupported script type for input {}",
                i
            )));
        }
    }

    Ok(())
}

/// Encodes the finalized signature according to the signature format.
///
/// Extracts the appropriate data from the signed PSBT and encodes it
/// as a base64 string.
fn encode_signature(
    psbt: &Psbt,
    signature_type: SignatureFormat,
    script_pubkey: &ScriptBuf,
) -> Result<MessageProof, Error> {
    let mut buffer = Vec::new();

    let signature_format = if signature_type == SignatureFormat::Simple
        && !script_pubkey.is_p2wpkh()
        && !script_pubkey.is_p2wsh()
        && !script_pubkey.is_p2tr()
    {
        SignatureFormat::Full
    } else {
        signature_type
    };

    match signature_format {
        SignatureFormat::Legacy => Err(Error::InvalidFormat(
            "Legacy format is verify-only. Use Simple or Full for P2PKH addresses".to_string(),
        )),
        SignatureFormat::Simple => {
            if script_pubkey.is_p2sh() {
                return Err(Error::InvalidFormat(
                    "Simple format is not supported for P2SH addresses. Use Full format."
                        .to_string(),
                ));
            }

            let witness = psbt.inputs[0]
                .final_script_witness
                .as_ref()
                .ok_or(Error::InvalidFormat("No final witness found".to_string()))?;

            validate_witness(witness, script_pubkey)?;

            witness.consensus_encode(&mut buffer)?;
            let simple_signature = general_purpose::STANDARD.encode(&buffer);
            Ok(MessageProof::Signed(simple_signature))
        }
        SignatureFormat::Full | SignatureFormat::FullProofOfFunds => {
            let tx = psbt.clone().extract_tx()?;

            tx.consensus_encode(&mut buffer)?;
            let full_signature = general_purpose::STANDARD.encode(&buffer);
            Ok(MessageProof::Signed(full_signature))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::{
        KeychainKind,
        test_utils::{get_funded_wallet, get_funded_wallet_single},
    };
    use bitcoin::Amount;

    #[test]
    fn test_legacy_signing_rejected() {
        const EXTERNAL_DESC: &str = "pkh(tprv8ZgxMBicQKsPfGXKjYNsw4gayjfBsq6FHxvNZ8LSBdz4DSTeBPd7cjvVQXTdMH9NJBVwNrNKLDr58dcrf4YmWLYBs4KogJhSgUELXuo1JwH/44'/1'/0'/0/*)";
        const INTERNAL_DESC: &str = "pkh(tprv8ZgxMBicQKsPfGXKjYNsw4gayjfBsq6FHxvNZ8LSBdz4DSTeBPd7cjvVQXTdMH9NJBVwNrNKLDr58dcrf4YmWLYBs4KogJhSgUELXuo1JwH/44'/1'/0'/1/*)";

        let (mut wallet, _) = get_funded_wallet(EXTERNAL_DESC, INTERNAL_DESC);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let result = wallet.sign_message("HELLO WORLD", SignatureFormat::Legacy, &address, None);

        assert!(result.is_err())
    }

    #[test]
    fn test_simple_format_p2pkh() {
        const EXTERNAL_DESC: &str = "pkh(tprv8ZgxMBicQKsPfGXKjYNsw4gayjfBsq6FHxvNZ8LSBdz4DSTeBPd7cjvVQXTdMH9NJBVwNrNKLDr58dcrf4YmWLYBs4KogJhSgUELXuo1JwH/44'/1'/0'/0/*)";
        const INTERNAL_DESC: &str = "pkh(tprv8ZgxMBicQKsPfGXKjYNsw4gayjfBsq6FHxvNZ8LSBdz4DSTeBPd7cjvVQXTdMH9NJBVwNrNKLDr58dcrf4YmWLYBs4KogJhSgUELXuo1JwH/44'/1'/0'/1/*)";

        let (mut wallet, _) = get_funded_wallet(EXTERNAL_DESC, INTERNAL_DESC);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        // signing goes through Full Format
        let sign = wallet
            .sign_message("HELLO WORLD", SignatureFormat::Simple, &address, None)
            .unwrap();

        let verify = wallet
            .verify_message(&sign, "HELLO WORLD", &address)
            .unwrap();

        assert!(verify.valid)
    }

    #[test]
    fn test_simple_format_p2wpkh() {
        const EXTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
        const INTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";

        let (mut wallet, _) = get_funded_wallet(EXTERNAL_DESC, INTERNAL_DESC);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let sign = wallet
            .sign_message("HELLO WORLD", SignatureFormat::Simple, &address, None)
            .unwrap();

        let verify = wallet
            .verify_message(&sign, "HELLO WORLD", &address)
            .unwrap();

        assert!(verify.valid)
    }

    #[test]
    fn test_simple_format_p2tr() {
        const EXTERNAL_DESC: &str = "tr(tprv8ZgxMBicQKsPd3krDUsBAmtnRsK3rb8u5yi1zhQgMhF1tR8MW7xfE4rnrbbsrbPR52e7rKapu6ztw1jXveJSCGHEriUGZV7mCe88duLp5pj/86'/1'/0'/0/*)";
        const INTERNAL_DESC: &str = "tr(tprv8ZgxMBicQKsPd3krDUsBAmtnRsK3rb8u5yi1zhQgMhF1tR8MW7xfE4rnrbbsrbPR52e7rKapu6ztw1jXveJSCGHEriUGZV7mCe88duLp5pj/86'/1'/0'/1/*)";

        let (mut wallet, _) = get_funded_wallet(EXTERNAL_DESC, INTERNAL_DESC);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let sign = wallet
            .sign_message("HELLO WORLD", SignatureFormat::Simple, &address, None)
            .unwrap();

        let verify = wallet
            .verify_message(&sign, "HELLO WORLD", &address)
            .unwrap();

        assert!(verify.valid)
    }

    #[test]
    fn test_simple_format_p2wsh() {
        let (mut wallet, _) = get_funded_wallet_single(
            "wsh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),older(6)))",
        );
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let sign = wallet
            .sign_message("HELLO WORLD", SignatureFormat::Simple, &address, None)
            .unwrap();

        let verify = wallet
            .verify_message(&sign, "HELLO WORLD", &address)
            .unwrap();

        assert!(verify.valid)
    }

    #[test]
    fn test_full_format_p2wpkh() {
        const EXTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
        const INTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";

        let (mut wallet, _) = get_funded_wallet(EXTERNAL_DESC, INTERNAL_DESC);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let sign = wallet
            .sign_message("HELLO WORLD", SignatureFormat::Full, &address, None)
            .unwrap();

        let verify = wallet
            .verify_message(&sign, "HELLO WORLD", &address)
            .unwrap();

        assert!(verify.valid)
    }

    #[test]
    fn test_full_format_p2tr() {
        const EXTERNAL_DESC: &str = "tr(tprv8ZgxMBicQKsPd3krDUsBAmtnRsK3rb8u5yi1zhQgMhF1tR8MW7xfE4rnrbbsrbPR52e7rKapu6ztw1jXveJSCGHEriUGZV7mCe88duLp5pj/86'/1'/0'/0/*)";
        const INTERNAL_DESC: &str = "tr(tprv8ZgxMBicQKsPd3krDUsBAmtnRsK3rb8u5yi1zhQgMhF1tR8MW7xfE4rnrbbsrbPR52e7rKapu6ztw1jXveJSCGHEriUGZV7mCe88duLp5pj/86'/1'/0'/1/*)";

        let (mut wallet, _) = get_funded_wallet(EXTERNAL_DESC, INTERNAL_DESC);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let sign = wallet
            .sign_message("HELLO WORLD", SignatureFormat::Full, &address, None)
            .unwrap();

        let verify = wallet
            .verify_message(&sign, "HELLO WORLD", &address)
            .unwrap();

        assert!(verify.valid)
    }

    #[test]
    fn test_full_format_p2wsh() {
        let (mut wallet, _) = get_funded_wallet_single(
            "wsh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),older(6)))",
        );
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let sign = wallet
            .sign_message("HELLO WORLD", SignatureFormat::Full, &address, None)
            .unwrap();

        let verify = wallet
            .verify_message(&sign, "HELLO WORLD", &address)
            .unwrap();

        assert!(verify.valid)
    }

    #[test]
    fn test_full_with_proof_of_funds_format_p2wpkh() {
        const EXTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
        const INTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";

        let (mut wallet, _) = get_funded_wallet(EXTERNAL_DESC, INTERNAL_DESC);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let utxos: Vec<_> = wallet
            .list_unspent()
            .filter(|utxo| utxo.txout.script_pubkey == address.script_pubkey())
            .map(|utxo| utxo.outpoint)
            .collect();

        assert!(!utxos.is_empty(), "No UTXOs found for address");

        let sign = wallet
            .sign_message(
                "HELLO WORLD",
                SignatureFormat::FullProofOfFunds,
                &address,
                Some(utxos),
            )
            .unwrap();

        let verify = wallet
            .verify_message(&sign, "HELLO WORLD", &address)
            .unwrap();

        assert!(verify.valid)
    }

    #[test]
    fn test_full_with_proof_of_funds_format_p2tr() {
        const EXTERNAL_DESC: &str = "tr(tprv8ZgxMBicQKsPd3krDUsBAmtnRsK3rb8u5yi1zhQgMhF1tR8MW7xfE4rnrbbsrbPR52e7rKapu6ztw1jXveJSCGHEriUGZV7mCe88duLp5pj/86'/1'/0'/0/*)";
        const INTERNAL_DESC: &str = "tr(tprv8ZgxMBicQKsPd3krDUsBAmtnRsK3rb8u5yi1zhQgMhF1tR8MW7xfE4rnrbbsrbPR52e7rKapu6ztw1jXveJSCGHEriUGZV7mCe88duLp5pj/86'/1'/0'/1/*)";

        let (mut wallet, _) = get_funded_wallet(EXTERNAL_DESC, INTERNAL_DESC);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let utxos: Vec<_> = wallet
            .list_unspent()
            .filter(|utxo| utxo.txout.script_pubkey == address.script_pubkey())
            .map(|utxo| utxo.outpoint)
            .collect();

        assert!(!utxos.is_empty(), "No UTXOs found for address");

        let sign = wallet
            .sign_message(
                "HELLO WORLD",
                SignatureFormat::FullProofOfFunds,
                &address,
                Some(utxos),
            )
            .unwrap();

        let verify = wallet
            .verify_message(&sign, "HELLO WORLD", &address)
            .unwrap();

        assert!(verify.valid)
    }

    #[test]
    fn test_full_with_proof_of_funds_format_p2wsh() {
        const DESCRIPTOR: &str = "wsh(pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW))";

        let (mut wallet, _) = get_funded_wallet_single(DESCRIPTOR);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let utxos: Vec<_> = wallet
            .list_unspent()
            .filter(|utxo| utxo.txout.script_pubkey == address.script_pubkey())
            .map(|utxo| utxo.outpoint)
            .collect();

        assert!(!utxos.is_empty(), "No UTXOs found for address");

        let sign = wallet
            .sign_message(
                "HELLO WORLD",
                SignatureFormat::FullProofOfFunds,
                &address,
                Some(utxos),
            )
            .unwrap();

        let verify = wallet
            .verify_message(&sign, "HELLO WORLD", &address)
            .unwrap();

        assert!(verify.valid)
    }

    #[test]
    fn test_full_with_proof_of_funds_psbt() {
        const DESCRIPTOR: &str =
            "wsh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),older(6)))";

        let (mut wallet, _) = get_funded_wallet_single(DESCRIPTOR);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let utxos: Vec<_> = wallet
            .list_unspent()
            .filter(|utxo| utxo.txout.script_pubkey == address.script_pubkey())
            .map(|utxo| utxo.outpoint)
            .collect();

        assert!(!utxos.is_empty(), "No UTXOs found for address");

        let sign = wallet
            .sign_message(
                "HELLO WORLD",
                SignatureFormat::FullProofOfFunds,
                &address,
                Some(utxos),
            )
            .unwrap();

        let verify = wallet
            .verify_message(&sign, "HELLO WORLD", &address)
            .unwrap();

        assert!(verify.valid);
        assert_eq!(verify.proven_amount.unwrap(), Amount::from_sat(50000));
        assert_ne!(verify.proven_amount.unwrap(), Amount::from_sat(0))
    }

    #[test]
    fn test_simple_format_p2sh_p2wpkh() {
        const EXTERNAL_DESC: &str = "sh(wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/49'/1'/0'/0/*))";
        const INTERNAL_DESC: &str = "sh(wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/49'/1'/0'/1/*))";

        let (mut wallet, _) = get_funded_wallet(EXTERNAL_DESC, INTERNAL_DESC);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let sign = wallet
            .sign_message("HELLO WORLD", SignatureFormat::Simple, &address, None)
            .unwrap();

        let verify = wallet
            .verify_message(&sign, "HELLO WORLD", &address)
            .unwrap();

        assert!(verify.valid);
    }

    #[test]
    fn test_full_format_p2sh_p2wsh() {
        let (mut wallet, _) = get_funded_wallet_single(
            "sh(wsh(pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)))",
        );
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let sign = wallet
            .sign_message("HELLO WORLD", SignatureFormat::Full, &address, None)
            .unwrap();

        let verify = wallet
            .verify_message(&sign, "HELLO WORLD", &address)
            .unwrap();

        assert!(verify.valid);
    }

    #[test]
    fn test_wrong_message_fails_verification() {
        const EXTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
        const INTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";

        let (mut wallet, _) = get_funded_wallet(EXTERNAL_DESC, INTERNAL_DESC);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let sign = wallet
            .sign_message("HELLO WORLD", SignatureFormat::Simple, &address, None)
            .unwrap();

        // Verify with wrong message should fail
        let verify = wallet.verify_message(&sign, "WRONG MESSAGE", &address);

        if let Ok(result) = verify {
            assert!(!result.valid)
        }
    }

    #[test]
    fn test_utxos_rejected_for_non_pof_format() {
        const EXTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
        const INTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";

        let (mut wallet, _) = get_funded_wallet(EXTERNAL_DESC, INTERNAL_DESC);
        let address = wallet.peek_address(KeychainKind::External, 0).address;

        let utxos: Vec<_> = wallet.list_unspent().map(|utxo| utxo.outpoint).collect();

        // Simple format with UTXOs should error
        let result = wallet.sign_message(
            "HELLO WORLD",
            SignatureFormat::Simple,
            &address,
            Some(utxos),
        );

        assert!(result.is_err());
    }
}
