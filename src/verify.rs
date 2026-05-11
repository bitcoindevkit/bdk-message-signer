//! BIP-322 signature verification implementation.
//!
//! This module handles verification of all signature formats including
//! legacy, simple, full, and proof-of-funds variants.

use crate::{
    Error, MessageVerificationResult, SignatureFormat, detect_signature_format, extract_pubkeys,
    extract_redeem_script, to_sign, to_spend, validate_to_sign, validate_witness,
};
use alloc::{string::ToString, vec::Vec};
use bdk_wallet::Wallet;
use bitcoin::{
    Address, Amount, EcdsaSighashType, OutPoint, Psbt, PubkeyHash, PublicKey, ScriptBuf, Sequence,
    TapSighashType, Transaction, TxOut, Witness, WitnessVersion, XOnlyPublicKey,
    absolute::LockTime,
    base64::{Engine, engine::general_purpose},
    consensus::Decodable,
    hashes::Hash,
    hashes::{HashEngine, sha256d},
    key::Secp256k1,
    script::Instruction,
    secp256k1::ecdsa::{RecoverableSignature, RecoveryId},
    secp256k1::{Message, VerifyOnly, ecdsa::Signature, schnorr},
    sighash::{self, SighashCache},
    transaction::Version,
};

/// Verifies a PSBT (unsigned/partially-signed) proof for proof-of-funds.
///
/// Validates that the PSBT contains inputs matching the given address
/// and sums their amounts. Skips input 0 (the virtual `to_spend`).
///
/// **Note**: This validates structure and amounts only, not cryptographic signatures.
pub fn verify_psbt_proof(
    psbt: &Psbt,
    message: &str,
    address: &Address,
) -> Result<MessageVerificationResult, Error> {
    let script_pubkey = address.script_pubkey();

    // Verify the PSBT was constructed for this message
    let expected_to_spend = to_spend(&script_pubkey, message);
    let expected_outpoint = OutPoint {
        txid: expected_to_spend.compute_txid(),
        vout: 0,
    };

    if psbt.unsigned_tx.input.is_empty()
        || psbt.unsigned_tx.input[0].previous_output != expected_outpoint
    {
        return Ok(MessageVerificationResult {
            valid: false,
            proven_amount: None,
        });
    }

    // Calculate total amount from inputs matching the address (skip input 0 which is the virtual to_spend)
    let total_amount: Amount = psbt
        .inputs
        .iter()
        .enumerate()
        .skip(1)
        .filter_map(|(i, psbt_input)| {
            let tx_input = &psbt.unsigned_tx.input.get(i)?;
            // Get UTXO value from witness_utxo or non_witness_utxo
            psbt_input.witness_utxo.as_ref().or_else(|| {
                psbt_input
                    .non_witness_utxo
                    .as_ref()
                    .and_then(|tx| tx.output.get(tx_input.previous_output.vout as usize))
            })
        })
        .filter(|utxo| utxo.script_pubkey == script_pubkey)
        .map(|utxo| utxo.value)
        .sum();

    Ok(if total_amount > Amount::ZERO {
        MessageVerificationResult {
            valid: true,
            proven_amount: Some(total_amount),
        }
    } else {
        MessageVerificationResult {
            valid: false,
            proven_amount: None,
        }
    })
}

/// Verifies a signed (finalized) proof.
pub fn verify_signed_proof(
    wallet: &Wallet,
    message: &str,
    address: &Address,
    signature_base64: &str,
) -> Result<MessageVerificationResult, Error> {
    let script_pubkey = address.script_pubkey();
    let to_spend = to_spend(&script_pubkey, message);
    let mut to_sign = to_sign(&to_spend, Version(0), LockTime::ZERO, Sequence::ZERO);

    // Decode the base64 signature
    let signature_bytes = general_purpose::STANDARD
        .decode(signature_base64)
        .map_err(|_| Error::InvalidFormat("Invalid base64 encoding".to_string()))?;

    if signature_bytes.is_empty() {
        return Err(Error::InvalidFormat("Empty scriptSig".to_string()));
    }

    let mut cursor = bitcoin::io::Cursor::new(signature_bytes.clone());
    let secp = Secp256k1::verification_only();

    let signature_type = detect_signature_format(&signature_bytes)?;

    match signature_type {
        SignatureFormat::Legacy => {
            let verification_result = verify_legacy(signature_base64, message, address, &secp)?;

            Ok(MessageVerificationResult {
                valid: verification_result,
                proven_amount: None,
            })
        }
        SignatureFormat::Simple => {
            let witness = Witness::consensus_decode_from_finite_reader(&mut cursor)?;
            validate_witness(&witness, &script_pubkey)?;

            to_sign.input[0].witness = witness;

            let verification_result =
                verify_message(wallet, address, &to_sign, to_spend, signature_type, &secp)?;

            Ok(MessageVerificationResult {
                valid: verification_result,
                proven_amount: None,
            })
        }
        SignatureFormat::Full | SignatureFormat::FullProofOfFunds => {
            let tx = Transaction::consensus_decode_from_finite_reader(&mut cursor)?;
            validate_to_sign(&tx, &to_spend)?;

            // FullProofOfFunds — additional input validation and amount summation
            let total_amount = if signature_type == SignatureFormat::FullProofOfFunds {
                if tx.input.len() < 2 {
                    return Err(Error::InvalidFormat(
                        "FullProofOfFunds requires at least 2 inputs".to_string(),
                    ));
                }

                let mut amount = Amount::ZERO;
                for input in tx.input.iter().skip(1) {
                    let utxo = wallet
                        .get_utxo(input.previous_output)
                        .ok_or(Error::UtxoNotFound(input.previous_output))?;

                    if utxo.txout.script_pubkey != script_pubkey {
                        return Err(Error::InvalidFormat(
                            "Additional input does not belong to the signing address".to_string(),
                        ));
                    }

                    amount += utxo.txout.value;
                }
                Some(amount)
            } else {
                None
            };

            let valid = verify_message(wallet, address, &tx, to_spend, signature_type, &secp)?;

            Ok(MessageVerificationResult {
                valid,
                proven_amount: if valid { total_amount } else { None },
            })
        }
    }
}

/// Verifies a message signature for the given address using the specified format.
fn verify_message(
    wallet: &Wallet,
    address: &Address,
    to_sign: &Transaction,
    to_spend: Transaction,
    signature_type: SignatureFormat,
    secp: &Secp256k1<VerifyOnly>,
) -> Result<bool, Error> {
    validate_to_sign(to_sign, &to_spend)?;
    let script_pubkey = address.script_pubkey();

    let prevout = TxOut {
        value: Amount::from_sat(0),
        script_pubkey: to_spend.output[0].clone().script_pubkey,
    };

    let valid = if script_pubkey.is_p2pkh() {
        verify_p2pkh(to_sign, &script_pubkey, 0, secp)?
    } else if script_pubkey.is_p2wpkh() {
        let wp = address.witness_program().ok_or(Error::NotSegwitAddress)?;
        if wp.version() != WitnessVersion::V0 {
            return Err(Error::UnsupportedSegwitVersion("v0".to_string()));
        }
        verify_p2wpkh(to_sign, &prevout, 0, secp)?
    } else if script_pubkey.is_p2wsh() {
        let wp = address.witness_program().ok_or(Error::NotSegwitAddress)?;
        if wp.version() != WitnessVersion::V0 {
            return Err(Error::UnsupportedSegwitVersion("v0".to_string()));
        }
        verify_p2wsh(to_sign, &prevout, &script_pubkey, 0, secp)?
    } else if script_pubkey.is_p2tr() {
        let wp = address.witness_program().ok_or(Error::NotSegwitAddress)?;
        if wp.version() != WitnessVersion::V1 {
            return Err(Error::UnsupportedSegwitVersion("v1".to_string()));
        }
        verify_p2tr(to_sign, &prevout, 0, wallet, &to_spend, secp)?
    } else if script_pubkey.is_p2sh() {
        verify_p2sh(to_sign, &prevout, &script_pubkey, 0, secp)?
    } else {
        return Ok(false);
    };

    if !valid {
        return Ok(false);
    }

    // For proof-of-funds, verify all additional inputs
    if signature_type == SignatureFormat::FullProofOfFunds {
        return verify_proof_of_funds(wallet, to_sign, &to_spend, address, secp);
    }

    Ok(true)
}

/// Verifies all proof-of-funds inputs beyond the first.
fn verify_proof_of_funds(
    wallet: &Wallet,
    to_sign: &Transaction,
    to_spend: &Transaction,
    address: &Address,
    secp: &Secp256k1<VerifyOnly>,
) -> Result<bool, Error> {
    let script_pubkey = address.script_pubkey();
    if to_sign.input.len() < 2 {
        return Err(Error::InvalidFormat(
            "FullProofOfFunds requires at least 2 inputs".to_string(),
        ));
    }

    // Verify each additional input
    for (i, tx_input) in to_sign.input.iter().enumerate().skip(1) {
        let utxo = wallet
            .get_utxo(tx_input.previous_output)
            .ok_or(Error::UtxoNotFound(tx_input.previous_output))?;

        if utxo.txout.script_pubkey != *script_pubkey {
            return Ok(false);
        }

        if script_pubkey.is_p2pkh() {
            if !verify_p2pkh(to_sign, &script_pubkey, i, secp)? {
                return Ok(false);
            }
        } else if script_pubkey.is_p2wpkh() {
            if !verify_p2wpkh(to_sign, &utxo.txout, i, secp)? {
                return Ok(false);
            }
        } else if script_pubkey.is_p2tr() {
            if !verify_p2tr(to_sign, &utxo.txout, i, wallet, to_spend, secp)? {
                return Ok(false);
            }
        } else if script_pubkey.is_p2wsh() {
            if !verify_p2wsh(to_sign, &utxo.txout, &script_pubkey, i, secp)? {
                return Ok(false);
            }
        } else if script_pubkey.is_p2sh() {
            if !verify_p2sh(to_sign, &utxo.txout, &script_pubkey, i, secp)? {
                return Ok(false);
            }
        } else {
            return Err(Error::InvalidFormat(
                "Unsupported script type for proof of funds".to_string(),
            ));
        };
    }

    Ok(true)
}

/// Verifies Legacy format Bitcoin Core message signature.
fn verify_legacy(
    signature_base64: &str,
    message: &str,
    address: &Address,
    secp: &Secp256k1<VerifyOnly>,
) -> Result<bool, Error> {
    let signature_bytes = general_purpose::STANDARD
        .decode(signature_base64)
        .map_err(|_| Error::InvalidFormat("Invalid base64 encoding".to_string()))?;

    if signature_bytes.len() != 65 {
        return Err(Error::InvalidFormat(alloc::format!(
            "Legacy signature must be 65 bytes, got {}",
            signature_bytes.len()
        )));
    }

    // Parse recovery flag
    let recovery_flag = signature_bytes[0];
    let (recovery_id, compressed) = if (27..=30).contains(&recovery_flag) {
        (recovery_flag - 27, false)
    } else if (31..=34).contains(&recovery_flag) {
        (recovery_flag - 31, true)
    } else {
        return Err(Error::InvalidFormat(alloc::format!(
            "Invalid recovery flag: {}",
            recovery_flag
        )));
    };

    // Compute Bitcoin Core message hash
    let msg_hash = {
        let mut engine = sha256d::Hash::engine();
        engine.input(b"\x18Bitcoin Signed Message:\n");
        let msg_bytes = message.as_bytes();
        // Encode message length as Bitcoin varint
        let mut len_buf = Vec::new();
        bitcoin::consensus::encode::Encodable::consensus_encode(
            &bitcoin::VarInt(msg_bytes.len() as u64),
            &mut len_buf,
        )
        .map_err(Error::IoError)?;
        engine.input(&len_buf);
        engine.input(msg_bytes);
        sha256d::Hash::from_engine(engine)
    };

    let msg = Message::from_digest_slice(msg_hash.as_ref()).map_err(|_| Error::InvalidMessage)?;

    // Build recoverable signature
    let rec_id = RecoveryId::from_i32(recovery_id as i32)
        .map_err(|e| Error::InvalidSignature(e.to_string()))?;
    let recoverable_sig = RecoverableSignature::from_compact(&signature_bytes[1..65], rec_id)
        .map_err(|e| Error::InvalidSignature(e.to_string()))?;

    // Recover the public key
    let recovered_pubkey = secp
        .recover_ecdsa(&msg, &recoverable_sig)
        .map_err(|e| Error::InvalidSignature(e.to_string()))?;

    // Serialize in the correct format (compressed or uncompressed)
    let pubkey_bytes = if compressed {
        recovered_pubkey.serialize().to_vec()
    } else {
        recovered_pubkey.serialize_uncompressed().to_vec()
    };

    // Derive P2PKH script from recovered key and compare with address
    let pubkey_hash = PubkeyHash::hash(&pubkey_bytes);
    let expected_script = ScriptBuf::new_p2pkh(&pubkey_hash);

    Ok(expected_script == address.script_pubkey())
}

/// Verifies P2PKH format
fn verify_p2pkh(
    to_sign: &Transaction,
    script_pubkey: &ScriptBuf,
    input_index: usize,
    secp: &Secp256k1<VerifyOnly>,
) -> Result<bool, Error> {
    let script_sig = &to_sign.input[input_index].script_sig;

    if script_sig.is_empty() {
        return Ok(false);
    }

    let mut instructions = script_sig.instructions();

    // DER signature + sighash byte
    let sig_with_sighash = match instructions.next() {
        Some(Ok(Instruction::PushBytes(bytes))) => bytes.as_bytes(),
        _ => {
            return Err(Error::InvalidFormat(
                "Expected signature push in scriptSig".to_string(),
            ));
        }
    };

    if sig_with_sighash.is_empty() {
        return Ok(false);
    }

    let sighash_byte = sig_with_sighash[sig_with_sighash.len() - 1];
    let sig_der = &sig_with_sighash[..sig_with_sighash.len() - 1];

    let sighash_type = EcdsaSighashType::from_consensus(sighash_byte as u32);
    if sighash_type != EcdsaSighashType::All {
        return Err(Error::InvalidSighashType);
    }

    // compressed public key
    let pubkey_bytes = match instructions.next() {
        Some(Ok(Instruction::PushBytes(bytes))) => bytes.as_bytes(),
        _ => {
            return Err(Error::InvalidFormat(
                "Expected pubkey push in scriptSig".to_string(),
            ));
        }
    };

    if instructions.next().is_some() {
        return Err(Error::InvalidFormat(
            "Unexpected extra data in scriptSig".to_string(),
        ));
    }

    let pub_key =
        PublicKey::from_slice(pubkey_bytes).map_err(|e| Error::InvalidPublicKey(e.to_string()))?;

    let pubkey_hash = PubkeyHash::hash(pubkey_bytes);
    let expected_script_pubkey = ScriptBuf::new_p2pkh(&pubkey_hash);

    if expected_script_pubkey != *script_pubkey {
        return Err(Error::InvalidFormat(
            "Address doesn't match public key in signature".to_string(),
        ));
    }

    // Compute the legacy sighash
    let sighash_cache = SighashCache::new(to_sign);
    let sighash = sighash_cache
        .legacy_signature_hash(0, script_pubkey, sighash_type.to_u32())
        .map_err(|_| Error::SighashError)?;

    let msg = Message::from_digest_slice(sighash.as_ref()).map_err(|_| Error::InvalidMessage)?;

    let signature =
        Signature::from_der(sig_der).map_err(|e| Error::InvalidSignature(e.to_string()))?;

    Ok(secp.verify_ecdsa(&msg, &signature, &pub_key.inner).is_ok())
}

/// Verifies P2WPKH (Pay-to-Witness-Public-Key-Hash) signature.
fn verify_p2wpkh(
    to_sign: &Transaction,
    prevout: &TxOut,
    input_index: usize,
    secp: &Secp256k1<VerifyOnly>,
) -> Result<bool, Error> {
    let witness = &to_sign.input[input_index].witness;

    if witness.len() != 2 {
        return Err(Error::InvalidWitness(
            "P2WPKH requires exactly 2 witness elements".to_string(),
        ));
    }

    // Extract witness elements
    let encoded_signature = witness
        .nth(0)
        .ok_or(Error::InvalidWitness("Missing signature".to_string()))?;
    let witness_pub_key = witness
        .nth(1)
        .ok_or(Error::InvalidWitness("Missing public key".to_string()))?;
    let signature_length = encoded_signature.len();

    if encoded_signature.is_empty() {
        return Ok(false);
    }

    // Parse public key
    let pub_key = PublicKey::from_slice(witness_pub_key)
        .map_err(|e| Error::InvalidPublicKey(e.to_string()))?;

    // Parse signature (DER + sighash byte)
    let signature = Signature::from_der(&encoded_signature[..signature_length - 1])
        .map_err(|e| Error::InvalidSignature(e.to_string()))?;
    let sighash_type =
        EcdsaSighashType::from_consensus(encoded_signature[signature_length - 1] as u32);

    if sighash_type != EcdsaSighashType::All {
        return Err(Error::InvalidSighashType);
    }

    // Compute sighash
    let mut sighash_cache = SighashCache::new(to_sign);
    let wpubkey_hash = &pub_key
        .wpubkey_hash()
        .map_err(|e| Error::InvalidPublicKey(e.to_string()))?;
    let script_code = ScriptBuf::new_p2wpkh(wpubkey_hash);

    let sighash = sighash_cache
        .p2wpkh_signature_hash(input_index, &script_code, prevout.value, sighash_type)
        .map_err(|_| Error::SighashError)?;

    let msg = &Message::from_digest_slice(sighash.as_ref()).map_err(|_| Error::InvalidMessage)?;

    Ok(secp.verify_ecdsa(msg, &signature, &pub_key.inner).is_ok())
}

/// Verifies P2WSH (Pay-to-Witness-Script-Hash) signature(s).
///
/// Supports both single-key and multi-key witness scripts.
fn verify_p2wsh(
    to_sign: &Transaction,
    prevout: &TxOut,
    script_pubkey: &ScriptBuf,
    input_index: usize,
    secp: &Secp256k1<VerifyOnly>,
) -> Result<bool, Error> {
    // let script_pubkey = address.script_pubkey();
    let witness = &to_sign.input[input_index].witness;

    if witness.len() < 2 {
        return Err(Error::InvalidWitness(
            "P2WSH requires at least 2 witness elements".to_string(),
        ));
    }

    let witness_script_bytes = witness
        .nth(witness.len() - 1)
        .ok_or(Error::InvalidWitness("No witness script found".to_string()))?;
    let witness_script = ScriptBuf::from_bytes(witness_script_bytes.to_vec());

    // Verify witness script hash matches address
    let script_hash = witness_script.wscript_hash();
    let expected_script_pubkey = ScriptBuf::new_p2wsh(&script_hash);

    if *script_pubkey != expected_script_pubkey {
        return Err(Error::InvalidSignature(
            "Witness script hash doesn't match address".to_string(),
        ));
    }

    // Compute sighash
    let mut sighash_cache = SighashCache::new(to_sign);
    let sighash = sighash_cache
        .p2wsh_signature_hash(
            input_index,
            &witness_script,
            prevout.value,
            EcdsaSighashType::All,
        )
        .map_err(|_| Error::SighashError)?;

    let msg = &Message::from_digest_slice(sighash.as_ref()).map_err(|_| Error::InvalidMessage)?;

    // Delegate signature verification (works for both single-key and multi-key)
    verify_p2wsh_signatures(witness, &witness_script, msg, secp)
}

/// Matches witness stack signatures against public keys extracted from the witness script.
///
/// Keys must be consumed in order per OP_CHECKMULTISIG semantics (BIP-67).
/// Supports both single-key and multi-key scripts.
fn verify_p2wsh_signatures(
    witness: &Witness,
    witness_script: &ScriptBuf,
    sighash: &Message,
    secp: &Secp256k1<VerifyOnly>,
) -> Result<bool, Error> {
    // Extract all compressed pubkeys from the witness script
    let pubkeys = extract_pubkeys(witness_script)?;

    // Collect all signatures from the witness
    let signatures: Vec<&[u8]> = witness
        .iter()
        .take(witness.len().saturating_sub(1))
        .filter(|elem| !elem.is_empty())
        .collect();

    if signatures.is_empty() {
        return Ok(false);
    }

    let mut key_idx = 0;
    for sig_bytes in &signatures {
        let sig_len = sig_bytes.len();
        let signature = Signature::from_der(&sig_bytes[..sig_len - 1])
            .map_err(|e| Error::InvalidSignature(e.to_string()))?;

        let sighash_type = EcdsaSighashType::from_consensus(sig_bytes[sig_len - 1] as u32);
        if sighash_type != EcdsaSighashType::All {
            return Err(Error::InvalidSighashType);
        }

        // Find a matching pubkey (must be at or after current key_idx)
        let mut matched = false;
        while key_idx < pubkeys.len() {
            if secp
                .verify_ecdsa(sighash, &signature, &pubkeys[key_idx].inner)
                .is_ok()
            {
                key_idx += 1;
                matched = true;
                break;
            }
            key_idx += 1;
        }

        if !matched {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Verifies P2TR (Pay-to-Taproot) signature for key path spend.
fn verify_p2tr(
    to_sign: &Transaction,
    prevout: &TxOut,
    input_index: usize,
    wallet: &Wallet,
    to_spend: &Transaction,
    secp: &Secp256k1<VerifyOnly>,
) -> Result<bool, Error> {
    let script_bytes = prevout.script_pubkey.as_bytes();

    // Extract x-only public key from script
    let pub_key = XOnlyPublicKey::from_slice(&script_bytes[2..])
        .map_err(|e| Error::InvalidPublicKey(e.to_string()))?;

    // Validate witness structure
    let witness = &to_sign.input[input_index].witness;
    if witness.is_empty() {
        return Err(Error::InvalidWitness(
            "P2TR key path requires at least 1 witness element".to_string(),
        ));
    }

    let encoded_signature = witness
        .nth(0)
        .ok_or(Error::InvalidWitness("Missing signature".to_string()))?;

    let (signature, sighash_type) = match encoded_signature.len() {
        64 => {
            let sig = schnorr::Signature::from_slice(encoded_signature)
                .map_err(|e| Error::InvalidSignature(e.to_string()))?;
            (sig, TapSighashType::Default)
        }
        65 => {
            let sig = schnorr::Signature::from_slice(&encoded_signature[..64])
                .map_err(|e| Error::InvalidSignature(e.to_string()))?;
            let sht = TapSighashType::from_consensus_u8(encoded_signature[64])
                .map_err(|_| Error::InvalidSighashType)?;
            (sig, sht)
        }
        other => {
            return Err(Error::InvalidSignature(alloc::format!(
                "Invalid Schnorr signature length: {} (expected 64 or 65)",
                other
            )));
        }
    };

    if !matches!(sighash_type, TapSighashType::Default | TapSighashType::All) {
        return Err(Error::InvalidSighashType);
    }

    // Build prevouts array for sighash computation
    let mut prevouts = Vec::with_capacity(to_sign.input.len());
    let to_spend_outpoint = OutPoint {
        txid: to_spend.compute_txid(),
        vout: 0,
    };
    for (i, txin) in to_sign.input.iter().enumerate() {
        if i == input_index {
            prevouts.push(prevout.clone());
        } else if txin.previous_output == to_spend_outpoint {
            prevouts.push(to_spend.output[0].clone());
        } else {
            let utxo = wallet
                .get_utxo(txin.previous_output)
                .ok_or(Error::UtxoNotFound(txin.previous_output))?;
            prevouts.push(utxo.txout);
        }
    }

    let prevouts = sighash::Prevouts::All(&prevouts);

    // Compute sighash
    let mut sighash_cache = SighashCache::new(to_sign);
    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
        .map_err(|_| Error::SighashError)?;

    let msg = &Message::from_digest_slice(sighash.as_ref()).map_err(|_| Error::InvalidMessage)?;

    Ok(secp.verify_schnorr(&signature, msg, &pub_key).is_ok())
}

/// Verifies P2SH-wrapped SegWit signatures (P2SH-P2WPKH and P2SH-P2WSH).
///
/// Extracts the redeem script from the input's script_sig, determines
/// the inner SegWit type, and delegates to the appropriate verifier.
fn verify_p2sh(
    to_sign: &Transaction,
    prevout: &TxOut,
    script_pubkey: &ScriptBuf,
    input_index: usize,
    secp: &Secp256k1<VerifyOnly>,
) -> Result<bool, Error> {
    let input = &to_sign.input[input_index];

    // P2SH-wrapped SegWit: the script_sig contains a single push of the redeem script.
    // The redeem script IS the inner SegWit scriptPubKey (e.g., OP_0 <20-byte-hash>).
    let redeem_script = extract_redeem_script(&input.script_sig)?;

    // Verify the redeem script hashes to the P2SH address
    let script_hash = redeem_script.script_hash();
    let expected_script_pubkey = ScriptBuf::new_p2sh(&script_hash);

    if *script_pubkey != expected_script_pubkey {
        return Err(Error::InvalidSignature(
            "Redeem script hash doesn't match P2SH address".to_string(),
        ));
    }

    // Create a synthetic prevout with the inner SegWit scriptPubKey
    // so the existing verifiers compute the correct sighash.
    let inner_prevout = TxOut {
        value: prevout.value,
        script_pubkey: redeem_script.clone(),
    };

    if redeem_script.is_p2wpkh() {
        verify_p2wpkh(to_sign, &inner_prevout, input_index, secp)
    } else if redeem_script.is_p2wsh() {
        // For P2SH-P2WSH, we need a synthetic address wrapping the inner P2WSH
        // so verify_p2wsh can check the witness script hash.
        // We construct a temporary address from the inner script.
        verify_p2wsh(to_sign, &inner_prevout, &redeem_script, input_index, secp)
    } else {
        Err(Error::UnsupportedScriptType(
            "Only P2SH-P2WPKH and P2SH-P2WSH are supported.".to_string(),
        ))
    }
}
