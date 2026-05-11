//! The utility methods for message signing according to the BIP-322 standard.
use alloc::{string::ToString, vec::Vec};

use bdk_wallet::{
    Wallet,
    keys::ScriptContext,
    miniscript::{
        DefiniteDescriptorKey, Descriptor, Miniscript, Terminal, ToPublicKey as _,
        descriptor::{ShInner, WshInner},
    },
};
use bitcoin::{
    Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime,
    consensus::Decodable,
    hashes::{Hash, HashEngine, sha256},
    opcodes::{OP_0, all::OP_RETURN},
    script::{Builder, Instruction},
    transaction::Version,
};

use crate::{Error, SignatureFormat};

/// The tag used for message hashing.
pub const MESSAGE_SIGNER_TAG: &str = "BIP0322-signed-message";

/// Creates a tagged hash of a message according to the BIP322 specification.
pub fn tagged_message_hash(message: &[u8]) -> sha256::Hash {
    let mut engine = sha256::Hash::engine();

    let tag_hash = sha256::Hash::hash(MESSAGE_SIGNER_TAG.as_bytes());
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    engine.input(message);

    sha256::Hash::from_engine(engine)
}

/// Creates the virtual "to_spend" transaction.
pub fn to_spend(script_pubkey: &ScriptBuf, message: &str) -> Transaction {
    let message_hash = tagged_message_hash(message.as_bytes());
    let script_sig = Builder::new()
        .push_opcode(OP_0)
        .push_slice(message_hash.to_byte_array())
        .into_script();

    Transaction {
        version: Version(0),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0xFFFFFFFF,
            },
            script_sig,
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: script_pubkey.clone(),
        }],
    }
}

/// Creates the virtual "to_sign" transaction.
pub fn to_sign(
    to_spend: &Transaction,
    version: Version,
    lock_time: LockTime,
    sequence: Sequence,
) -> Transaction {
    let outpoint = OutPoint {
        txid: to_spend.compute_txid(),
        vout: 0,
    };
    let op_return_script = Builder::new().push_opcode(OP_RETURN).into_script();

    Transaction {
        version,
        lock_time,
        input: vec![TxIn {
            previous_output: outpoint,
            sequence,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: op_return_script,
        }],
    }
}

/// Validates witness structure matches the script type.
pub fn validate_witness(witness: &Witness, script_pubkey: &ScriptBuf) -> Result<(), Error> {
    if witness.is_empty() {
        return Err(Error::InvalidFormat("Empty witness".to_string()));
    }

    if script_pubkey.is_p2wpkh() {
        if witness.len() != 2 {
            return Err(Error::InvalidFormat(
                "P2WPKH requires exactly 2 witness elements".to_string(),
            ));
        }
    } else if script_pubkey.is_p2wsh() {
        if witness.len() < 2 {
            return Err(Error::InvalidFormat(
                "P2WSH requires at least 2 witness elements".to_string(),
            ));
        }
    } else if script_pubkey.is_p2tr() {
        if witness.is_empty() {
            return Err(Error::InvalidFormat(
                "P2TR requires at least 1 witness element".to_string(),
            ));
        }
    } else if script_pubkey.is_p2sh() {
        if witness.is_empty() {
            return Err(Error::InvalidFormat(
                "P2SH-wrapped SegWit requires witness data".to_string(),
            ));
        }
    } else {
        return Err(Error::InvalidFormat(
            "Unsupported script type for Simple format".to_string(),
        ));
    }

    Ok(())
}

/// Validates that the "to_sign" transaction correctly spends the "to_spend" transaction
pub fn validate_to_sign(to_sign: &Transaction, to_spend: &Transaction) -> Result<(), Error> {
    let to_spend_outpoint = OutPoint {
        txid: to_spend.compute_txid(),
        vout: 0,
    };

    if !matches!(to_sign.version, Version(0) | Version(2)) {
        return Err(Error::InvalidSignature(
            "to_sign version must be 0 or 2".to_string(),
        ));
    }

    if to_sign.input.is_empty() {
        return Err(Error::InvalidSignature(
            "to_sign must have at least one input".to_string(),
        ));
    }

    if to_spend_outpoint != to_sign.input[0].previous_output {
        return Err(Error::InvalidSignature(
            "to_sign first input must spend to_spend output".to_string(),
        ));
    }

    if to_sign.output.len() != 1 {
        return Err(Error::InvalidSignature(
            "to_sign must have exactly one output".to_string(),
        ));
    }

    let op_return = Builder::new().push_opcode(OP_RETURN).into_script();
    if to_sign.output[0].script_pubkey != op_return {
        return Err(Error::InvalidSignature(
            "to_sign output must be OP_RETURN".to_string(),
        ));
    }

    // Output value must be zero
    if to_sign.output[0].value != Amount::ZERO {
        return Err(Error::InvalidSignature(
            "to_sign output value must be 0".to_string(),
        ));
    }

    Ok(())
}

/// Extracts compressed public keys from a witness script.
pub fn extract_pubkeys(witness_script: &ScriptBuf) -> Result<Vec<PublicKey>, Error> {
    let mut pubkeys = Vec::new();

    for instruction in witness_script.instructions().flatten() {
        if let Instruction::PushBytes(bytes) = instruction {
            let data = bytes.as_bytes();
            if data.len() == 33 && matches!(data[0], 0x02 | 0x03) {
                if let Ok(key) = PublicKey::from_slice(data) {
                    pubkeys.push(key);
                }
            }
        }
    }

    if pubkeys.is_empty() {
        return Err(Error::UnsupportedScriptType(
            "No valid compressed public keys found in witness script".to_string(),
        ));
    }

    Ok(pubkeys)
}

/// Detects the signature format from raw signature bytes.
pub fn detect_signature_format(signature_bytes: &[u8]) -> Result<SignatureFormat, Error> {
    if signature_bytes.len() == 65 {
        let recovery_flag = signature_bytes[0];
        if (27..=34).contains(&recovery_flag) {
            return Ok(SignatureFormat::Legacy);
        }
        // 65 bytes but invalid recovery flag — not a valid format
        return Err(Error::InvalidFormat(
            "65-byte signature with invalid recovery flag".to_string(),
        ));
    }

    let mut cursor = bitcoin::io::Cursor::new(signature_bytes);

    // decode full format
    if let Ok(tx) = Transaction::consensus_decode_from_finite_reader(&mut cursor) {
        if cursor.position() as usize == signature_bytes.len() {
            return if tx.input.len() > 1 {
                Ok(SignatureFormat::FullProofOfFunds)
            } else {
                Ok(SignatureFormat::Full)
            };
        }
    }

    // decode simple format
    let mut cursor = bitcoin::io::Cursor::new(signature_bytes);
    if Witness::consensus_decode_from_finite_reader(&mut cursor).is_ok()
        && cursor.position() as usize == signature_bytes.len()
    {
        return Ok(SignatureFormat::Simple);
    }

    Err(Error::InvalidSignature(
        "Bytes match no format (not 65-byte legacy, not a full transaction, not a witness stack)"
            .to_string(),
    ))
}

pub fn derive_tx_params(
    wallet: &Wallet,
    script_pubkey: &ScriptBuf,
) -> (Version, LockTime, Sequence) {
    let defaults = (Version(0), LockTime::ZERO, Sequence::ZERO);

    let Some((keychain, index)) = wallet.derivation_of_spk(script_pubkey.clone()) else {
        return defaults;
    };

    let descriptor = wallet.public_descriptor(keychain);
    let Ok(derived) = descriptor.at_derivation_index(index) else {
        return defaults;
    };

    match extract_timelocks(&derived) {
        (None, None) => defaults,
        (Some(seq), None) => (Version(2), LockTime::ZERO, seq),
        (None, Some(lt)) => (Version(2), lt, Sequence::ZERO),
        (Some(seq), Some(lt)) => (Version(2), lt, seq),
    }
}

/// Extracts the maximum CSV and CLTV requirements from a derived descriptor.
fn extract_timelocks(
    descriptor: &Descriptor<bdk_wallet::miniscript::DefiniteDescriptorKey>,
) -> (Option<Sequence>, Option<LockTime>) {
    let (csv, cltv) = match descriptor {
        Descriptor::Wsh(wsh) => match wsh.as_inner() {
            WshInner::Ms(ms) => find_timelocks(ms),
            WshInner::SortedMulti(_) => (None, None),
        },
        Descriptor::Sh(sh) => match sh.as_inner() {
            ShInner::Wsh(wsh) => match wsh.as_inner() {
                WshInner::Ms(ms) => find_timelocks(ms),
                WshInner::SortedMulti(_) => (None, None),
            },
            _ => (None, None),
        },
        Descriptor::Tr(tr) => {
            let mut csv = None;
            let mut cltv = None;

            for (_, ms) in tr.iter_scripts() {
                let (found_csv, found_cltv) = find_timelocks(ms);
                csv = max_option(csv, found_csv);
                cltv = max_option(cltv, found_cltv);
            }

            (csv, cltv)
        }
        _ => (None, None),
    };

    (
        csv.map(Sequence::from_consensus),
        cltv.map(LockTime::from_consensus),
    )
}

/// Returns the maximum of two `Option<T>` values.
fn max_option<T: Ord>(a: Option<T>, b: Option<T>) -> Option<T> {
    a.max(b)
}

/// Extract the maximum Older (CSV) and After (CLTV) values.
fn find_timelocks<Ctx: ScriptContext>(
    ms: &Miniscript<bdk_wallet::miniscript::DefiniteDescriptorKey, Ctx>,
) -> (Option<u32>, Option<u32>) {
    let mut max_csv: Option<u32> = None;
    let mut max_cltv: Option<u32> = None;

    for node in ms.iter() {
        match &node.node {
            Terminal::Older(n) => {
                max_csv = max_option(max_csv, Some(n.to_consensus_u32()));
            }
            Terminal::After(n) => {
                max_cltv = max_option(max_cltv, Some(n.to_consensus_u32()));
            }
            _ => {}
        }
    }

    (max_csv, max_cltv)
}

/// Extracts the redeem script from a P2SH script_sig.
pub fn extract_redeem_script(script_sig: &ScriptBuf) -> Result<ScriptBuf, Error> {
    let mut instructions = script_sig.instructions();

    let redeem_script = match instructions.next() {
        Some(Ok(Instruction::PushBytes(bytes))) => ScriptBuf::from_bytes(bytes.as_bytes().to_vec()),
        _ => {
            return Err(Error::InvalidFormat(
                "P2SH scriptSig must start with a push".to_string(),
            ));
        }
    };

    if instructions.next().is_some() {
        return Err(Error::InvalidFormat(
            "P2SH-wrapped SegWit scriptSig must be a single push".to_string(),
        ));
    }

    Ok(redeem_script)
}

/// Configures PSBT input fields for P2SH-wrapped SegWit descriptors.
pub fn configure_p2sh_input(
    psbt_input: &mut bitcoin::psbt::Input,
    derived: &Descriptor<DefiniteDescriptorKey>,
) -> Result<(), Error> {
    let Descriptor::Sh(sh) = derived else {
        return Err(Error::InvalidFormat(
            "Expected Sh descriptor for P2SH scriptPubKey".to_string(),
        ));
    };

    match sh.as_inner() {
        ShInner::Wpkh(wpkh) => {
            let pk = wpkh.as_inner().to_public_key();
            let wpkh_hash = pk
                .wpubkey_hash()
                .map_err(|e| Error::InvalidPublicKey(e.to_string()))?;
            psbt_input.redeem_script = Some(ScriptBuf::new_p2wpkh(&wpkh_hash));
        }
        ShInner::Wsh(wsh) => {
            let witness_script = match wsh.as_inner() {
                WshInner::Ms(ms) => ms.encode(),
                WshInner::SortedMulti(sm) => sm.encode(),
            };
            let wsh_hash = witness_script.wscript_hash();
            psbt_input.redeem_script = Some(ScriptBuf::new_p2wsh(&wsh_hash));
            psbt_input.witness_script = Some(witness_script);
        }
        _ => {
            return Err(Error::UnsupportedScriptType(
                "Only P2SH-P2WPKH and P2SH-P2WSH are supported".to_string(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use bitcoin::Address;
    use core::str::FromStr;

    const HELLO_WORLD_MESSAGE: &str = "Hello World";
    const SEGWIT_ADDRESS: &str = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";

    #[test]
    fn test_message_hashing() {
        let empty_hash = tagged_message_hash(b"");
        let hello_world_hash = tagged_message_hash(b"Hello World");

        assert_eq!(
            empty_hash.to_string(),
            "c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1"
        );
        assert_eq!(
            hello_world_hash.to_string(),
            "f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a"
        );
    }

    #[test]
    fn test_to_spend_and_to_sign() {
        let script_pubkey = Address::from_str(SEGWIT_ADDRESS)
            .unwrap()
            .assume_checked()
            .script_pubkey();

        // Test case for empty message - to_spend
        let tx_spend_empty_msg = to_spend(&script_pubkey, "");
        assert_eq!(
            tx_spend_empty_msg.compute_txid().to_string(),
            "c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7"
        );

        // Test case for "Hello World" - to_spend
        let tx_spend_hello_world_msg = to_spend(&script_pubkey, HELLO_WORLD_MESSAGE);
        assert_eq!(
            tx_spend_hello_world_msg.compute_txid().to_string(),
            "b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b"
        );

        // Test case for empty message - to_sign
        let tx_sign_empty_msg = to_sign(
            &tx_spend_empty_msg,
            Version(0),
            LockTime::ZERO,
            Sequence::ZERO,
        );
        assert_eq!(
            tx_sign_empty_msg.compute_txid().to_string(),
            "1e9654e951a5ba44c8604c4de6c67fd78a27e81dcadcfe1edf638ba3aaebaed6"
        );

        // Test case for HELLO_WORLD_MESSAGE - to_sign
        let tx_sign_hw_msg = to_sign(
            &tx_spend_hello_world_msg,
            Version(0),
            LockTime::ZERO,
            Sequence::ZERO,
        );
        assert_eq!(
            tx_sign_hw_msg.compute_txid().to_string(),
            "88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf"
        );
    }
}
