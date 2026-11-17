use base64::{Engine, engine::general_purpose::STANDARD};
use bdk_wallet::{
    KeychainKind, SignOptions, Wallet,
    bitcoin::{Address, OutPoint, Psbt, ScriptBuf, Sequence, absolute::LockTime, consensus},
    miniscript::descriptor::DescriptorType,
    signer::SignersContainer,
};
use bip322::{
    FULL_SIGNATURE_PREFIX, LockParams, POF_SIGNATURE_PREFIX, ProofInput, SIMPLE_SIGNATURE_PREFIX,
};

use crate::{Error, MessageProof, MessageSigner, SignatureFormat, verify::check_signature};

impl MessageSigner for Wallet {
    fn sign_message(
        &self,
        address: &Address,
        message: &str,
        format: SignatureFormat,
        signers: &[&SignersContainer],
    ) -> Result<MessageProof, Error> {
        let script_pubkey = address.script_pubkey();
        let (keychain, index) = self
            .derivation_of_spk(script_pubkey.clone())
            .ok_or(Error::AddressNotInWallet)?;

        let (utxos, locks): (&[OutPoint], LockParams) = match &format {
            SignatureFormat::Simple => (&[], LockParams::default()),
            SignatureFormat::Full(locks) => (&[], *locks),
            SignatureFormat::ProofOfFunds { utxos, .. } if utxos.is_empty() => {
                return Err(Error::NoProofUtxos);
            }
            SignatureFormat::ProofOfFunds { utxos, locks } => (utxos.as_slice(), *locks),
        };

        let inputs = utxos
            .iter()
            .map(|outpoint| proof_input(self, *outpoint))
            .collect::<Result<Vec<_>, _>>()?;
        let script = witness_or_redeem_script(self, keychain, index)?;
        let psbt = bip322::create_bip322_psbt(address, message, script.as_ref(), &inputs, locks)?;

        self.sign_message_psbt(psbt, &format, signers)
    }

    fn sign_message_psbt(
        &self,
        mut psbt: Psbt,
        format: &SignatureFormat,
        signers: &[&SignersContainer],
    ) -> Result<MessageProof, Error> {
        let request = bip322::detect_bip322_psbt(&psbt).ok_or(Error::NotBip322Psbt)?;
        let message = String::from_utf8(request.message).map_err(|_| Error::NotBip322Psbt)?;
        let challenge = request.message_challenge;
        self.derivation_of_spk(challenge.clone())
            .ok_or(Error::AddressNotInWallet)?;
        let address = Address::from_script(&challenge, self.network())
            .map_err(|_| Error::AddressNotInWallet)?;

        // Only `pof` carries more than one input.
        let proof_of_funds = psbt.inputs.len() > 1;
        if proof_of_funds != matches!(format, SignatureFormat::ProofOfFunds { .. }) {
            return Err(Error::FormatMismatch);
        }

        if let SignatureFormat::Simple = format {
            let to_sign = &psbt.unsigned_tx;
            let no_locks = to_sign.version.0 == 0
                && to_sign.lock_time == LockTime::ZERO
                && to_sign.input[0].sequence == Sequence::ZERO;
            if !challenge.is_witness_program() || !no_locks {
                return Err(Error::SimpleNotSupported);
            }
        }

        // The proof inputs are the claim being signed.
        for index in 1..psbt.inputs.len() {
            check_proof_input(self, &psbt, index)?;
        }

        // A BIP-322 `to_sign` spends a virtual output and can never be broadcast,
        // so the segwit v0 fee attack this option guards against does not apply.
        // `check_proof_input` covers the prevouts the wallet signs for.
        let options = SignOptions {
            trust_witness_utxo: true,
            ..Default::default()
        };
        if !self.sign_with_signers(&mut psbt, signers, options)? {
            return Ok(MessageProof::Psbt(psbt));
        }

        let signature = encode_signature(&psbt, format)?;
        check_signature(&address, &message, &signature)?;
        Ok(MessageProof::Signature(signature))
    }
}

/// Encodes a finalized BIP-322 PSBT as a signature in `format`.
///
/// # Errors
///
/// [`Error::NotFinalized`] if the PSBT has no inputs or an input has no final script.
pub fn encode_signature(psbt: &Psbt, format: &SignatureFormat) -> Result<String, Error> {
    let finalized = !psbt.inputs.is_empty()
        && psbt
            .inputs
            .iter()
            .all(|input| input.final_script_sig.is_some() || input.final_script_witness.is_some());

    let (prefix, bytes) = match format {
        _ if !finalized => return Err(Error::NotFinalized),
        SignatureFormat::ProofOfFunds { .. } => (POF_SIGNATURE_PREFIX, psbt.serialize()),
        SignatureFormat::Simple | SignatureFormat::Full(_) => {
            // `to_sign` has no fee, so the fee rate check does not apply.
            let to_sign = psbt.clone().extract_tx_unchecked_fee_rate();
            match format {
                SignatureFormat::Simple => (
                    SIMPLE_SIGNATURE_PREFIX,
                    consensus::serialize(&to_sign.input[0].witness),
                ),
                _ => (FULL_SIGNATURE_PREFIX, consensus::serialize(&to_sign)),
            }
        }
    };

    Ok(format!("{prefix}{}", STANDARD.encode(bytes)))
}

/// Refuses to sign a proof input whose claimed prevout disagrees with the wallet.
///
/// A wallet UTXO must match every prevout the PSBT gives for it. Any other
/// outpoint must not pay to a wallet script, or the wallet would sign a proof
/// for an output it does not hold, such as a spent or made-up one.
///
/// # Errors
///
/// - [`Error::ProofUtxoMismatch`] if a wallet UTXO's prevout in the PSBT
///   differs from the wallet's record.
/// - [`Error::UtxoNotInWallet`] if the outpoint is not an unspent wallet
///   output but pays to a wallet script.
fn check_proof_input(wallet: &Wallet, psbt: &Psbt, index: usize) -> Result<(), Error> {
    let outpoint = psbt.unsigned_tx.input[index].previous_output;
    let input = &psbt.inputs[index];
    let witness_utxo = input.witness_utxo.as_ref();
    let legacy_utxo = input
        .non_witness_utxo
        .as_ref()
        .map(|tx| (tx.compute_txid(), tx.output.get(outpoint.vout as usize)));

    match wallet.get_utxo(outpoint) {
        Some(utxo) => {
            let witness_matches = witness_utxo.is_none_or(|txout| *txout == utxo.txout);
            let legacy_matches = legacy_utxo
                .is_none_or(|(txid, txout)| txid == outpoint.txid && txout == Some(&utxo.txout));
            if witness_matches && legacy_matches {
                Ok(())
            } else {
                Err(Error::ProofUtxoMismatch(outpoint))
            }
        }
        None => {
            let pays_wallet = witness_utxo
                .into_iter()
                .chain(legacy_utxo.and_then(|(_, txout)| txout))
                .any(|txout| {
                    wallet
                        .derivation_of_spk(txout.script_pubkey.clone())
                        .is_some()
                });
            if pays_wallet {
                Err(Error::UtxoNotInWallet(outpoint))
            } else {
                Ok(())
            }
        }
    }
}

/// Returns the script that the wallet address at `keychain` and `index` hashes.
///
/// # Errors
///
/// [`Error::Descriptor`] if the descriptor cannot produce the script.
fn witness_or_redeem_script(
    wallet: &Wallet,
    keychain: KeychainKind,
    index: u32,
) -> Result<Option<ScriptBuf>, Error> {
    let descriptor = wallet
        .public_descriptor(keychain)
        .at_derivation_index(index)
        .expect("wallet descriptors have no hardened wildcard");

    match descriptor.desc_type() {
        DescriptorType::Sh
        | DescriptorType::ShSortedMulti
        | DescriptorType::Wsh
        | DescriptorType::WshSortedMulti
        | DescriptorType::ShWsh
        | DescriptorType::ShWshSortedMulti => Ok(Some(descriptor.explicit_script()?)),
        _ => Ok(None),
    }
}

/// Builds the proof input for the wallet UTXO at `outpoint`.
///
/// # Errors
///
/// [`Error::UtxoNotInWallet`] if `outpoint` is not an unspent wallet output.
fn proof_input(wallet: &Wallet, outpoint: OutPoint) -> Result<ProofInput, Error> {
    let utxo = wallet
        .get_utxo(outpoint)
        .ok_or(Error::UtxoNotInWallet(outpoint))?;

    Ok(ProofInput {
        outpoint,
        prevout: utxo.txout,
        // bip322 only uses it for legacy inputs, checked against the outpoint.
        prev_tx: wallet
            .get_tx(outpoint.txid)
            .map(|tx| tx.tx_node.tx.as_ref().clone()),
        private_keys: Vec::new(),
        witness_script: witness_or_redeem_script(wallet, utxo.keychain, utxo.derivation_index)?,
    })
}
