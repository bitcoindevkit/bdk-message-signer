use bdk_message_signer::{
    Error, MessageProof, MessageSigner, SignatureFormat,
    bip322::{self, LockParams},
    encode_signature,
};
use bdk_wallet::{
    KeychainKind,
    bitcoin::{Amount, OutPoint, PrivateKey, Sequence, absolute::LockTime, hashes::Hash},
    test_utils::*,
};

mod common;
use common::*;

#[test]
fn simple_and_full_for_native_segwit() {
    let multi = format!("wsh(multi(2,{TPRV_A}/0/*,{TPRV_B}/0/*))");
    for descriptor in [
        get_test_wpkh(),
        get_test_tr_single_sig(),
        // Script path: the internal key has no private key.
        get_test_tr_with_taptree(),
        multi.as_str(),
    ] {
        let (wallet, address, signers) = wallet(descriptor);
        assert_valid(
            &wallet,
            &address,
            &signers,
            SignatureFormat::Simple,
            bip322::SIMPLE_SIGNATURE_PREFIX,
        );
        let full = SignatureFormat::Full(LockParams::default());
        assert_valid(
            &wallet,
            &address,
            &signers,
            full,
            bip322::FULL_SIGNATURE_PREFIX,
        );
    }
}

#[test]
fn full_for_legacy_and_nested() {
    let descriptors = [
        get_test_pkh().to_string(),
        format!("sh(wpkh({TPRV_A}/0/*))"),
        format!("sh(multi(1,{TPRV_A}/0/*))"),
        format!("sh(wsh(sortedmulti(2,{TPRV_A}/0/*,{TPRV_B}/0/*)))"),
    ];
    for descriptor in &descriptors {
        let (wallet, address, signers) = wallet(descriptor);
        let full = SignatureFormat::Full(LockParams::default());
        assert_valid(
            &wallet,
            &address,
            &signers,
            full,
            bip322::FULL_SIGNATURE_PREFIX,
        );
        assert!(matches!(
            wallet.sign_message(&address, MESSAGE, SignatureFormat::Simple, &[&signers]),
            Err(Error::SimpleNotSupported)
        ));
    }
}

#[test]
fn proof_of_funds() {
    for descriptor in [get_test_wpkh(), get_test_tr_single_sig(), get_test_pkh()] {
        let (mut wallet, _) = get_funded_wallet_single(descriptor);
        let address = wallet.reveal_next_address(KeychainKind::External).address;
        let signers = signers(&wallet, descriptor);
        let utxos: Vec<OutPoint> = wallet.list_unspent().map(|utxo| utxo.outpoint).collect();
        assert!(!utxos.is_empty());

        let format = SignatureFormat::ProofOfFunds {
            utxos,
            locks: LockParams::default(),
        };
        assert_valid(
            &wallet,
            &address,
            &signers,
            format,
            bip322::POF_SIGNATURE_PREFIX,
        );
    }
}

#[test]
fn timelocked_descriptor() {
    // wsh(and_v(v:pk(..),older(6))): BDK finalizes it, and bip322's
    // interpreter fallback reports it as Inconclusive, not Invalid.
    let (wallet, address, signers) = wallet(get_test_single_sig_csv());
    let locks = LockParams {
        lock_time: LockTime::ZERO,
        sequence: Sequence(6),
    };
    let signed = wallet
        .sign_message(&address, MESSAGE, SignatureFormat::Full(locks), &[&signers])
        .unwrap();
    assert!(verify(&address, &signature(signed)).is_inconclusive());
}

#[test]
fn no_signers_returns_bip322_psbt() {
    let (wallet, address, _) = wallet(get_test_wpkh());
    let MessageProof::Psbt(psbt) = wallet
        .sign_message(&address, MESSAGE, SignatureFormat::Simple, &[])
        .unwrap()
    else {
        panic!("nothing signed, nothing to finalize");
    };
    // A hardware signer can detect it and show it as a message.
    let detected = bip322::detect_bip322_psbt(&psbt).unwrap();
    assert_eq!(detected.message, MESSAGE.as_bytes());
}

#[test]
fn multisig_cosigner_signs_bip322_psbt() {
    let (a, address, a_signers) =
        wallet(&format!("wsh(multi(2,{TPRV_A}/0/*,{}/0/*))", tpub(TPRV_B)));
    let (b, _, b_signers) = wallet(&format!("wsh(multi(2,{}/0/*,{TPRV_B}/0/*))", tpub(TPRV_A)));

    let format = SignatureFormat::Full(LockParams::default());
    let signed = a
        .sign_message(&address, MESSAGE, format.clone(), &[&a_signers])
        .unwrap();
    let MessageProof::Psbt(psbt) = signed else {
        panic!("one key cannot finalize a 2-of-2");
    };
    assert!(matches!(
        encode_signature(&psbt, &format),
        Err(Error::NotFinalized)
    ));

    // The cosigner shows the request, then signs, finalizes and encodes.
    let request = bip322::detect_bip322_psbt(&psbt).unwrap();
    assert_eq!(request.message, MESSAGE.as_bytes());
    assert_eq!(request.message_challenge, address.script_pubkey());

    let signed = b.sign_message_psbt(psbt, &format, &[&b_signers]).unwrap();
    assert!(verify(&address, &signature(signed)).is_valid());
}

#[test]
fn hardware_signer_then_wallet_finalizes() {
    let (wallet, address, _) = wallet(get_test_wpkh());
    let MessageProof::Psbt(mut psbt) = wallet
        .sign_message(&address, MESSAGE, SignatureFormat::Simple, &[])
        .unwrap()
    else {
        panic!("nothing signed, nothing to finalize");
    };

    // Stand-in for a hardware signer: adds a partial signature only.
    let key = PrivateKey::from_wif("cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW").unwrap();
    bip322::sign_bip322_psbt_input(&mut psbt, &key, 0).unwrap();

    let signed = wallet
        .sign_message_psbt(psbt, &SignatureFormat::Simple, &[])
        .unwrap();
    assert!(verify(&address, &signature(signed)).is_valid());
}

#[test]
fn sign_message_psbt_checks_format() {
    let (mut wallet, _) = get_funded_wallet_single(get_test_wpkh());
    let address = wallet.reveal_next_address(KeychainKind::External).address;
    let utxos: Vec<OutPoint> = wallet.list_unspent().map(|utxo| utxo.outpoint).collect();
    let format = SignatureFormat::ProofOfFunds {
        utxos,
        locks: LockParams::default(),
    };
    let MessageProof::Psbt(psbt) = wallet.sign_message(&address, MESSAGE, format, &[]).unwrap()
    else {
        panic!("nothing signed, nothing to finalize");
    };

    assert!(matches!(
        wallet.sign_message_psbt(psbt, &SignatureFormat::Full(LockParams::default()), &[]),
        Err(Error::FormatMismatch)
    ));
}

#[test]
fn sign_message_psbt_refuses_false_proofs() {
    let (mut wallet, _) = get_funded_wallet_single(get_test_wpkh());
    let signers = signers(&wallet, get_test_wpkh());
    let address = wallet.reveal_next_address(KeychainKind::External).address;
    let utxo = wallet.list_unspent().next().unwrap().outpoint;
    let format = SignatureFormat::ProofOfFunds {
        utxos: vec![utxo],
        locks: LockParams::default(),
    };
    let unsigned = || match wallet
        .sign_message(&address, MESSAGE, format.clone(), &[])
        .unwrap()
    {
        MessageProof::Psbt(psbt) => psbt,
        MessageProof::Signature(_) => panic!("nothing signed, nothing to finalize"),
    };

    // A coordinator inflates the amount of a wallet UTXO.
    let mut inflated = unsigned();
    inflated.inputs[1].witness_utxo.as_mut().unwrap().value = Amount::MAX_MONEY;
    assert!(matches!(
        wallet.sign_message_psbt(inflated, &format, &[&signers]),
        Err(Error::ProofUtxoMismatch(outpoint)) if outpoint == utxo
    ));

    // A coordinator claims an outpoint the wallet does not hold, paid to it.
    let mut made_up = unsigned();
    let fake = OutPoint::new(Hash::all_zeros(), 9);
    made_up.unsigned_tx.input[1].previous_output = fake;
    assert!(matches!(
        wallet.sign_message_psbt(made_up, &format, &[&signers]),
        Err(Error::UtxoNotInWallet(outpoint)) if outpoint == fake
    ));
}

#[test]
fn sign_message_psbt_checks_simple_rules() {
    let (wallet, address, signers) = wallet(get_test_wpkh());
    let locks = LockParams {
        lock_time: LockTime::from_height(100).unwrap(),
        sequence: Sequence::ZERO,
    };
    let MessageProof::Psbt(psbt) = wallet
        .sign_message(&address, MESSAGE, SignatureFormat::Full(locks), &[])
        .unwrap()
    else {
        panic!("nothing signed, nothing to finalize");
    };
    assert!(matches!(
        wallet.sign_message_psbt(psbt, &SignatureFormat::Simple, &[&signers]),
        Err(Error::SimpleNotSupported)
    ));
}

#[test]
fn bip322_finalizer_for_standard_scripts() {
    let (wallet, address, _) = wallet(get_test_wpkh());
    let MessageProof::Psbt(mut psbt) = wallet
        .sign_message(
            &address,
            MESSAGE,
            SignatureFormat::Full(LockParams::default()),
            &[],
        )
        .unwrap()
    else {
        panic!("nothing signed, nothing to finalize");
    };

    // An external signer adds a partial signature, then bip322 finalizes.
    let key = PrivateKey::from_wif("cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW").unwrap();
    bip322::sign_bip322_psbt_input(&mut psbt, &key, 0).unwrap();
    let signature = bdk_message_signer::finalize_bip322_psbt(psbt).unwrap();

    assert!(signature.starts_with(bdk_message_signer::FULL_SIGNATURE_PREFIX));
    assert!(verify(&address, &signature).is_valid());
}

#[test]
fn sign_message_psbt_refuses_transactions() {
    let (mut wallet, _) = get_funded_wallet_single(get_test_wpkh());
    let signers = signers(&wallet, get_test_wpkh());
    let recipient = wallet.reveal_next_address(KeychainKind::External).address;

    let mut builder = wallet.build_tx();
    builder.add_recipient(recipient.script_pubkey(), Amount::from_sat(10_000));
    let spend = builder.finish().unwrap();

    let format = SignatureFormat::Full(LockParams::default());
    assert!(matches!(
        wallet.sign_message_psbt(spend, &format, &[&signers]),
        Err(Error::NotBip322Psbt)
    ));
}
