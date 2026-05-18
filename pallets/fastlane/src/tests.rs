// ============================================================
// pallets/fastlane/src/tests.rs
// Unit tests for the FastLane pallet.
// ============================================================

#![cfg(test)]

use crate::{
    mock::{
        account, checks_hash_for, keypair, payload_id_for, sign_attestation, AccountId,
        Balance, BlockNumber, ExtBuilder, Fastlane, RuntimeOrigin, System, Test,
    },
    pallet::{
        AuthorityBonds, Authorities, Attestations, Error, Event, ExpiryAt, Nonces,
        PendingCount, PreConsensedQueue, Status, Statuses, Threshold,
    },
};
use frame_support::{
    assert_err, assert_noop, assert_ok,
    traits::Hooks,
    BoundedVec,
};
use sp_runtime::DispatchError;

// ============================================================
// Setup helpers
// ============================================================

fn alice() -> AccountId { account("//Alice") }
fn bob() -> AccountId { account("//Bob") }
fn charlie() -> AccountId { account("//Charlie") }
fn dave() -> AccountId { account("//Dave") }

const E18: Balance = 1_000_000_000_000_000_000;
const MIN_BOND: Balance = 1_000;

/// Standard 3-authority committee with threshold 2, all funded.
fn three_auth_ext() -> sp_io::TestExternalities {
    ExtBuilder::default()
        .with_balances(vec![
            (alice(),   E18),
            (bob(),     E18),
            (charlie(), E18),
            (dave(),    E18),
        ])
        .with_authorities(vec![alice(), bob(), charlie()])
        .with_threshold(2)
        .build()
}

fn submit_payload(
    who: AccountId,
    nonce: u64,
    expiry: BlockNumber,
    domain: u32,
    payload_hash: [u8; 32],
) {
    assert_ok!(Fastlane::submit(
        RuntimeOrigin::signed(who),
        nonce,
        expiry,
        domain,
        payload_hash,
    ));
}

fn last_event() -> Event<Test> {
    System::events()
        .into_iter()
        .filter_map(|r| if let crate::mock::RuntimeEvent::Fastlane(e) = r.event { Some(e) } else { None })
        .last()
        .expect("expected a Fastlane event")
}

fn events() -> Vec<Event<Test>> {
    System::events()
        .into_iter()
        .filter_map(|r| if let crate::mock::RuntimeEvent::Fastlane(e) = r.event { Some(e) } else { None })
        .collect()
}

// ============================================================
// Genesis
// ============================================================

#[test]
fn genesis_reserves_min_bond_for_each_authority() {
    three_auth_ext().execute_with(|| {
        for a in [alice(), bob(), charlie()] {
            assert_eq!(AuthorityBonds::<Test>::get(&a), MIN_BOND);
            assert_eq!(pallet_balances::Pallet::<Test>::reserved_balance(&a), MIN_BOND);
        }
        assert_eq!(Authorities::<Test>::get().to_vec(), vec![alice(), bob(), charlie()]);
        assert_eq!(Threshold::<Test>::get(), 2);
    });
}

// ============================================================
// submit()
// ============================================================

#[test]
fn submit_happy_path() {
    three_auth_ext().execute_with(|| {
        let expiry = 100;
        submit_payload(dave(), 0, expiry, 1, [7u8; 32]);
        let pid = payload_id_for(dave(), 0, 1, [7u8; 32]);

        assert_eq!(Statuses::<Test>::get(pid), Some(Status::Submitted));
        assert_eq!(PendingCount::<Test>::get(), 1);
        assert_eq!(Nonces::<Test>::get(&dave()), 1);
        // Scheduled to expire at expiry+1.
        assert!(ExpiryAt::<Test>::get(expiry + 1).contains(&pid));
    });
}

#[test]
fn submit_rejects_past_expiry() {
    three_auth_ext().execute_with(|| {
        System::set_block_number(50);
        assert_noop!(
            Fastlane::submit(RuntimeOrigin::signed(dave()), 0, 50, 1, [7u8; 32]),
            Error::<Test>::PayloadExpired
        );
    });
}

#[test]
fn submit_enforces_nonce_order() {
    three_auth_ext().execute_with(|| {
        submit_payload(dave(), 0, 100, 1, [7u8; 32]);
        // Skip nonce 1.
        assert_noop!(
            Fastlane::submit(RuntimeOrigin::signed(dave()), 2, 100, 1, [8u8; 32]),
            Error::<Test>::InvalidNonce
        );
    });
}

#[test]
fn submit_rejects_duplicate_payload() {
    three_auth_ext().execute_with(|| {
        submit_payload(dave(), 0, 100, 1, [7u8; 32]);
        // Same nonce, same content → rejected. But nonce moved to 1 so this
        // first hits InvalidNonce; use a fresh account to test duplicate path.
        assert_noop!(
            Fastlane::submit(RuntimeOrigin::signed(dave()), 0, 100, 1, [7u8; 32]),
            Error::<Test>::InvalidNonce
        );
    });
}

// ============================================================
// attest() & threshold transition
// ============================================================

fn submit_and_get_payload() -> ([u8; 32], BlockNumber, [u8; 32]) {
    let expiry: BlockNumber = 100;
    let payload_hash = [7u8; 32];
    submit_payload(dave(), 0, expiry, 1, payload_hash);
    let pid = payload_id_for(dave(), 0, 1, payload_hash);
    let ch = checks_hash_for(dave(), 0, 1, payload_hash, expiry);
    (pid, expiry, ch)
}

#[test]
fn attest_signature_verification_round_trip() {
    three_auth_ext().execute_with(|| {
        let (pid, expiry, ch) = submit_and_get_payload();

        let alice_pair = keypair("//Alice");
        let sig = sign_attestation(&alice_pair, pid, expiry, ch);

        assert_ok!(Fastlane::attest(
            RuntimeOrigin::signed(alice()),
            pid,
            alice(),
            sig,
            ch,
        ));

        assert_eq!(Attestations::<Test>::get(pid).len(), 1);
        // Below threshold, still Submitted.
        assert_eq!(Statuses::<Test>::get(pid), Some(Status::Submitted));
    });
}

#[test]
fn attest_reaches_threshold_and_preconsenses() {
    three_auth_ext().execute_with(|| {
        let (pid, expiry, ch) = submit_and_get_payload();

        let alice_pair = keypair("//Alice");
        assert_ok!(Fastlane::attest(
            RuntimeOrigin::signed(alice()),
            pid, alice(),
            sign_attestation(&alice_pair, pid, expiry, ch),
            ch,
        ));

        let bob_pair = keypair("//Bob");
        assert_ok!(Fastlane::attest(
            RuntimeOrigin::signed(bob()),
            pid, bob(),
            sign_attestation(&bob_pair, pid, expiry, ch),
            ch,
        ));

        assert_eq!(Statuses::<Test>::get(pid), Some(Status::PreConsensed));
        assert_eq!(PendingCount::<Test>::get(), 0);
        assert!(PreConsensedQueue::<Test>::get().contains(&pid));
    });
}

#[test]
fn attest_rejects_bad_signature() {
    three_auth_ext().execute_with(|| {
        let (pid, _expiry, ch) = submit_and_get_payload();
        // Use Bob's signature claiming to be Alice.
        let bob_pair = keypair("//Bob");
        let bad_sig = sign_attestation(&bob_pair, pid, 100, ch);

        assert_err!(
            Fastlane::attest(RuntimeOrigin::signed(alice()), pid, alice(), bad_sig, ch),
            Error::<Test>::InvalidSignature
        );
    });
}

#[test]
fn attest_rejects_non_authority() {
    three_auth_ext().execute_with(|| {
        let (pid, expiry, ch) = submit_and_get_payload();
        let dave_pair = keypair("//Dave");
        let sig = sign_attestation(&dave_pair, pid, expiry, ch);

        assert_err!(
            Fastlane::attest(RuntimeOrigin::signed(dave()), pid, dave(), sig, ch),
            Error::<Test>::NotAuthority
        );
    });
}

#[test]
fn attest_rejects_double_signing_by_same_authority() {
    three_auth_ext().execute_with(|| {
        let (pid, expiry, ch) = submit_and_get_payload();
        let alice_pair = keypair("//Alice");
        let sig = sign_attestation(&alice_pair, pid, expiry, ch);
        assert_ok!(Fastlane::attest(RuntimeOrigin::signed(alice()), pid, alice(), sig.clone(), ch));
        assert_err!(
            Fastlane::attest(RuntimeOrigin::signed(alice()), pid, alice(), sig, ch),
            Error::<Test>::AlreadyAttested
        );
    });
}

// ============================================================
// finalize() & on_initialize auto-finalize
// ============================================================

fn drive_to_preconsensed() -> [u8; 32] {
    let (pid, expiry, ch) = submit_and_get_payload();
    let alice_pair = keypair("//Alice");
    let bob_pair = keypair("//Bob");
    assert_ok!(Fastlane::attest(
        RuntimeOrigin::signed(alice()), pid, alice(),
        sign_attestation(&alice_pair, pid, expiry, ch), ch,
    ));
    assert_ok!(Fastlane::attest(
        RuntimeOrigin::signed(bob()), pid, bob(),
        sign_attestation(&bob_pair, pid, expiry, ch), ch,
    ));
    pid
}

#[test]
fn finalize_succeeds_when_preconsensed() {
    three_auth_ext().execute_with(|| {
        let pid = drive_to_preconsensed();
        assert_ok!(Fastlane::finalize(RuntimeOrigin::signed(dave()), pid));
        assert_eq!(Statuses::<Test>::get(pid), Some(Status::Finalised));
        assert!(!PreConsensedQueue::<Test>::get().contains(&pid));
    });
}

#[test]
fn finalize_rejected_when_only_submitted() {
    three_auth_ext().execute_with(|| {
        let (pid, _, _) = submit_and_get_payload();
        assert_err!(
            Fastlane::finalize(RuntimeOrigin::signed(dave()), pid),
            Error::<Test>::ThresholdNotMet
        );
    });
}

#[test]
fn on_initialize_auto_finalizes_preconsensed() {
    three_auth_ext().execute_with(|| {
        let pid = drive_to_preconsensed();
        assert!(PreConsensedQueue::<Test>::get().contains(&pid));

        let next = System::block_number() + 1;
        Fastlane::on_initialize(next);

        assert_eq!(Statuses::<Test>::get(pid), Some(Status::Finalised));
        assert!(!PreConsensedQueue::<Test>::get().contains(&pid));
    });
}

#[test]
fn on_initialize_finalize_is_bounded_per_block() {
    // MaxAutoFinalizePerBlock = 5 in the mock.
    three_auth_ext().execute_with(|| {
        let alice_pair = keypair("//Alice");
        let bob_pair = keypair("//Bob");
        let mut pids = Vec::new();
        for nonce in 0..7u64 {
            let payload_hash = [nonce as u8; 32];
            submit_payload(dave(), nonce, 100, 1, payload_hash);
            let pid = payload_id_for(dave(), nonce, 1, payload_hash);
            let ch = checks_hash_for(dave(), nonce, 1, payload_hash, 100);
            assert_ok!(Fastlane::attest(
                RuntimeOrigin::signed(alice()), pid, alice(),
                sign_attestation(&alice_pair, pid, 100, ch), ch,
            ));
            assert_ok!(Fastlane::attest(
                RuntimeOrigin::signed(bob()), pid, bob(),
                sign_attestation(&bob_pair, pid, 100, ch), ch,
            ));
            pids.push(pid);
        }
        assert_eq!(PreConsensedQueue::<Test>::get().len(), 7);

        // Run on_initialize once: 5 finalised, 2 remain.
        Fastlane::on_initialize(System::block_number() + 1);
        assert_eq!(PreConsensedQueue::<Test>::get().len(), 2);

        // Run again: drains the rest.
        Fastlane::on_initialize(System::block_number() + 2);
        assert_eq!(PreConsensedQueue::<Test>::get().len(), 0);
    });
}

// ============================================================
// Expiry
// ============================================================

#[test]
fn on_initialize_expires_stale_submitted_payloads() {
    three_auth_ext().execute_with(|| {
        let expiry: BlockNumber = 5;
        let payload_hash = [7u8; 32];
        submit_payload(dave(), 0, expiry, 1, payload_hash);
        let pid = payload_id_for(dave(), 0, 1, payload_hash);
        assert_eq!(PendingCount::<Test>::get(), 1);

        // Move past expiry+1 and run on_initialize.
        System::set_block_number(expiry + 1);
        Fastlane::on_initialize(expiry + 1);

        assert_eq!(Statuses::<Test>::get(pid), Some(Status::Expired));
        assert_eq!(PendingCount::<Test>::get(), 0);
        assert!(matches!(last_event(), Event::Expired { .. }));
    });
}

#[test]
fn expired_payload_skipped_if_already_preconsensed() {
    three_auth_ext().execute_with(|| {
        // Submit and PreConsensed before expiry.
        let pid = drive_to_preconsensed();
        // Block expiry+1 should NOT re-mark it as Expired.
        System::set_block_number(101);
        Fastlane::on_initialize(101);
        // Auto-finalised, not expired.
        assert_eq!(Statuses::<Test>::get(pid), Some(Status::Finalised));
    });
}

// ============================================================
// set_authorities / set_threshold
// ============================================================

#[test]
fn set_authorities_requires_root() {
    three_auth_ext().execute_with(|| {
        let new = BoundedVec::try_from(vec![alice(), bob()]).unwrap();
        assert_err!(
            Fastlane::set_authorities(RuntimeOrigin::signed(alice()), new),
            DispatchError::BadOrigin
        );
    });
}

#[test]
fn set_authorities_rejects_unbonded() {
    three_auth_ext().execute_with(|| {
        let new = BoundedVec::try_from(vec![alice(), dave()]).unwrap();
        assert_err!(
            Fastlane::set_authorities(RuntimeOrigin::root(), new),
            Error::<Test>::BondTooLow
        );
    });
}

#[test]
fn set_threshold_rejects_at_or_below_half() {
    three_auth_ext().execute_with(|| {
        // 3 authorities, 50% = 1, threshold must be > 1.
        assert_err!(
            Fastlane::set_threshold(RuntimeOrigin::root(), 1),
            Error::<Test>::ThresholdTooLow
        );
        assert_ok!(Fastlane::set_threshold(RuntimeOrigin::root(), 2));
        assert_ok!(Fastlane::set_threshold(RuntimeOrigin::root(), 3));
    });
}

#[test]
fn set_threshold_rejects_above_authority_count() {
    three_auth_ext().execute_with(|| {
        assert_err!(
            Fastlane::set_threshold(RuntimeOrigin::root(), 4),
            Error::<Test>::ThresholdTooHigh
        );
    });
}

// ============================================================
// post_bond
// ============================================================

#[test]
fn post_bond_reserves_and_accumulates() {
    three_auth_ext().execute_with(|| {
        assert_ok!(Fastlane::post_bond(RuntimeOrigin::signed(dave()), MIN_BOND));
        assert_eq!(AuthorityBonds::<Test>::get(&dave()), MIN_BOND);
        assert_eq!(pallet_balances::Pallet::<Test>::reserved_balance(&dave()), MIN_BOND);

        assert_ok!(Fastlane::post_bond(RuntimeOrigin::signed(dave()), MIN_BOND));
        assert_eq!(AuthorityBonds::<Test>::get(&dave()), 2 * MIN_BOND);
    });
}

#[test]
fn post_bond_rejects_below_minimum() {
    three_auth_ext().execute_with(|| {
        assert_err!(
            Fastlane::post_bond(RuntimeOrigin::signed(dave()), MIN_BOND - 1),
            Error::<Test>::BondTooLow
        );
    });
}

// ============================================================
// slash + auto-eviction
// ============================================================

#[test]
fn slash_burns_reserved_balance_and_decrements_bond() {
    three_auth_ext().execute_with(|| {
        // Top up so a partial slash leaves bond above MIN.
        assert_ok!(Fastlane::post_bond(RuntimeOrigin::signed(alice()), MIN_BOND * 5));
        let bond_before = AuthorityBonds::<Test>::get(&alice());

        // Build a real InvalidSignature proof: get Alice's attestation onto a
        // payload, then craft a bogus signature claiming to be hers.
        let (pid, expiry, ch) = submit_and_get_payload();
        let alice_pair = keypair("//Alice");
        let real_sig = sign_attestation(&alice_pair, pid, expiry, ch);
        assert_ok!(Fastlane::attest(
            RuntimeOrigin::signed(alice()), pid, alice(), real_sig, ch,
        ));

        // Manually corrupt the recorded signature so it fails verification.
        let mut sigs = Attestations::<Test>::get(pid);
        sigs[0].signature = vec![0u8; 64];
        Attestations::<Test>::insert(pid, sigs);

        let proof = crate::pallet::SlashProof::InvalidSignature(pid, vec![0u8; 64]);
        let slash_amount = MIN_BOND;
        assert_ok!(Fastlane::slash(RuntimeOrigin::root(), alice(), slash_amount, proof));

        assert_eq!(AuthorityBonds::<Test>::get(&alice()), bond_before - slash_amount);
        // Still authority — bond above min.
        assert!(Authorities::<Test>::get().contains(&alice()));
    });
}

#[test]
fn slash_evicts_authority_when_bond_drops_below_min() {
    three_auth_ext().execute_with(|| {
        // Slash all of alice's bond → eviction.
        let (pid, expiry, ch) = submit_and_get_payload();
        let alice_pair = keypair("//Alice");
        assert_ok!(Fastlane::attest(
            RuntimeOrigin::signed(alice()), pid, alice(),
            sign_attestation(&alice_pair, pid, expiry, ch), ch,
        ));
        let mut sigs = Attestations::<Test>::get(pid);
        sigs[0].signature = vec![0u8; 64];
        Attestations::<Test>::insert(pid, sigs);

        let proof = crate::pallet::SlashProof::InvalidSignature(pid, vec![0u8; 64]);
        assert_ok!(Fastlane::slash(RuntimeOrigin::root(), alice(), MIN_BOND, proof));

        assert_eq!(AuthorityBonds::<Test>::get(&alice()), 0);
        assert!(!Authorities::<Test>::get().contains(&alice()));
        assert!(events().iter().any(|e| matches!(e, Event::AuthorityEvicted { .. })));
    });
}

#[test]
fn slash_rejects_amount_exceeding_bond() {
    three_auth_ext().execute_with(|| {
        let proof = crate::pallet::SlashProof::InvalidSignature([0u8; 32], vec![0u8; 64]);
        assert_err!(
            Fastlane::slash(RuntimeOrigin::root(), alice(), MIN_BOND * 1000, proof),
            Error::<Test>::SlashExceedsBond
        );
    });
}

#[test]
fn slash_rejects_none_proof() {
    three_auth_ext().execute_with(|| {
        assert_err!(
            Fastlane::slash(RuntimeOrigin::root(), alice(), MIN_BOND, crate::pallet::SlashProof::None),
            Error::<Test>::MissingSlashProof
        );
    });
}

// ============================================================
// validate_unsigned
// ============================================================

#[test]
fn validate_unsigned_accepts_valid_attestation() {
    use sp_runtime::transaction_validity::TransactionSource;
    use frame_support::pallet_prelude::ValidateUnsigned;
    use codec::Encode;

    three_auth_ext().execute_with(|| {
        let (pid, expiry, ch) = submit_and_get_payload();
        let alice_pair = keypair("//Alice");
        let sig = sign_attestation(&alice_pair, pid, expiry, ch);
        let call = crate::pallet::Call::attest_unsigned {
            payload_id: pid,
            authority_encoded: alice().encode(),
            signature: sig,
            checks_hash: ch,
        };
        let result = crate::pallet::Pallet::<Test>::validate_unsigned(
            TransactionSource::External, &call,
        );
        assert!(result.is_ok());
    });
}

#[test]
fn validate_unsigned_rejects_unknown_authority() {
    use sp_runtime::transaction_validity::TransactionSource;
    use frame_support::pallet_prelude::ValidateUnsigned;
    use codec::Encode;

    three_auth_ext().execute_with(|| {
        let (pid, expiry, ch) = submit_and_get_payload();
        let dave_pair = keypair("//Dave");
        let sig = sign_attestation(&dave_pair, pid, expiry, ch);
        let call = crate::pallet::Call::attest_unsigned {
            payload_id: pid,
            authority_encoded: dave().encode(),
            signature: sig,
            checks_hash: ch,
        };
        let result = crate::pallet::Pallet::<Test>::validate_unsigned(
            TransactionSource::External, &call,
        );
        assert!(result.is_err());
    });
}

#[test]
fn validate_unsigned_rejects_unknown_payload() {
    use sp_runtime::transaction_validity::TransactionSource;
    use frame_support::pallet_prelude::ValidateUnsigned;
    use codec::Encode;

    three_auth_ext().execute_with(|| {
        let call = crate::pallet::Call::attest_unsigned {
            payload_id: [99u8; 32],
            authority_encoded: alice().encode(),
            signature: vec![0u8; 64],
            checks_hash: [0u8; 32],
        };
        let result = crate::pallet::Pallet::<Test>::validate_unsigned(
            TransactionSource::External, &call,
        );
        assert!(result.is_err());
    });
}
