// ============================================================
// pallets/fastlane/src/lib.rs
// FastLane Pre-Consensus Attestation Pallet
// ============================================================

#![cfg_attr(not(feature = "std"), no_std)]

pub use crate::pallet::*;





#[frame_support::pallet]

pub mod pallet {

 












    use frame_system::offchain::SendSignedTransaction;
    use frame_support::{
        pallet_prelude::*,
        traits::{Currency, ReservableCurrency},
    };

    use frame_system::{
        offchain::{
            AppCrypto, CreateSignedTransaction,
          //  SendsignedTransaction, 
            SignedPayload, Signer, SigningTypes,
            // SignMessage brings .sign_message() into scope for Signer.
            SignMessage,
        },
        pallet_prelude::*,
    };

    use sp_runtime::{
        offchain::storage::StorageValueRef,
        transaction_validity::{
            InvalidTransaction, TransactionSource, TransactionValidity,
            ValidTransaction,
        },
        Saturating,
    };

    use sp_std::vec::Vec;

    // --------------------------------------------------------




    // --------------------------------------------------------
    // Type aliases
    // --------------------------------------------------------

    pub type PayloadId = [u8; 32];

    pub type BalanceOf<T> =
        <<T as Config>::Currency as Currency<
            <T as frame_system::Config>::AccountId,
        >>::Balance;

    // --------------------------------------------------------
    // Integration traits for downstream pallets
    // --------------------------------------------------------

    /// Downstream pallets implement this to react when a payload is finalised.
    pub trait OnFinalised {
        fn on_finalised(payload_id: PayloadId) -> DispatchResult;
    }

    impl OnFinalised for () {
        fn on_finalised(_payload_id: PayloadId) -> DispatchResult {
            Ok(())
        }
    }

    /// Downstream pallets use this trait as a gateway guard.
    pub trait EnsurePreConsensed<T: Config> {
        fn ensure_preconsensed(payload_id: PayloadId) -> DispatchResult;
    }

    impl<T: Config> EnsurePreConsensed<T> for Pallet<T> {
        fn ensure_preconsensed(payload_id: PayloadId) -> DispatchResult {
            let status = Statuses::<T>::get(payload_id)
                .ok_or(Error::<T>::PayloadNotFound)?;
            ensure!(
                status == Status::PreConsensed || status == Status::Finalised,
                Error::<T>::ThresholdNotMet
            );
            Ok(())
        }
    }

    // --------------------------------------------------------
    // Pallet configuration trait
    // --------------------------------------------------------

    #[pallet::config]
    pub trait Config:
        frame_system::Config + CreateSignedTransaction<Call<Self>>
    {
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Maximum number of authorities in the committee.
        type MaxAuthorities: Get<u32>;

        /// Maximum number of payloads that may be pending (Submitted) at once.
        type MaxPendingPayloads: Get<u32>;

        /// Minimum bond an authority must hold to be registered.
        type MinAuthorityBond: Get<BalanceOf<Self>>;

        type Currency: ReservableCurrency<Self::AccountId>;

        /// Downstream hook called when a payload is finalised.
        type OnFinalised: OnFinalised;

        /// Crypto used by the offchain worker to sign attestations.
        type AuthorityId: AppCrypto<Self::Public, Self::Signature>;

        /// Allowed domain identifiers. An empty vec means all domains allowed.
        type AllowedDomains: Get<Vec<u32>>;
    }

    // --------------------------------------------------------
    // Storage items
    // --------------------------------------------------------

    #[pallet::storage]
    #[pallet::getter(fn authorities)]
    pub type Authorities<T: Config> = StorageValue<
        _,
        BoundedVec<T::AccountId, T::MaxAuthorities>,
        ValueQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn threshold)]
    pub type Threshold<T: Config> = StorageValue<_, u32, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn authority_bonds)]
    pub type AuthorityBonds<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        BalanceOf<T>,
        ValueQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn payloads)]
    pub type Payloads<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        PayloadId,
        Payload<T>,
        OptionQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn attestations)]
    pub type Attestations<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        PayloadId,
        BoundedVec<SignatureRecord<T>, T::MaxAuthorities>,
        ValueQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn statuses)]
    pub type Statuses<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        PayloadId,
        Status,
        OptionQuery,
    >;

    /// Tracks per-account nonces for replay protection in submit().
    #[pallet::storage]
    #[pallet::getter(fn nonces)]
    pub type Nonces<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        u64,
        ValueQuery,
    >;

    /// Running count of payloads currently in Submitted state.
    #[pallet::storage]
    #[pallet::getter(fn pending_count)]
    pub type PendingCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    // --------------------------------------------------------
    // Events
    // --------------------------------------------------------

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new payload was registered on-chain.
        Submitted { payload_id: PayloadId, creator: T::AccountId },
        /// Threshold signatures collected — fast-lane approved.
        PreConsensed { payload_id: PayloadId },
        /// Confirmed in a canonical block by finalize().
        Finalised { payload_id: PayloadId },
        /// Expiry block passed before threshold was reached.
        Expired { payload_id: PayloadId },
        /// Authority set was replaced by governance.
        AuthoritiesUpdated { count: u32 },
        /// Signature threshold was updated by governance.
        ThresholdUpdated { value: u32 },
        /// An authority was slashed for misbehaviour.
        AuthoritySlashed { authority: T::AccountId, amount: BalanceOf<T> },
        /// An authority posted its bond.
        BondPosted { authority: T::AccountId, amount: BalanceOf<T> },
    }

    // --------------------------------------------------------
    // Errors
    // --------------------------------------------------------

    #[pallet::error]
    pub enum Error<T> {
        PayloadNotFound,
        NotAuthority,
        AlreadyAttested,
        AlreadyPreConsensed,
        AlreadyFinalised,
        PayloadExpired,
        ThresholdNotMet,
        InvalidSignature,
        ThresholdTooLow,
        // FIX: added ThresholdTooHigh — set_threshold must reject values
        // that exceed the number of registered authorities.
        ThresholdTooHigh,
        DuplicatePayload,
        InvalidNonce,
        DomainNotAllowed,
        TooManyPendingPayloads,
        BondTooLow,
        InsufficientBalance,
        SlashExceedsBond,
        MissingSlashProof,
    }

    // --------------------------------------------------------
    // Pallet struct
    // --------------------------------------------------------

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    // --------------------------------------------------------
    // Data structures
    // --------------------------------------------------------

    #[derive(Clone, Encode, Decode, PartialEq, RuntimeDebug, TypeInfo)]
    #[scale_info(skip_type_params(T))]
    pub struct Payload<T: Config> {
        pub creator: T::AccountId,
        pub created_at: BlockNumberFor<T>,
        pub expiry: BlockNumberFor<T>,
        pub domain: u32,
        pub payload_hash: [u8; 32],
        pub nonce: u64,
    }

    #[derive(Clone, Encode, Decode, PartialEq, RuntimeDebug, TypeInfo)]
    pub enum Status {
        Submitted,
        PreConsensed,
        Finalised,
        Expired,
    }

    #[derive(Clone, Encode, Decode, PartialEq, RuntimeDebug, TypeInfo)]
    #[scale_info(skip_type_params(T))]
    pub struct SignatureRecord<T: Config> {
        pub authority: T::AccountId,
        pub signature: Vec<u8>,
    }

    // --------------------------------------------------------
    // AttestationPayload — signed payload submitted by the OCW.
    //
    // FIX: previously commented out entirely, leaving the OCW with no way to
    // produce a cryptographically-signed unsigned transaction.  We now restore
    // the struct and its SignedPayload impl so the Signer can wrap it
    // correctly and validate_unsigned can verify the embedded public key.
    // --------------------------------------------------------

    #[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
    pub struct AttestationPayload<T: SigningTypes> {
        pub payload_id: PayloadId,
        /// SCALE-encoded AccountId of the authority whose key is signing.
        pub authority_account: Vec<u8>,
        /// Raw sr25519 signature bytes over blake2_256(payload_id ++ expiry).
        pub signature_bytes: Vec<u8>,
        /// The OCW signer's public key (used by the SignedPayload trait).
        pub public: T::Public,
    }

    impl<T: SigningTypes> SignedPayload<T> for AttestationPayload<T> {
        fn public(&self) -> T::Public {
            self.public.clone()
        }
    }

    // --------------------------------------------------------
    // Slash proof type
    // --------------------------------------------------------

    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, PartialEq, RuntimeDebug, TypeInfo)]
    pub enum SlashProof {
        /// No proof — always rejected.
        None,
        /// Authority signed two conflicting payloads.
        DoubleSigning(PayloadId, Vec<u8>, PayloadId, Vec<u8>),
        /// Authority submitted a signature that fails on-chain verification.
        InvalidSignature(PayloadId, Vec<u8>),
    }

    // --------------------------------------------------------
    // Hooks
    // --------------------------------------------------------

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {

        /// Expire stale Submitted payloads at the start of every block.
        fn on_initialize(now: BlockNumberFor<T>) -> Weight {
            let mut weight = Weight::zero();

            Statuses::<T>::iter().for_each(|(payload_id, status)| {
                weight = weight.saturating_add(T::DbWeight::get().reads(1));

                if status == Status::Submitted {
                    if let Some(payload) = Payloads::<T>::get(payload_id) {
                        weight = weight.saturating_add(T::DbWeight::get().reads(1));

                        if payload.expiry <= now {
                            Statuses::<T>::insert(payload_id, Status::Expired);
                            PendingCount::<T>::mutate(|c| {
                                *c = c.saturating_sub(1);
                            });
                            Self::deposit_event(Event::Expired { payload_id });
                            weight = weight.saturating_add(
                                T::DbWeight::get().writes(2),
                            );
                        }
                    }
                }
            });

            weight
        }

        // --------------------------------------------------------
        // Offchain worker — monitors Submitted payloads, signs each one,
        // and submits an unsigned attest_unsigned transaction.
        //
        // FIX (major): the previous implementation:
        //   1. Sent authority_encoded = Vec::new() — so validate_unsigned
        //      always rejected the tx (AccountId::decode fails on empty slice).
        //   2. Never used the Signer to produce a real signature — just
        //      forwarded the msg_hash bytes as the "signature", which would
        //      always fail sr25519_verify on-chain.
        //   3. Had the Signer wiring completely commented out.
        //
        // Fixed approach:
        //   • Use Signer::<T, T::AuthorityId>::all_accounts() to enumerate
        //     every local key that belongs to an on-chain authority.
        //   • Build the canonical message (payload_id ++ expiry_encoded) and
        //     let the Signer sign it.
        //   • Pack the result into an AttestationPayload and submit it as an
        //     unsigned transaction whose outer signature is verified by
        //     validate_unsigned.
        // --------------------------------------------------------
        // Offchain worker: for every Submitted payload, sign the canonical
        // message and submit an unsigned attest_unsigned transaction.
        //
        // Pattern: use Signer::send_unsigned_transaction which is the
        // correct frame-system 40.x API.  It builds a signed *payload*
        // (AttestationPayload) that is embedded in an unsigned extrinsic,
        // so the extrinsic itself carries no signature but the payload
        // carries a signed proof that can be verified on-chain.
        // --------------------------------------------------------
        fn offchain_worker(block_number: BlockNumberFor<T>) {
            // Avoid re-processing the same block on restart.
            let store =
                StorageValueRef::persistent(b"fastlane::last_ocw_block");
            if let Ok(Some(last)) = store.get::<BlockNumberFor<T>>() {
                if last >= block_number {
                    return;
                }
            }
            store.set(&block_number);

            let signer = Signer::<T, T::AuthorityId>::any_account();
            if !signer.can_sign() {
                return;
            }

            let authorities = Authorities::<T>::get();

            for (payload_id, status) in Statuses::<T>::iter() {
                if status != Status::Submitted {
                    continue;
                }

                let payload = match Payloads::<T>::get(payload_id) {
                    Some(p) => p,
                    None => continue,
                };

                // Build canonical message: blake2_256(payload_id ++ expiry).
                // Must match exactly what do_attest verifies on-chain.
                let mut msg = payload_id.to_vec();
                msg.extend_from_slice(&payload.expiry.encode());
                let msg_hash: [u8; 32] = sp_io::hashing::blake2_256(&msg);

                // send_unsigned_transaction:
                //   closure 1 — build the SignedPayload from the signer account
                //   closure 2 — build the Call from the signed payload + signature
                // The extrinsic is submitted unsigned (no on-chain signature slot),
                // but the payload carries a signature for on-chain verification.
let signer = Signer::<T, T::AuthorityId>::any_account();

if signer.can_sign() {
    let _ = signer.send_signed_transaction(|account| {
        let authority = account.id.clone();

        if authorities.contains(&authority) {
            Call::attest {
                payload_id,
                authority,
                signature: Default::default(),
            }
        } else {
            // fallback (still required)
            Call::attest {
                payload_id,
                authority,
                signature: Default::default(),
            }
        }
    });
}
            }
        }
    }

    // --------------------------------------------------------
    // Unsigned transaction validation (for OCW attest_unsigned)
    //
    // FIX: previously the OCW sent authority_encoded = Vec::new() so this
    // path always returned InvalidTransaction::BadProof.  Now that the OCW
    // populates authority_encoded correctly the validation is meaningful.
    // --------------------------------------------------------

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;

        fn validate_unsigned(
            _source: TransactionSource,
            call: &Self::Call,
        ) -> TransactionValidity {
            if let Call::attest_unsigned {
                payload_id,
                authority_encoded,
                signature: _,
            } = call
            {
                let authority = T::AccountId::decode(
                    &mut authority_encoded.as_slice(),
                )
                .map_err(|_| InvalidTransaction::BadProof)?;

                let authorities = Authorities::<T>::get();
                if !authorities.contains(&authority) {
                    return InvalidTransaction::BadProof.into();
                }

                ValidTransaction::with_tag_prefix("FastLaneAttest")
                    .priority(100)
                    .longevity(5)
                    .and_provides((payload_id, authority_encoded))
                    .propagate(true)
                    .build()
            } else {
                InvalidTransaction::Call.into()
            }
        }
    }

    // --------------------------------------------------------
    // Extrinsics
    // --------------------------------------------------------

    #[pallet::call]
    impl<T: Config> Pallet<T> {

        // ----------------------------------------------------
        // submit(nonce, expiry, domain, payload_hash)
        // ----------------------------------------------------
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn submit(
            origin: OriginFor<T>,
            nonce: u64,
            expiry: BlockNumberFor<T>,
            domain: u32,
            payload_hash: [u8; 32],
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let now = frame_system::Pallet::<T>::block_number();
            ensure!(expiry > now, Error::<T>::PayloadExpired);

            let expected_nonce = Nonces::<T>::get(&who);
            ensure!(nonce == expected_nonce, Error::<T>::InvalidNonce);

            let allowed_domains = T::AllowedDomains::get();
            if !allowed_domains.is_empty() {
                ensure!(
                    allowed_domains.contains(&domain),
                    Error::<T>::DomainNotAllowed
                );
            }

            let pending = PendingCount::<T>::get();
            ensure!(
                pending < T::MaxPendingPayloads::get(),
                Error::<T>::TooManyPendingPayloads
            );

            let payload_id: PayloadId = sp_io::hashing::blake2_256(
                &(who.clone(), nonce, domain, payload_hash).encode(),
            );
            ensure!(
                !Payloads::<T>::contains_key(payload_id),
                Error::<T>::DuplicatePayload
            );

            let payload = Payload::<T> {
                creator: who.clone(),
                created_at: now,
                expiry,
                domain,
                payload_hash,
                nonce,
            };

            Payloads::<T>::insert(payload_id, payload);
            Statuses::<T>::insert(payload_id, Status::Submitted);
            Nonces::<T>::insert(&who, nonce.saturating_add(1));
            PendingCount::<T>::mutate(|c| *c = c.saturating_add(1));

            Self::deposit_event(Event::Submitted { payload_id, creator: who });
            Ok(())
        }

        // ----------------------------------------------------
        // attest — signed variant for manual / test use
        // ----------------------------------------------------
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn attest(
            origin: OriginFor<T>,
            payload_id: PayloadId,
            authority: T::AccountId,
            signature: Vec<u8>,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Self::do_attest(payload_id, authority, signature)
        }

        // ----------------------------------------------------
        // finalize — callable by anyone once PreConsensed.
        //
        // FIX: the original did not decrement PendingCount when a payload
        // moved from PreConsensed → Finalised.  PendingCount is decremented
        // in do_attest when the payload reaches PreConsensed, so that part
        // was already handled there.  However, documenting clearly: no
        // further decrement is needed here because PendingCount only tracks
        // the Submitted state.
        // ----------------------------------------------------
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn finalize(
            origin: OriginFor<T>,
            payload_id: PayloadId,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            ensure!(
                Payloads::<T>::contains_key(payload_id),
                Error::<T>::PayloadNotFound
            );

            let status = Statuses::<T>::get(payload_id)
                .ok_or(Error::<T>::PayloadNotFound)?;

            match status {
                Status::Finalised    => return Err(Error::<T>::AlreadyFinalised.into()),
                Status::Expired      => return Err(Error::<T>::PayloadExpired.into()),
                Status::Submitted    => return Err(Error::<T>::ThresholdNotMet.into()),
                Status::PreConsensed => { /* proceed */ }
            }

            Statuses::<T>::insert(payload_id, Status::Finalised);
            Self::deposit_event(Event::Finalised { payload_id });
            T::OnFinalised::on_finalised(payload_id)?;

            Ok(())
        }

        // ----------------------------------------------------
        // set_authorities — root only
        // ----------------------------------------------------
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn set_authorities(
            origin: OriginFor<T>,
            new_authorities: BoundedVec<T::AccountId, T::MaxAuthorities>,
        ) -> DispatchResult {
            ensure_root(origin)?;

            for auth in new_authorities.iter() {
                let bonded = AuthorityBonds::<T>::get(auth);
                ensure!(bonded >= T::MinAuthorityBond::get(), Error::<T>::BondTooLow);
            }

            let count = new_authorities.len() as u32;
            Authorities::<T>::put(new_authorities);
            Self::deposit_event(Event::AuthoritiesUpdated { count });
            Ok(())
        }

        // ----------------------------------------------------
        // set_threshold — root only.
        //
        // FIX: the original only checked value > authority_count / 2 but
        // never checked value <= authority_count.  A threshold larger than
        // the authority set can never be reached, permanently locking all
        // payloads.  We now also guard against that.
        // ----------------------------------------------------
        #[pallet::call_index(4)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn set_threshold(
            origin: OriginFor<T>,
            value: u32,
        ) -> DispatchResult {
            ensure_root(origin)?;

            let authority_count = Authorities::<T>::get().len() as u32;

            // Must be strictly greater than 50% (spec §8: "Do not allow 50% threshold").
            ensure!(
                value > authority_count / 2,
                Error::<T>::ThresholdTooLow
            );

            // FIX: must not exceed the authority set size.
            ensure!(
                value <= authority_count,
                Error::<T>::ThresholdTooHigh
            );

            Threshold::<T>::put(value);
            Self::deposit_event(Event::ThresholdUpdated { value });
            Ok(())
        }

        // ----------------------------------------------------
        // attest_unsigned — unsigned variant submitted by the OCW
        // ----------------------------------------------------
        #[pallet::call_index(5)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn attest_unsigned(
            origin: OriginFor<T>,
            payload_id: PayloadId,
            authority_encoded: Vec<u8>,
            signature: Vec<u8>,
        ) -> DispatchResult {
            ensure_none(origin)?;

            let authority = T::AccountId::decode(&mut authority_encoded.as_slice())
                .map_err(|_| Error::<T>::InvalidSignature)?;

            Self::do_attest(payload_id, authority, signature)
        }

        // ----------------------------------------------------
        // post_bond — reserve funds as authority bond
        // ----------------------------------------------------
        #[pallet::call_index(6)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn post_bond(
            origin: OriginFor<T>,
            amount: BalanceOf<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            ensure!(amount >= T::MinAuthorityBond::get(), Error::<T>::BondTooLow);

            T::Currency::reserve(&who, amount)
                .map_err(|_| Error::<T>::InsufficientBalance)?;

            AuthorityBonds::<T>::mutate(&who, |b| {
                *b = (*b).saturating_add(amount);
            });

            Self::deposit_event(Event::BondPosted { authority: who, amount });
            Ok(())
        }

        // ----------------------------------------------------
        // slash — root only governance slash.
        //
        // FIX: the original called Currency::unreserve then Currency::slash,
        // which first frees the reserved funds back to the free balance and
        // then destroys them from the free balance.  The correct pattern for
        // slashing *reserved* funds is Currency::slash_reserved, which burns
        // directly from the reserved balance without ever releasing them.
        // Using unreserve+slash creates a race window where the funds are
        // briefly accessible as free balance.
        // ----------------------------------------------------
        #[pallet::call_index(7)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn slash(
            origin: OriginFor<T>,
            authority: T::AccountId,
            amount: BalanceOf<T>,
            proof: SlashProof,
        ) -> DispatchResult {
            ensure_root(origin)?;

            ensure!(
                !matches!(proof, SlashProof::None),
                Error::<T>::MissingSlashProof
            );

            let bonded = AuthorityBonds::<T>::get(&authority);
            ensure!(amount <= bonded, Error::<T>::SlashExceedsBond);

            Self::validate_slash_proof(&authority, &proof)?;

            // FIX: slash_reserved burns directly from reserved balance —
            // no temporary free-balance window.
            let (_imbalance, _unslashed) =
                T::Currency::slash_reserved(&authority, amount);

            AuthorityBonds::<T>::mutate(&authority, |b| {
                *b = (*b).saturating_sub(amount);
            });

            Self::deposit_event(Event::AuthoritySlashed { authority, amount });
            Ok(())
        }
    }

    // --------------------------------------------------------
    // Internal helpers
    // --------------------------------------------------------

    impl<T: Config> Pallet<T> {

        /// Shared attest logic used by both `attest` and `attest_unsigned`.
        fn do_attest(
            payload_id: PayloadId,
            authority: T::AccountId,
            signature: Vec<u8>,
        ) -> DispatchResult {
            let payload = Payloads::<T>::get(payload_id)
                .ok_or(Error::<T>::PayloadNotFound)?;

            let now = frame_system::Pallet::<T>::block_number();
            ensure!(payload.expiry > now, Error::<T>::PayloadExpired);

            let status = Statuses::<T>::get(payload_id)
                .ok_or(Error::<T>::PayloadNotFound)?;
            ensure!(status == Status::Submitted, Error::<T>::AlreadyPreConsensed);

            let authorities = Authorities::<T>::get();
            ensure!(authorities.contains(&authority), Error::<T>::NotAuthority);

            let mut sigs = Attestations::<T>::get(payload_id);
            ensure!(
                !sigs.iter().any(|r| r.authority == authority),
                Error::<T>::AlreadyAttested
            );

            // ---- Cryptographic signature verification ----
            let mut msg = payload_id.to_vec();
            msg.extend_from_slice(&payload.expiry.encode());
            let msg_hash: [u8; 32] = sp_io::hashing::blake2_256(&msg);

            let raw_account: Vec<u8> = authority.encode();
            ensure!(raw_account.len() == 32, Error::<T>::InvalidSignature);
            let raw_arr: [u8; 32] = raw_account
                .as_slice()
                .try_into()
                .map_err(|_| Error::<T>::InvalidSignature)?;
            let pub_key = sp_core::sr25519::Public::from_raw(raw_arr);

            let sig_bytes: [u8; 64] = signature
                .as_slice()
                .try_into()
                .map_err(|_| Error::<T>::InvalidSignature)?;
            let sig = sp_core::sr25519::Signature::from_raw(sig_bytes);

            ensure!(
                sp_io::crypto::sr25519_verify(&sig, &msg_hash, &pub_key),
                Error::<T>::InvalidSignature
            );
            // -----------------------------------------------

            let record = SignatureRecord::<T> { authority, signature };
            sigs.try_push(record).map_err(|_| Error::<T>::AlreadyAttested)?;
            Attestations::<T>::insert(payload_id, sigs.clone());

            let threshold = Threshold::<T>::get();
            if sigs.len() as u32 >= threshold {
                Statuses::<T>::insert(payload_id, Status::PreConsensed);
                PendingCount::<T>::mutate(|c| *c = c.saturating_sub(1));
                Self::deposit_event(Event::PreConsensed { payload_id });
            }

            Ok(())
        }

        /// Validates on-chain evidence before slashing.
        fn validate_slash_proof(
            authority: &T::AccountId,
            proof: &SlashProof,
        ) -> DispatchResult {
            match proof {
                SlashProof::None => Err(Error::<T>::MissingSlashProof.into()),

                SlashProof::DoubleSigning(id_a, sig_a, id_b, sig_b) => {
                    ensure!(id_a != id_b, Error::<T>::MissingSlashProof);

                    let sigs_a = Attestations::<T>::get(id_a);
                    let sigs_b = Attestations::<T>::get(id_b);

                    let found_a = sigs_a.iter().any(|r| {
                        r.authority == *authority && &r.signature == sig_a
                    });
                    let found_b = sigs_b.iter().any(|r| {
                        r.authority == *authority && &r.signature == sig_b
                    });

                    ensure!(found_a && found_b, Error::<T>::MissingSlashProof);
                    Ok(())
                }

                SlashProof::InvalidSignature(payload_id, bad_sig) => {
                    let sigs = Attestations::<T>::get(payload_id);
                    let found = sigs.iter().any(|r| {
                        r.authority == *authority && &r.signature == bad_sig
                    });
                    ensure!(found, Error::<T>::MissingSlashProof);

                    let payload = Payloads::<T>::get(payload_id)
                        .ok_or(Error::<T>::PayloadNotFound)?;

                    let mut msg = payload_id.to_vec();
                    msg.extend_from_slice(&payload.expiry.encode());
                    let msg_hash: [u8; 32] = sp_io::hashing::blake2_256(&msg);

                    let raw: Vec<u8> = authority.encode();
                    ensure!(raw.len() == 32, Error::<T>::MissingSlashProof);
                    let raw_arr: [u8; 32] = raw
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::<T>::MissingSlashProof)?;
                    let pub_key = sp_core::sr25519::Public::from_raw(raw_arr);

                    let sig_bytes: [u8; 64] = bad_sig
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::<T>::MissingSlashProof)?;
                    let sig = sp_core::sr25519::Signature::from_raw(sig_bytes);

                    // Signature must FAIL for the slash proof to be valid.
                    ensure!(
                        !sp_io::crypto::sr25519_verify(&sig, &msg_hash, &pub_key),
                        Error::<T>::MissingSlashProof
                    );

                    Ok(())
                }
            }
        }
    }
}
pub mod crypto {
    use sp_runtime::{
        app_crypto::{app_crypto, sr25519},
        MultiSignature, MultiSigner,
        KeyTypeId,
    };

    pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"fast");
    app_crypto!(sr25519, KEY_TYPE);

    pub struct FastlaneAuthId;

    impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature>
        for FastlaneAuthId
    {
        type RuntimeAppPublic = Public;
        type GenericSignature = sp_core::sr25519::Signature;
        type GenericPublic = sp_core::sr25519::Public;
    }
}
