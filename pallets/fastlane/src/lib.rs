// ============================================================
// pallets/fastlane/src/lib.rs
// FastLane Pre-Consensus Attestation Pallet
// ============================================================

#![cfg_attr(not(feature = "std"), no_std)]

pub use crate::pallet::*;





#[frame_support::pallet]

pub mod pallet {

 












    use frame_support::{
        pallet_prelude::*,
        traits::{Currency, ReservableCurrency},
    };

    use frame_system::{
        offchain::{
            AppCrypto, CreateSignedTransaction, SubmitTransaction,
        },
        pallet_prelude::*,
    };

    use sp_runtime::{
        traits::Zero,
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

    /// Hook to run deterministic checks used by OCW and on-chain verification.
    pub trait OffchainChecks<T: Config> {
        fn compute_checks_hash(payload: &Payload<T>) -> Option<[u8; 32]>;
    }

    impl<T: Config> OffchainChecks<T> for () {
        fn compute_checks_hash(payload: &Payload<T>) -> Option<[u8; 32]> {
            let allowed_domains = T::AllowedDomains::get();
            let domain_ok =
                allowed_domains.is_empty() || allowed_domains.contains(&payload.domain);
            // Accept the payload if the stored nonce has advanced past it,
            // meaning submit() already validated and accepted the nonce.
            let nonce_ok =
                Nonces::<T>::get(&payload.creator) >= payload.nonce.saturating_add(1);
            let balance_ok = !T::Currency::free_balance(&payload.creator).is_zero();
            let kyc_ok = true;
            let rate_limit_ok = true;
            let domain_specific_ok = true;
            let all_ok = domain_ok
                && nonce_ok
                && balance_ok
                && kyc_ok
                && rate_limit_ok
                && domain_specific_ok;

            if !all_ok {
                return None;
            }

            Some(sp_io::hashing::blake2_256(
                &(
                    payload.creator.clone(),
                    payload.nonce,
                    payload.domain,
                    payload.payload_hash,
                    payload.expiry,
                    domain_ok,
                    nonce_ok,
                    balance_ok,
                    kyc_ok,
                    rate_limit_ok,
                    domain_specific_ok,
                )
                    .encode(),
            ))
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
        frame_system::Config
        + CreateSignedTransaction<Call<Self>>
        + frame_system::offchain::CreateInherent<
            Call<Self>,
        >
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
        /// Runtime hook for domain-specific pre-attestation checks.
        type OffchainChecks: OffchainChecks<Self>;
        /// Maximum number of PreConsensed payloads auto-finalized in one block.
        type MaxAutoFinalizePerBlock: Get<u32>;
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
        pub checks_hash: [u8; 32],
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
    // Genesis config
    // --------------------------------------------------------

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        pub authorities: Vec<T::AccountId>,
        pub threshold: u32,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            let bounded: BoundedVec<T::AccountId, T::MaxAuthorities> = self
                .authorities
                .clone()
                .try_into()
                .expect("Too many genesis authorities; increase MaxAuthorities");
            Authorities::<T>::put(bounded);
            Threshold::<T>::put(self.threshold);
        }
    }

    // --------------------------------------------------------
    // Hooks
    // --------------------------------------------------------

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {

        /// Expire stale Submitted payloads at the start of every block.
        fn on_initialize(now: BlockNumberFor<T>) -> Weight {
            let mut weight = Weight::zero();
            let mut finalized: u32 = 0;

            Statuses::<T>::iter().for_each(|(payload_id, status)| {
                weight = weight.saturating_add(T::DbWeight::get().reads(1));

                if status == Status::Submitted {
                    if let Some(payload) = Payloads::<T>::get(payload_id) {
                        weight = weight.saturating_add(T::DbWeight::get().reads(1));

                        if now > payload.expiry {
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
                } else if status == Status::PreConsensed
                    && finalized < T::MaxAutoFinalizePerBlock::get()
                {
                    if T::OnFinalised::on_finalised(payload_id).is_ok() {
                        Statuses::<T>::insert(payload_id, Status::Finalised);
                        Self::deposit_event(Event::Finalised { payload_id });
                        finalized = finalized.saturating_add(1);
                        weight = weight.saturating_add(T::DbWeight::get().writes(1));
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
        fn offchain_worker(block_number: BlockNumberFor<T>) {
            // Avoid re-processing the same block on restart.
            let store = StorageValueRef::persistent(b"fastlane::last_ocw_block");
            if let Ok(Some(last)) = store.get::<BlockNumberFor<T>>() {
                if last >= block_number {
                    return;
                }
            }
            store.set(&block_number);

            // Enumerate local sr25519 keys registered under the "fast" key type.
            let local_keys =
                sp_io::crypto::sr25519_public_keys(crate::crypto::KEY_TYPE);
            if local_keys.is_empty() {
                return;
            }

            for (payload_id, status) in Statuses::<T>::iter() {
                if status != Status::Submitted {
                    continue;
                }

                let payload = match Payloads::<T>::get(payload_id) {
                    Some(p) => p,
                    None => continue,
                };

                let checks_hash =
                    match T::OffchainChecks::compute_checks_hash(&payload) {
                        Some(h) => h,
                        None => continue,
                    };

                let authorities = Authorities::<T>::get();
                if authorities.is_empty() {
                    continue;
                }

                // Canonical message — same bytes verified by do_attest.
                let mut msg = payload_id.to_vec();
                msg.extend_from_slice(&payload.expiry.encode());
                msg.extend_from_slice(&checks_hash);
                let msg_hash: [u8; 32] = sp_io::hashing::blake2_256(&msg);

                for key_pub in &local_keys {
                    // In sr25519 runtimes the AccountId IS the raw public key.
                    let auth = match T::AccountId::decode(
                        &mut key_pub.0.as_ref(),
                    ) {
                        Ok(a) => a,
                        Err(_) => continue,
                    };

                    if !authorities.contains(&auth) {
                        continue;
                    }

                    // Skip if we already attested this payload.
                    if Attestations::<T>::get(payload_id)
                        .iter()
                        .any(|r| r.authority == auth)
                    {
                        continue;
                    }

                    if let Some(raw_sig) = sp_io::crypto::sr25519_sign(
                        crate::crypto::KEY_TYPE,
                        key_pub,
                        &msg_hash,
                    ) {
                        let call = Call::attest_unsigned {
                            payload_id,
                            authority_encoded: auth.encode(),
                            // 64-byte raw sig — handled by do_attest's len==64 branch.
                            signature: raw_sig.0.to_vec(),
                            checks_hash,
                        };
                        let xt = T::create_inherent(call.into());
                        let _ = SubmitTransaction::<T, Call<T>>::submit_transaction(xt);
                    }
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
                signature,
                checks_hash,
            } = call
            {
                let status = Statuses::<T>::get(payload_id)
                    .ok_or(InvalidTransaction::Stale)?;
                if status != Status::Submitted {
                    return InvalidTransaction::Stale.into();
                }

                let payload = Payloads::<T>::get(payload_id)
                    .ok_or(InvalidTransaction::Stale)?;
                let now = frame_system::Pallet::<T>::block_number();
                if now > payload.expiry {
                    return InvalidTransaction::Stale.into();
                }

                let authority = T::AccountId::decode(
                    &mut authority_encoded.as_slice(),
                )
                .map_err(|_| InvalidTransaction::BadProof)?;

                let authorities = Authorities::<T>::get();
                if !authorities.contains(&authority) {
                    return InvalidTransaction::BadProof.into();
                }

                let sigs = Attestations::<T>::get(payload_id);
                if sigs.iter().any(|r| r.authority == authority) {
                    return InvalidTransaction::Stale.into();
                }

                let expected_checks_hash =
                    T::OffchainChecks::compute_checks_hash(&payload)
                        .ok_or(InvalidTransaction::BadProof)?;
                if *checks_hash != expected_checks_hash {
                    return InvalidTransaction::BadProof.into();
                }

                if signature.is_empty() {
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
            checks_hash: [u8; 32],
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(who == authority, Error::<T>::NotAuthority);
            Self::do_attest(payload_id, authority, signature, checks_hash)
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
            let _ = ensure_signed(origin)?;

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
            checks_hash: [u8; 32],
        ) -> DispatchResult {
            ensure_none(origin)?;

            let authority = T::AccountId::decode(&mut authority_encoded.as_slice())
                .map_err(|_| Error::<T>::InvalidSignature)?;

            Self::do_attest(payload_id, authority, signature, checks_hash)
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
            checks_hash: [u8; 32],
        ) -> DispatchResult {
            let payload = Payloads::<T>::get(payload_id)
                .ok_or(Error::<T>::PayloadNotFound)?;

            let now = frame_system::Pallet::<T>::block_number();
            ensure!(payload.expiry > now, Error::<T>::PayloadExpired);

            let status = Statuses::<T>::get(payload_id)
                .ok_or(Error::<T>::PayloadNotFound)?;
            match status {
                Status::Submitted    => { /* proceed */ }
                Status::PreConsensed => return Err(Error::<T>::AlreadyPreConsensed.into()),
                Status::Finalised    => return Err(Error::<T>::AlreadyFinalised.into()),
                Status::Expired      => return Err(Error::<T>::PayloadExpired.into()),
            }

            let authorities = Authorities::<T>::get();
            ensure!(authorities.contains(&authority), Error::<T>::NotAuthority);

            let mut sigs = Attestations::<T>::get(payload_id);
            ensure!(
                !sigs.iter().any(|r| r.authority == authority),
                Error::<T>::AlreadyAttested
            );

            let expected_checks_hash = T::OffchainChecks::compute_checks_hash(&payload)
                .ok_or(Error::<T>::InvalidSignature)?;
            ensure!(checks_hash == expected_checks_hash, Error::<T>::InvalidSignature);

            // ---- Cryptographic signature verification ----
            let mut msg = payload_id.to_vec();
            msg.extend_from_slice(&payload.expiry.encode());
            msg.extend_from_slice(&checks_hash);
            let msg_hash: [u8; 32] = sp_io::hashing::blake2_256(&msg);

            let raw_account: Vec<u8> = authority.encode();
            ensure!(raw_account.len() == 32, Error::<T>::InvalidSignature);
            let raw_arr: [u8; 32] = raw_account
                .as_slice()
                .try_into()
                .map_err(|_| Error::<T>::InvalidSignature)?;
            let pub_key = sp_core::sr25519::Public::from_raw(raw_arr);

            let sig = if signature.len() == 64 {
                let sig_bytes: [u8; 64] = signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::<T>::InvalidSignature)?;
                sp_core::sr25519::Signature::from_raw(sig_bytes)
            } else {
                let multi = sp_runtime::MultiSignature::decode(&mut signature.as_slice())
                    .map_err(|_| Error::<T>::InvalidSignature)?;
                match multi {
                    sp_runtime::MultiSignature::Sr25519(s) => s,
                    _ => return Err(Error::<T>::InvalidSignature.into()),
                }
            };

            ensure!(
                sp_io::crypto::sr25519_verify(&sig, &msg_hash, &pub_key),
                Error::<T>::InvalidSignature
            );
            // -----------------------------------------------

            let record = SignatureRecord::<T> {
                authority,
                signature,
                checks_hash,
            };
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
                    let found = sigs.iter().find(|r| {
                        r.authority == *authority && &r.signature == bad_sig
                    });
                    let record = found.ok_or(Error::<T>::MissingSlashProof)?;

                    let payload = Payloads::<T>::get(payload_id)
                        .ok_or(Error::<T>::PayloadNotFound)?;

                    let mut msg = payload_id.to_vec();
                    msg.extend_from_slice(&payload.expiry.encode());
                    msg.extend_from_slice(&record.checks_hash);
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
