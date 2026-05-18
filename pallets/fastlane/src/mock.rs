// ============================================================
// pallets/fastlane/src/mock.rs
// Test runtime for the FastLane pallet.
// ============================================================

#![cfg(test)]

use crate as pallet_fastlane;

use frame_support::{
    derive_impl, parameter_types,
    traits::{ConstU128, ConstU32},
};
use frame_system::offchain::{
    AppCrypto, CreateInherent, CreateSignedTransaction, CreateTransactionBase,
    SigningTypes,
};
use sp_core::{sr25519, Pair};
use sp_runtime::{
    testing::TestXt,
    traits::{IdentifyAccount, IdentityLookup, Verify},
    BuildStorage, MultiSignature,
};

pub type Signature = MultiSignature;
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;
pub type Balance = u128;
pub type BlockNumber = u64;
pub type Extrinsic = TestXt<RuntimeCall, ()>;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        Balances: pallet_balances,
        Fastlane: pallet_fastlane,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = frame_system::mocking::MockBlock<Test>;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type AccountData = pallet_balances::AccountData<Balance>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
    type AccountStore = System;
    type Balance = Balance;
    type ExistentialDeposit = ConstU128<1>;
}

parameter_types! {
    pub AllowedDomains: Vec<u32> = Vec::new();
}

impl SigningTypes for Test {
    type Public = <Signature as Verify>::Signer;
    type Signature = Signature;
}

impl CreateTransactionBase<pallet_fastlane::Call<Test>> for Test {
    type Extrinsic = Extrinsic;
    type RuntimeCall = RuntimeCall;
}

impl CreateInherent<pallet_fastlane::Call<Test>> for Test {
    fn create_inherent(call: RuntimeCall) -> Extrinsic {
        Extrinsic::new_bare(call)
    }
}

impl CreateSignedTransaction<pallet_fastlane::Call<Test>> for Test {
    fn create_signed_transaction<C: AppCrypto<Self::Public, Self::Signature>>(
        call: RuntimeCall,
        _public: Self::Public,
        _account: AccountId,
        _nonce: u32,
    ) -> Option<Extrinsic> {
        Some(Extrinsic::new_bare(call))
    }
}

impl pallet_fastlane::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type MinAuthorityBond = ConstU128<1_000>;
    type MaxPendingPayloads = ConstU32<100>;
    type MaxAuthorities = ConstU32<16>;
    type AuthorityId = pallet_fastlane::crypto::FastlaneAuthId;
    type AllowedDomains = AllowedDomains;
    type OffchainChecks = ();
    type MaxAutoFinalizePerBlock = ConstU32<5>;
    type MaxExpiriesPerBlock = ConstU32<5>;
    type WeightInfo = ();
    type OnFinalised = ();
}

// --------------------------------------------------------
// Test helpers — sr25519 key derivation
// --------------------------------------------------------

/// Derive a deterministic sr25519 keypair for `seed` ("//Alice", "//Bob", ...).
pub fn keypair(seed: &str) -> sr25519::Pair {
    sr25519::Pair::from_string(seed, None).expect("valid keypair seed")
}

/// AccountId for a derivation seed (sr25519 public key as 32 bytes).
pub fn account(seed: &str) -> AccountId {
    let pair = keypair(seed);
    sp_runtime::AccountId32::from(pair.public().0)
}

/// Sign the canonical FastLane attestation message:
///   blake2_256(payload_id ++ expiry.encode() ++ checks_hash)
pub fn sign_attestation(
    pair: &sr25519::Pair,
    payload_id: [u8; 32],
    expiry: BlockNumber,
    checks_hash: [u8; 32],
) -> Vec<u8> {
    use codec::Encode;
    let mut msg = payload_id.to_vec();
    msg.extend_from_slice(&expiry.encode());
    msg.extend_from_slice(&checks_hash);
    let msg_hash = sp_io::hashing::blake2_256(&msg);
    pair.sign(&msg_hash).0.to_vec()
}

/// Re-derive the checks_hash that `()::OffchainChecks::compute_checks_hash`
/// produces for an accepted payload. All flags are true on the happy path.
pub fn checks_hash_for(
    creator: AccountId,
    nonce: u64,
    domain: u32,
    payload_hash: [u8; 32],
    expiry: BlockNumber,
) -> [u8; 32] {
    use codec::Encode;
    sp_io::hashing::blake2_256(
        &(
            creator,
            nonce,
            domain,
            payload_hash,
            expiry,
            true, true, true, true, true, true,
        )
            .encode(),
    )
}

/// Compute the deterministic payload_id used by `submit()`.
pub fn payload_id_for(
    creator: AccountId,
    nonce: u64,
    domain: u32,
    payload_hash: [u8; 32],
) -> [u8; 32] {
    use codec::Encode;
    sp_io::hashing::blake2_256(&(creator, nonce, domain, payload_hash).encode())
}

// --------------------------------------------------------
// ext builder
// --------------------------------------------------------

#[derive(Default)]
pub struct ExtBuilder {
    balances: Vec<(AccountId, Balance)>,
    fastlane_authorities: Vec<AccountId>,
    fastlane_threshold: u32,
}

impl ExtBuilder {
    pub fn with_balances(mut self, b: Vec<(AccountId, Balance)>) -> Self {
        self.balances = b;
        self
    }

    pub fn with_authorities(mut self, a: Vec<AccountId>) -> Self {
        self.fastlane_authorities = a;
        self
    }

    pub fn with_threshold(mut self, t: u32) -> Self {
        self.fastlane_threshold = t;
        self
    }

    pub fn build(self) -> sp_io::TestExternalities {
        let mut t = frame_system::GenesisConfig::<Test>::default()
            .build_storage()
            .unwrap();

        pallet_balances::GenesisConfig::<Test> {
            balances: self.balances,
            ..Default::default()
        }
        .assimilate_storage(&mut t)
        .unwrap();

        pallet_fastlane::GenesisConfig::<Test> {
            authorities: self.fastlane_authorities,
            threshold: self.fastlane_threshold,
            ..Default::default()
        }
        .assimilate_storage(&mut t)
        .unwrap();

        let mut ext = sp_io::TestExternalities::new(t);
        ext.execute_with(|| System::set_block_number(1));
        ext
    }
}
