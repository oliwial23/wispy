use ark_bn254::Fr as F;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_ff::fields::AdditiveGroup;
use ark_r1cs_std::prelude::AllocVar;
use ark_r1cs_std::prelude::AllocationMode;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::{
    boolean::Boolean,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
};
use ark_relations::r1cs::Namespace;
use ark_relations::r1cs::Result as ArkResult;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use rand::{CryptoRng, RngCore};
use std::borrow::Borrow;
use zk_callbacks::crypto::hash::HasherZK;
use zk_callbacks::{
    generic::{
        bulletin::{PublicCallbackBul, PublicUserBul},
        interaction::{Callback, Interaction},
        object::{Id, Time},
        scan::{self, PrivScanArgs, PrivScanArgsVar, PubScanArgs, PubScanArgsVar},
        user::{ExecutedMethod, User, UserVar},
    },
    impls::{
        centralized::{crypto::FakeSigPubkey, ds::sigstore::GRSchnorrCallbackStore},
        hash::Poseidon,
    },
    scannable_zk_object,
};

use crate::Args;
use crate::ArgsVar;
use crate::Cr;
use crate::H;
use crate::PK;
use crate::Snark;

pub const NUM_INTS_BEFORE_SCAN: usize = 5;
pub const BAN_FLAG: u64 = 999999999;
pub const MAX_PSEUDO: usize = 4;

#[scannable_zk_object(F)]
#[derive(Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct MsgUser {
    pub sk: F,
    pub reputation: F,
    pub num_interactions_since_last_scan: F,
    pub pseudo_counter: F,
    pub banned: F,
    pub badge1: F,
    pub badge2: F,
    pub badge3: F,
}

#[derive(Clone, Debug, Default, CanonicalDeserialize, CanonicalSerialize)]
pub struct PseudonymArgs<F: PrimeField> {
    pub context: F,
    pub claimed: F,
}

#[derive(Clone)]
pub struct PseudonymArgsVar<F: PrimeField> {
    pub context: FpVar<F>,
    pub claimed: FpVar<F>,
}

impl<F: PrimeField> AllocVar<PseudonymArgs<F>, F> for PseudonymArgsVar<F> {
    fn new_variable<T: Borrow<PseudonymArgs<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs(); // ConstraintSystemRef<F>

        let PseudonymArgs { context, claimed } = *f()?.borrow();
        Ok(Self {
            context: FpVar::new_variable(cs.clone(), || Ok(context), mode)?,
            claimed: FpVar::new_variable(cs, || Ok(claimed), mode)?,
        })
    }
}

// use ark_relations::r1cs::ToConstraintField;
use ark_ff::ToConstraintField;

impl<F: PrimeField> ToConstraintField<F> for PseudonymArgs<F> {
    fn to_field_elements(&self) -> Option<Vec<F>> {
        Some(vec![self.context, self.claimed])
    }
}

pub fn pseudonym_pred<'a, 'b>(
    tu: &'a UserVar<F, MsgUser>,
    _com: &'b FpVar<F>,
    pub_args: PseudonymArgsVar<F>,
    _priv_args: (),
) -> ArkResult<Boolean<F>> {
    let context = pub_args.context;
    let claimed = pub_args.claimed;
    let derived = Poseidon::<2>::hash_in_zk(&[tu.data.sk.clone(), context.clone()])?;
    derived.is_eq(&claimed)
}

#[derive(Clone, Debug, Default, CanonicalDeserialize, CanonicalSerialize)]
pub struct PseudonymArgsRate<F: PrimeField> {
    pub context: F,
    pub claimed: F,
    pub i: F,
}

#[derive(Clone)]
pub struct PseudonymArgsRateVar<F: PrimeField> {
    pub context: FpVar<F>,
    pub claimed: FpVar<F>,
    pub i: FpVar<F>,
}

impl<F: PrimeField> AllocVar<PseudonymArgsRate<F>, F> for PseudonymArgsRateVar<F> {
    fn new_variable<T: Borrow<PseudonymArgsRate<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs(); // ConstraintSystemRef<F>

        let PseudonymArgsRate {
            context,
            claimed,
            i,
        } = *f()?.borrow();
        Ok(Self {
            context: FpVar::new_variable(cs.clone(), || Ok(context), mode)?,
            claimed: FpVar::new_variable(cs.clone(), || Ok(claimed), mode)?,
            i: FpVar::new_variable(cs, || Ok(i), mode)?,
        })
    }
}

impl<F: PrimeField> ToConstraintField<F> for PseudonymArgsRate<F> {
    fn to_field_elements(&self) -> Option<Vec<F>> {
        Some(vec![self.context, self.claimed, self.i])
    }
}

#[derive(Clone, Debug, Default, CanonicalDeserialize, CanonicalSerialize)]
pub struct BadgesArgs<F: PrimeField> {
    pub i: F,
    pub claimed: F,
}

#[derive(Clone)]
pub struct BadgesArgsVar<F: PrimeField> {
    pub i: FpVar<F>,
    pub claimed: FpVar<F>,
}

impl<F: PrimeField> AllocVar<BadgesArgs<F>, F> for BadgesArgsVar<F> {
    fn new_variable<T: Borrow<BadgesArgs<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::alloc::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let BadgesArgs { i, claimed } = *f()?.borrow();
        Ok(Self {
            i: FpVar::new_variable(cs.clone(), || Ok(i), mode)?,
            claimed: FpVar::new_variable(cs, || Ok(claimed), mode)?,
        })
    }
}

pub fn badge_pred<'a, 'b>(
    tu: &'a UserVar<F, MsgUser>,
    _com: &'b FpVar<F>,
    pub_args: BadgesArgsVar<F>,
    _priv_args: (),
) -> ArkResult<Boolean<F>> {
    let claimed = pub_args.claimed;

    let is_one = pub_args.i.is_eq(&FpVar::Constant(F::from(1)))?;
    let is_two = pub_args.i.is_eq(&FpVar::Constant(F::from(2)))?;

    let badge12 = FpVar::conditionally_select(&is_one, &tu.data.badge1, &tu.data.badge2)?;
    let badge = FpVar::conditionally_select(&is_two, &badge12, &tu.data.badge3)?;

    let x1 = badge.is_eq(&claimed)?;

    Ok(x1)
}

#[derive(Clone, Default)]
pub struct PseudonymArgsPair<F: PrimeField> {
    pub a: PseudonymArgs<F>,
    pub b: PseudonymArgs<F>,
}

#[derive(Clone)]
pub struct PseudonymArgsPairVar<F: PrimeField> {
    pub a: PseudonymArgsVar<F>,
    pub b: PseudonymArgsVar<F>,
}

impl<F: PrimeField> AllocVar<PseudonymArgsPair<F>, F> for PseudonymArgsPairVar<F> {
    fn new_variable<T: Borrow<PseudonymArgsPair<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let pair = f()?;
        let pair = pair.borrow();

        let a_var = PseudonymArgsVar {
            context: FpVar::new_variable(cs.clone(), || Ok(pair.a.context), mode)?,
            claimed: FpVar::new_variable(cs.clone(), || Ok(pair.a.claimed), mode)?,
        };

        let b_var = PseudonymArgsVar {
            context: FpVar::new_variable(cs.clone(), || Ok(pair.b.context), mode)?,
            claimed: FpVar::new_variable(cs, || Ok(pair.b.claimed), mode)?,
        };

        Ok(Self { a: a_var, b: b_var })
    }
}

pub fn authorship_pred<'a, 'b>(
    tu: &'a UserVar<F, MsgUser>,
    _com: &'b FpVar<F>,
    pub_args: PseudonymArgsPairVar<F>,
    _priv_args: (),
) -> ArkResult<Boolean<F>> {
    let context = pub_args.a.context;
    let claimed = pub_args.a.claimed;
    let derived = Poseidon::<2>::hash_in_zk(&[tu.data.sk.clone(), context.clone()])?;

    let x1 = derived.is_eq(&claimed)?;

    let context2 = pub_args.b.context;
    let claimed2 = pub_args.b.claimed;
    let derived2 = Poseidon::<2>::hash_in_zk(&[tu.data.sk.clone(), context2.clone()])?;

    let x2 = derived2.is_eq(&claimed2)?;

    Ok(x1 & x2)
}

fn standard_method(tu: &User<F, MsgUser>, _args: F, _priv: ()) -> User<F, MsgUser> {
    let mut u = tu.clone();
    u.data.num_interactions_since_last_scan += F::from(1);
    u
}

fn standard_pseudo_method(
    tu: &User<F, MsgUser>,
    _args: PseudonymArgs<F>,
    _priv: (),
) -> User<F, MsgUser> {
    let mut u = tu.clone();
    u.data.num_interactions_since_last_scan += F::from(1);
    u
}

fn standard_pseudo_rate_method(
    tu: &User<F, MsgUser>,
    _args: PseudonymArgsRate<F>,
    _priv: (),
) -> User<F, MsgUser> {
    let mut u = tu.clone();
    u.data.num_interactions_since_last_scan += F::from(1);
    u
}

fn standard_predicate<'a>(
    tu_old: &'a UserVar<F, MsgUser>,
    tu_new: &'a UserVar<F, MsgUser>,
    _args: FpVar<F>,
    _priv: (),
) -> ArkResult<Boolean<F>> {
    let x1 = tu_new.data.num_interactions_since_last_scan.is_eq(
        &(tu_old.data.num_interactions_since_last_scan.clone() + FpVar::Constant(F::from(1))),
    )?;
    let x2 = tu_new.data.reputation.is_eq(&tu_old.data.reputation)?;
    let x3 = tu_new
        .data
        .num_interactions_since_last_scan
        .is_neq(&FpVar::Constant(F::from(NUM_INTS_BEFORE_SCAN as u64)))?;

    // Make sure user is not banned
    let x4 = tu_new.data.banned.is_eq(&FpVar::Constant(F::from(0)))?;
    let x5 = tu_new.data.sk.is_eq(&tu_old.data.sk)?;

    let x6 = tu_new.data.badge1.is_eq(&tu_old.data.badge1)?;
    let x7 = tu_new.data.badge2.is_eq(&tu_old.data.badge2)?;
    let x8 = tu_new.data.badge3.is_eq(&tu_old.data.badge3)?;

    Ok(x1 & x2 & x3 & x4 & x5 & x6 & x7 & x8)
}

fn standard_pseudo_predicate<'a>(
    tu_old: &'a UserVar<F, MsgUser>,
    tu_new: &'a UserVar<F, MsgUser>,
    pub_args: PseudonymArgsVar<F>,
    _priv: (),
) -> ArkResult<Boolean<F>> {
    let x1 = tu_new.data.num_interactions_since_last_scan.is_eq(
        &(tu_old.data.num_interactions_since_last_scan.clone() + FpVar::Constant(F::from(1))),
    )?;
    let x2 = tu_new.data.reputation.is_eq(&tu_old.data.reputation)?;
    let x3 = tu_new
        .data
        .num_interactions_since_last_scan
        .is_neq(&FpVar::Constant(F::from(NUM_INTS_BEFORE_SCAN as u64)))?;

    // Make sure user is not banned
    let x4 = tu_new.data.banned.is_eq(&FpVar::Constant(F::from(0)))?;
    let x5 = tu_new.data.sk.is_eq(&tu_old.data.sk)?;

    let x6 = tu_new.data.badge1.is_eq(&tu_old.data.badge1)?;
    let x7 = tu_new.data.badge2.is_eq(&tu_old.data.badge2)?;
    let x8 = tu_new.data.badge3.is_eq(&tu_old.data.badge3)?;

    // Pseudonym check
    let context = pub_args.context;
    let claimed = pub_args.claimed;
    let derived = Poseidon::<2>::hash_in_zk(&[tu_new.data.sk.clone(), context.clone()])?;
    let x9 = derived.is_eq(&claimed)?;

    Ok(x1 & x2 & x3 & x4 & x5 & x6 & x7 & x8 & x9)
}

fn standard_pseudo_rate_predicate<'a>(
    tu_old: &'a UserVar<F, MsgUser>,
    tu_new: &'a UserVar<F, MsgUser>,
    pub_args: PseudonymArgsRateVar<F>,
    _priv: (),
) -> ArkResult<Boolean<F>> {
    let x1 = tu_new.data.num_interactions_since_last_scan.is_eq(
        &(tu_old.data.num_interactions_since_last_scan.clone() + FpVar::Constant(F::from(1))),
    )?;
    let x2 = tu_new.data.reputation.is_eq(&tu_old.data.reputation)?;
    let x3 = tu_new
        .data
        .num_interactions_since_last_scan
        .is_neq(&FpVar::Constant(F::from(NUM_INTS_BEFORE_SCAN as u64)))?;

    // Make sure user is not banned
    let x4 = tu_new.data.banned.is_eq(&FpVar::Constant(F::from(0)))?;
    let x5 = tu_new.data.sk.is_eq(&tu_old.data.sk)?;

    let x6 = tu_new.data.badge1.is_eq(&tu_old.data.badge1)?;
    let x7 = tu_new.data.badge2.is_eq(&tu_old.data.badge2)?;
    let x8 = tu_new.data.badge3.is_eq(&tu_old.data.badge3)?;

    // Pseudonym check
    let context = pub_args.context;
    let claimed = pub_args.claimed;
    let i = pub_args.i;

    let x9 = i.is_neq(&FpVar::Constant(F::from(MAX_PSEUDO as u64)))?;

    let derived = Poseidon::<2>::hash_in_zk(&[tu_new.data.sk.clone(), context, i])?;
    let x10 = derived.is_eq(&claimed)?;

    Ok(x1 & x2 & x3 & x4 & x5 & x6 & x7 & x8 & x9 & x10)
}

pub fn arg_rep(n: i64) -> Fr {
    F::from(n)
}

pub fn arg_ban() -> Fr {
    F::from(999999999)
}

fn standard_callback_method(user: &User<F, MsgUser>, argument: F) -> User<F, MsgUser> {
    let mut u = user.clone();
    let raw = argument.into_bigint().0[0];
    if raw == BAN_FLAG {
        u.data.banned = F::from(1);
    } else {
        u.data.reputation += F::from(raw);
    }
    u.data.num_interactions_since_last_scan = F::ZERO;
    u
}

fn standard_callback_predicate(
    user: &UserVar<F, MsgUser>,
    argument: FpVar<F>,
) -> ArkResult<UserVar<F, MsgUser>> {
    let mut u = user.clone();

    let is_ban = argument.is_eq(&FpVar::Constant(F::from(0)))?;

    // Update reputation: if not banned, rep = rep + argument
    let new_rep = &user.data.reputation + &argument;
    u.data.reputation = FpVar::conditionally_select(&is_ban, &user.data.reputation, &new_rep)?;

    u.data.num_interactions_since_last_scan = FpVar::zero();
    Ok(u)
}

fn scan_method<CBul: PublicCallbackBul<F, Args, Cr> + Clone>(
    tu: &User<F, MsgUser>,
    pub_args: PubScan<CBul>,
    priv_args: PrivScan<CBul>,
) -> User<F, MsgUser> {
    let interaction =
        scan::get_scan_interaction::<F, MsgUser, Args, ArgsVar, Cr, CBul, Poseidon<2>, 1>();
    let mut out_user = (interaction.meth.0)(tu, pub_args, priv_args);
    out_user.data.num_interactions_since_last_scan = F::ZERO;
    out_user
}

// Hari
// fn scan_predicate<CBul: PublicCallbackBul<F, Args, Cr> + Clone>(
//     user_old: &UserVar<F, MsgUser>,
//     user_new: &UserVar<F, MsgUser>,
//     pub_args: PubScanVar<CBul>,
//     priv_args: PrivScanVar<CBul>,
// ) -> ArkResult<Boolean<F>> {
//     let interaction =
//         scan::get_scan_interaction::<F, MsgUser, Args, ArgsVar, Cr, CBul, Poseidon<2>, 1>();
//     let x = (interaction.meth.1)(user_old, user_new, pub_args, priv_args);
//     x.map(|a| {
//         a & user_new
//             .data
//             .num_interactions_since_last_scan
//             .is_eq(&FpVar::zero())
//             .unwrap()
//     })
// }

fn scan_predicate<CBul: PublicCallbackBul<F, Args, Cr> + Clone>(
    _user_old: &UserVar<F, MsgUser>,
    _user_new: &UserVar<F, MsgUser>,
    _pub_args: PubScanVar<CBul>,
    _priv_args: PrivScanVar<CBul>,
) -> ArkResult<Boolean<F>> {
    Ok(Boolean::TRUE)
}

pub fn get_callbacks() -> Vec<Callback<F, MsgUser, Args, ArgsVar>> {
    let standard_callback = Callback {
        method_id: Id::from(0),
        expirable: false,
        expiration: Time::from(10),
        method: standard_callback_method,
        predicate: standard_callback_predicate,
    };

    vec![standard_callback]
}

pub type StandInt = Interaction<F, MsgUser, F, FpVar<F>, (), (), Args, ArgsVar, 1>;

pub type PseudoStandInt =
    Interaction<F, MsgUser, PseudonymArgs<F>, PseudonymArgsVar<F>, (), (), Args, ArgsVar, 1>;

pub type PseudoRateStandInt = Interaction<
    F,
    MsgUser,
    PseudonymArgsRate<F>,
    PseudonymArgsRateVar<F>,
    (),
    (),
    Args,
    ArgsVar,
    1,
>;

pub fn get_standard_interaction() -> StandInt {
    Interaction {
        meth: (standard_method, standard_predicate),
        callbacks: get_callbacks().try_into().unwrap(),
    }
}

pub fn get_standard_pseudo_interaction() -> PseudoStandInt {
    Interaction {
        meth: (standard_pseudo_method, standard_pseudo_predicate),
        callbacks: get_callbacks().try_into().unwrap(),
    }
}

pub fn get_standard_pseudo_rate_interaction() -> PseudoRateStandInt {
    Interaction {
        meth: (standard_pseudo_rate_method, standard_pseudo_rate_predicate),
        callbacks: get_callbacks().try_into().unwrap(),
    }
}

pub fn exec_standint<Bul: PublicUserBul<F, MsgUser>>(
    user: &mut User<F, MsgUser>,
    rng: &mut (impl CryptoRng + RngCore),
    bul: &Bul,
    pk: &PK,
    cur_time: Time<F>,
    pub_args: F,
    priv_args: (),
) -> ArkResult<ExecutedMethod<F, Snark, Args, Cr, 1>> {
    user.exec_method_create_cb::<H, F, FpVar<F>, (), (), Args, ArgsVar, Cr, Snark, Bul, 1>(
        rng,
        get_standard_interaction(),
        [FakeSigPubkey::pk()],
        cur_time,
        bul,
        true,
        pk,
        pub_args,
        priv_args,
    )
}

pub fn exec_pseudo_standint<Bul: PublicUserBul<F, MsgUser>>(
    user: &mut User<F, MsgUser>,
    rng: &mut (impl CryptoRng + RngCore),
    bul: &Bul,
    pk: &PK,
    cur_time: Time<F>,
    pub_args: PseudonymArgs<F>,
    priv_args: (),
) -> ArkResult<ExecutedMethod<F, Snark, Args, Cr, 1>> {
    user.exec_method_create_cb::<H, PseudonymArgs<F>, PseudonymArgsVar<F>, (), (), Args, ArgsVar, Cr, Snark, Bul, 1>(
        rng,
        get_standard_pseudo_interaction(),
        [FakeSigPubkey::pk()],
        cur_time,
        bul,
        true,
        pk,
        pub_args,
        priv_args,
    )
}

pub fn exec_pseudo_rate_standint<Bul: PublicUserBul<F, MsgUser>>(
    user: &mut User<F, MsgUser>,
    rng: &mut (impl CryptoRng + RngCore),
    bul: &Bul,
    pk: &PK,
    cur_time: Time<F>,
    pub_args: PseudonymArgsRate<F>,
    priv_args: (),
) -> ArkResult<ExecutedMethod<F, Snark, Args, Cr, 1>> {
    user.exec_method_create_cb::<H, PseudonymArgsRate<F>, PseudonymArgsRateVar<F>, (), (), Args, ArgsVar, Cr, Snark, Bul, 1>(
        rng,
        get_standard_pseudo_rate_interaction(),
        [FakeSigPubkey::pk()],
        cur_time,
        bul,
        true,
        pk,
        pub_args,
        priv_args,
    )
}

pub type PubScan<CBul> = PubScanArgs<F, MsgUser, Args, ArgsVar, Cr, CBul, 1>;
pub type PubScanVar<CBul> = PubScanArgsVar<F, MsgUser, Args, ArgsVar, Cr, CBul, 1>;

pub type PrivScan<CBul> = PrivScanArgs<F, Args, Cr, CBul, 1>;
pub type PrivScanVar<CBul> = PrivScanArgsVar<F, Args, Cr, CBul, 1>;

pub type ScanInt<CBul> = Interaction<
    F,
    MsgUser,
    PubScan<CBul>,
    PubScanVar<CBul>,
    PrivScan<CBul>,
    PrivScanVar<CBul>,
    Args,
    ArgsVar,
    0,
>;

pub fn get_scan_interaction<CBul: PublicCallbackBul<F, Args, Cr> + Clone>() -> ScanInt<CBul> {
    Interaction {
        meth: (scan_method, scan_predicate),
        callbacks: [],
    }
}

pub fn exec_scanint<
    Bul: PublicUserBul<F, MsgUser>,
    CBul: PublicCallbackBul<F, Args, Cr> + std::fmt::Debug + Clone,
>(
    user: &mut User<F, MsgUser>,
    rng: &mut (impl CryptoRng + RngCore),
    bul: &Bul,
    pk: &PK,
    cbul: &CBul,
    cur_time: Time<F>,
) -> ArkResult<ExecutedMethod<F, Snark, Args, Cr, 0>>
where
    CBul::MembershipPub: std::fmt::Debug,
    CBul::NonMembershipPub: std::fmt::Debug,
{
    let (ps, prs) =
        user.get_scan_arguments::<_, _, _, _, 1>(cbul, (true, true), cur_time, get_callbacks());

    user.interact::<H, _, _, _, _, _, _, Cr, Snark, Bul, 0>(
        rng,
        get_scan_interaction(),
        [],
        cur_time,
        bul.get_membership_data(user.commit::<H>()).unwrap(),
        true,
        pk,
        ps,
        prs,
        true,
    )
}

pub fn get_extra_pubdata_for_scan<CBul: PublicCallbackBul<F, Args, Cr> + Clone>(
    cstore: &CBul,
    memb_pub: <CBul as PublicCallbackBul<F, Args, Cr>>::MembershipPub,
    nmemb_pub: <CBul as PublicCallbackBul<F, Args, Cr>>::NonMembershipPub,
    time: Time<F>,
) -> PubScan<CBul> {
    PubScan {
        memb_pub: [memb_pub; 1],
        is_memb_data_const: true,
        nmemb_pub: [nmemb_pub; 1],
        is_nmemb_data_const: true,
        cur_time: time,
        bulletin: cstore.clone(),
        cb_methods: get_callbacks(),
    }
}

pub fn get_extra_pubdata_for_scan2(
    cstore: &GRSchnorrCallbackStore<F>,
    memb_pub: <GRSchnorrCallbackStore<F> as PublicCallbackBul<F, Args, Cr>>::MembershipPub,
    nmemb_pub: <GRSchnorrCallbackStore<F> as PublicCallbackBul<F, Args, Cr>>::NonMembershipPub,
    time: Time<F>,
) -> PubScan<GRSchnorrCallbackStore<F>> {
    PubScan {
        memb_pub: [memb_pub; 1],
        is_memb_data_const: true,
        nmemb_pub: [nmemb_pub; 1],
        is_nmemb_data_const: true,
        cur_time: time,
        bulletin: cstore.clone(),
        cb_methods: get_callbacks(),
    }
}

// use ark_crypto_primitives::snark::SNARK;
// use ark_crypto_primitives::sponge::Absorb;
// use ark_std::marker::PhantomData;
// use rand::distributions::Standard;
// use rand::prelude::Distribution;
// use zk_callbacks::crypto::enc::AECipherSigZK;
// use zk_callbacks::crypto::hash::FieldHash;
// use zk_callbacks::generic::callbacks::CallbackCom;
// use zk_callbacks::generic::interaction::CallbackList;
// use zk_callbacks::generic::interaction::ExecMethodCircuit;
// use zk_callbacks::generic::interaction::MethProof;
// use zk_callbacks::generic::user::UserData;

// #[derive(Clone)]
// pub struct PseudoInteraction<
//     F: PrimeField + Absorb,
//     U: UserData<F>,
//     PubArgs: Clone,
//     PubArgsVar: AllocVar<PubArgs, F>,
//     PrivArgs: Clone,
//     PrivArgsVar: AllocVar<PrivArgs, F>,
//     CBArgs: Clone,
//     CBArgsVar: AllocVar<CBArgs, F>,
//     const NUMCBS: usize,
// > {
//     /// A method and a predicate. For example, one may have an update method, with a predicate
//     /// enforcing some reputation status.
//     pub meth: MethProof<F, U, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar>,
//     /// A list of callbacks.
//     pub callbacks: CallbackList<F, U, CBArgs, CBArgsVar, NUMCBS>,
// }

// impl<
//     F: PrimeField + Absorb,
//     U: UserData<F> + Default,
//     PubArgs: Clone + Default + std::fmt::Debug,
//     PubArgsVar: AllocVar<PubArgs, F> + Clone,
//     PrivArgs: Clone + Default + std::fmt::Debug,
//     PrivArgsVar: AllocVar<PrivArgs, F> + Clone,
//     CBArgs: Clone + Default + std::fmt::Debug,
//     CBArgsVar: AllocVar<CBArgs, F> + Clone,
//     const NUMCBS: usize,
// > PseudoInteraction<F, U, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar, CBArgs, CBArgsVar, NUMCBS>
// where
//     Standard: Distribution<F>,
// {
//     pub fn generate_keys<
//         H: FieldHash<F>,
//         Snark: SNARK<F>,
//         Crypto: AECipherSigZK<F, CBArgs>,
//         Bul: PublicUserBul<F, U>,
//     >(
//         &self,
//         rng: &mut (impl CryptoRng + RngCore),
//         memb_data: Option<Bul::MembershipPub>,
//         aux_data: Option<PubArgs>,
//         is_scan: bool,
//     ) -> (Snark::ProvingKey, Snark::VerifyingKey) {
//         let u = User::create(U::default(), rng);

//         let cbs: [CallbackCom<F, CBArgs, Crypto>; NUMCBS] =
//             create_defaults((*self).clone(), <Time<F>>::default());

//         let x = (*self).clone();

//         let out: ExecMethodCircuit<
//             F,
//             H,
//             U,
//             PubArgs,
//             PubArgsVar,
//             PrivArgs,
//             PrivArgsVar,
//             CBArgs,
//             CBArgsVar,
//             Crypto,
//             Bul,
//             NUMCBS,
//         > = ExecMethodCircuit {
//             priv_old_user: u.clone(),
//             priv_new_user: u.clone(),
//             priv_issued_callbacks: cbs.clone(),
//             priv_bul_membership_witness: Bul::MembershipWitness::default(),
//             priv_args: PrivArgs::default(),

//             pub_new_com: u.commit::<H>(),
//             pub_old_nul: u.zk_fields.nul,
//             pub_issued_callback_coms: cbs.map(|x| x.commit::<H>()),
//             pub_args: aux_data.unwrap_or_default(),
//             associated_method: x,
//             is_scan,
//             bul_memb_is_const: memb_data.is_some(),
//             pub_bul_membership_data: memb_data.unwrap_or_default(),
//             _phantom_hash: PhantomData,
//         };

//         Snark::circuit_specific_setup(out, rng).unwrap()
//     }
// }
// use ark_crypto_primitives::sponge::Absorb;

// pub enum PredicateMethod<F: PrimeField + Absorb> {
//     Old(
//         for<'a, 'b> fn(
//             &'a UserVar<F, MsgUser>,
//             &'b UserVar<F, MsgUser>,
//             FpVar<F>,
//             (),
//         ) -> Result<(), SynthesisError>,
//     ),
//     New(
//         for<'a> fn(
//             &'a UserVar<F, MsgUser>,
//             &'a UserVar<F, MsgUser>,
//             PseudonymArgsVar<F>,
//             (),
//         ) -> Result<(), SynthesisError>,
//     ),
// }

// pub struct Interaction<F: PrimeField> {
//     pub meth: PredicateMethod<F>,
//     pub callbacks: Vec<Callback<F>>,
// }
