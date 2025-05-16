use ark_bn254::{constraints::GVar, Bn254 as E, Fr as F, G1Projective as Projective};
use ark_groth16::Groth16;
use ark_grumpkin::{constraints::GVar as GVar2, Projective as Projective2};
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, prelude::Boolean};
use ark_relations::r1cs::Result as ArkResult;
use folding_schemes::{
    commitment::pedersen::Pedersen,
    folding::nova::{zk::RandomizedIVCProof, Nova, PreprocessorParam},
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    FoldingScheme,
};
use rand::thread_rng;
use std::time::SystemTime;
use zk_callbacks::{
    generic::{
        bulletin::{JoinableBulletin, PublicCallbackBul, UserBul},
        fold::{FoldSer, FoldableUserData, FoldingScan},
        interaction::{Callback, Interaction},
        object::{Id, Time},
        scan::{
            scan_method, scan_predicate, PrivScanArgs, PrivScanArgsVar, PubScanArgs, PubScanArgsVar,
        },
        service::ServiceProvider,
        user::{User, UserVar},
    },
    impls::{
        centralized::{
            crypto::{FakeSigPrivkey, FakeSigPubkey, NoSigOTP},
            ds::sigstore::{NonmembStore, UOVCallbackStore, UOVObjStore, UOVStore},
        },
        hash::Poseidon,
    },
};
use zk_object::scannable_zk_object;

#[scannable_zk_object(F)]
#[derive(Default)]
pub struct TestFolding {
    pub token1: F,
    pub token2: F,
}

impl FoldSer<F, TestFoldingZKVar> for TestFolding {
    fn repr_len() -> usize {
        2
    }

    fn to_fold_repr(&self) -> Vec<zk_callbacks::generic::object::Ser<F>> {
        vec![self.token1.clone(), self.token2.clone()]
    }

    fn from_fold_repr(ser: &[zk_callbacks::generic::object::Ser<F>]) -> Self {
        Self {
            token1: ser[0].clone(),
            token2: ser[1].clone(),
        }
    }

    fn from_fold_repr_zk(
        var: &[zk_callbacks::generic::object::SerVar<F>],
    ) -> Result<TestFoldingZKVar, ark_relations::r1cs::SynthesisError> {
        Ok(TestFoldingZKVar {
            token1: var[0].clone(),
            token2: var[1].clone(),
        })
    }

    fn to_fold_repr_zk(
        var: &TestFoldingZKVar,
    ) -> Result<Vec<zk_callbacks::generic::object::SerVar<F>>, ark_relations::r1cs::SynthesisError>
    {
        Ok(vec![var.token1.clone(), var.token2.clone()])
    }
}

impl FoldableUserData<F> for TestFolding {}

const NUMSCANS: usize = 1;
type CBArg = F;
type CBArgVar = FpVar<F>;
type U = User<F, TestFolding>;
type UV = UserVar<F, TestFolding>;
type CB = Callback<F, TestFolding, CBArg, CBArgVar>;
type Int1 = Interaction<F, TestFolding, (), (), (), (), CBArg, CBArgVar, 1>;
type PubScan =
    PubScanArgs<F, TestFolding, F, FpVar<F>, NoSigOTP<F>, UOVCallbackStore<F, F>, NUMSCANS>;
type PubScanVar =
    PubScanArgsVar<F, TestFolding, F, FpVar<F>, NoSigOTP<F>, UOVCallbackStore<F, F>, NUMSCANS>;

type PrivScan = PrivScanArgs<F, F, NoSigOTP<F>, UOVCallbackStore<F, F>, NUMSCANS>;
type PrivScanVar = PrivScanArgsVar<F, F, NoSigOTP<F>, UOVCallbackStore<F, F>, NUMSCANS>;

type IntScan =
    Interaction<F, TestFolding, PubScan, PubScanVar, PrivScan, PrivScanVar, CBArg, CBArgVar, 0>;

type OSt = UOVObjStore<F>;
type CSt = UOVCallbackStore<F, F>;
type St = UOVStore<F, F>;

fn int_meth<'a>(tu: &'a U, _pub_args: (), _priv_args: ()) -> U {
    let mut a = tu.clone();
    a.data.token1 += F::from(1);

    a
}

fn int_meth_pred<'a>(
    tu_old: &'a UV,
    tu_new: &'a UV,
    _pub_args: (),
    _priv_args: (),
) -> ArkResult<Boolean<F>> {
    let l0 = tu_new.data.token1.is_eq(&FpVar::Constant(F::from(0)))?;
    let l1 = tu_new.data.token1.is_eq(&FpVar::Constant(F::from(1)))?;
    let l2 = tu_new.data.token1.is_eq(&FpVar::Constant(F::from(2)))?;
    let o2 = tu_old.data.token1.clone() + FpVar::Constant(F::from(1));
    let b2 = tu_new.data.token1.is_eq(&o2)?;
    Ok((l0 | l1 | l2) & b2)
}
fn cb_meth<'a>(tu: &'a U, args: F) -> U {
    let mut out = tu.clone();
    out.data.token1 = args;
    out
}

fn cb_pred<'a>(tu_old: &'a UV, args: FpVar<F>) -> ArkResult<UV> {
    let mut tu_new = tu_old.clone();
    tu_new.data.token1 = args;
    Ok(tu_new)
}

fn main() {
    // SERVER SETUP
    let mut rng = thread_rng();

    // create a single callback type
    let cb: CB = Callback {
        method_id: Id::from(0),
        expirable: false,
        expiration: Time::from(300),
        method: cb_meth,
        predicate: cb_pred,
    };

    // irrelevant callback type, we create it to test the checks
    let cb2: CB = Callback {
        method_id: Id::from(1),
        expirable: true,
        expiration: Time::from(1),
        method: cb_meth,
        predicate: cb_pred,
    };

    let mut store = St::new(&mut rng);

    let cb_methods = vec![cb.clone(), cb2.clone()];

    let interaction: Int1 = Interaction {
        meth: (int_meth, int_meth_pred),
        callbacks: [cb.clone()],
    };

    let cb_interaction: IntScan = Interaction {
        meth: (
            scan_method::<F, TestFolding, F, FpVar<F>, NoSigOTP<F>, CSt, Poseidon<2>, NUMSCANS>,
            scan_predicate::<F, TestFolding, F, FpVar<F>, NoSigOTP<F>, CSt, Poseidon<2>, NUMSCANS>,
        ),
        callbacks: [],
    };

    let ex = PubScanArgs {
        memb_pub: [store.callback_bul.get_pubkey(); NUMSCANS],
        is_memb_data_const: true,
        nmemb_pub: [store.callback_bul.nmemb_bul.get_pubkey(); NUMSCANS],
        is_nmemb_data_const: true,
        cur_time: F::from(0),
        bulletin: store.callback_bul.clone(),
        cb_methods: cb_methods.clone(),
    };

    // generate keys for the method described initially
    let (pk, vk) = interaction // see interaction
        .generate_keys::<Poseidon<2>, Groth16<E>, NoSigOTP<F>, OSt>(
            &mut rng,
            Some(store.obj_bul.get_pubkey()),
            None,
            false,
        );

    // generate keys for the callback scan
    let (_pks, _vks) = cb_interaction // see cb_interaction
        .generate_keys::<Poseidon<2>, Groth16<E>, NoSigOTP<F>, OSt>(
            &mut rng,
            Some(store.obj_bul.get_pubkey()),
            Some(ex),
            true,
        );

    let mut u = User::create(
        TestFolding {
            token1: F::from(0),
            token2: F::from(3),
        },
        &mut rng,
    );

    let _ = <OSt as JoinableBulletin<F, TestFolding>>::join_bul(
        &mut store.obj_bul,
        u.commit::<Poseidon<2>>(),
        (),
    );

    let exec_method = u
        .exec_method_create_cb::<Poseidon<2>, (), (), (), (), F, FpVar<F>, NoSigOTP<F>, Groth16<E>, OSt, 1>(
            &mut rng,
            interaction.clone(), // see interaction
            [FakeSigPubkey::pk()],
            Time::from(0),
            &store.obj_bul,
            true,
            &pk,
            (),
            (),
        )
        .unwrap();

    let _out = <OSt as UserBul<F, TestFolding>>::verify_interact_and_append::<(), Groth16<E>, 1>(
        &mut store.obj_bul,
        exec_method.new_object.clone(),
        exec_method.old_nullifier.clone(),
        (),
        exec_method.cb_com_list.clone(),
        exec_method.proof.clone(),
        None,
        &vk,
    );
    // Server checks proof on interaction with the verification key, approves it, and stores the new object into the store

    let _ = store
        .approve_interaction_and_store::<TestFolding, Groth16<E>, (), OSt, Poseidon<2>, 1>(
            exec_method,          // output of interaction
            FakeSigPrivkey::sk(), // for authenticity: verify rerandomization of key produces
            // proper tickets (here it doesn't matter)
            (),
            &store.obj_bul.clone(),
            cb_methods.clone(),
            Time::from(0),
            store.obj_bul.get_pubkey(),
            true,
            &vk,
            332, // interaction number
        );

    let exec_method2 = u
        .exec_method_create_cb::<Poseidon<2>, (), (), (), (), F, FpVar<F>, NoSigOTP<F>, Groth16<E>, OSt, 1>(
            &mut rng,
            interaction.clone(),
            [FakeSigPubkey::pk()],
            Time::from(0),
            &store.obj_bul,
            true,
            &pk,
            (),
            (),
        )
        .unwrap();

    let _ = <OSt as UserBul<F, TestFolding>>::verify_interact_and_append::<(), Groth16<E>, 1>(
        &mut store.obj_bul,
        exec_method2.new_object.clone(),
        exec_method2.old_nullifier.clone(),
        (),
        exec_method2.cb_com_list.clone(),
        exec_method2.proof.clone(),
        None,
        &vk,
    );

    // The server approves the interaction and stores it again
    let _ = store
        .approve_interaction_and_store::<TestFolding, Groth16<E>, (), OSt, Poseidon<2>, 1>(
            exec_method2,
            FakeSigPrivkey::sk(),
            (),
            &store.obj_bul.clone(),
            cb_methods.clone(),
            Time::from(0),
            store.obj_bul.get_pubkey(),
            true,
            &vk,
            389,
        );

    type NF = Nova<
        Projective,
        GVar,
        Projective2,
        GVar2,
        FoldingScan<F, TestFolding, CBArg, CBArgVar, NoSigOTP<F>, CSt, Poseidon<2>>,
        Pedersen<Projective, true>,
        Pedersen<Projective2, true>,
        true,
    >;

    // Setup a scan for a single callback (the first one in the list)
    let ps = PubScanArgs {
        // Create the public scanning arguments
        memb_pub: [store.callback_bul.get_pubkey()], // Public membership data (pubkey)
        is_memb_data_const: true,                    // it is constant
        nmemb_pub: [store.callback_bul.nmemb_bul.get_pubkey()], // Public nonmemb data (pubkey for range sigs)
        is_nmemb_data_const: true,
        cur_time: store.callback_bul.nmemb_bul.get_epoch(), // *current* time as of this proof generation
        bulletin: store.callback_bul.clone(),               // bulletin handle
        cb_methods: cb_methods.clone(), // Vec of callbacks (used to check which method to call)
    };

    let f_circ: FoldingScan<F, TestFolding, CBArg, CBArgVar, NoSigOTP<F>, CSt, Poseidon<2>> =
        FoldingScan::new(ps.clone()).unwrap();

    let poseidon_config = poseidon_canonical_config::<F>();
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, f_circ.clone());
    let nova_params = NF::preprocess(&mut rng, &nova_preprocess_params).unwrap();

    let init_state = vec![u.commit::<Poseidon<2>>()];

    let cb = u.get_cb(0);
    let tik: FakeSigPubkey<F> = cb.get_ticket();

    let x =
        <CSt as PublicCallbackBul<F, F, NoSigOTP<F>>>::verify_in(&store.callback_bul, tik.clone());

    let prs1: PrivScanArgs<F, CBArg, NoSigOTP<F>, CSt, 1> = PrivScanArgs {
        priv_n_tickets: [cb],
        post_times: [x.map_or(F::from(0), |(_, p2)| p2)],
        enc_args: [x.map_or(F::from(0), |(p1, _)| p1)],
        memb_priv: [store
            .callback_bul
            .get_memb_witness(&tik)
            .unwrap_or_default()],
        nmemb_priv: [store
            .callback_bul
            .get_nmemb_witness(&tik)
            .unwrap_or_default()],
    };

    let cb = u.get_cb(1);
    let tik: FakeSigPubkey<F> = cb.get_ticket();

    let x =
        <CSt as PublicCallbackBul<F, F, NoSigOTP<F>>>::verify_in(&store.callback_bul, tik.clone());

    let prs2: PrivScanArgs<F, CBArg, NoSigOTP<F>, CSt, 1> = PrivScanArgs {
        priv_n_tickets: [cb],
        post_times: [x.map_or(F::from(0), |(_, p2)| p2)],
        enc_args: [x.map_or(F::from(0), |(p1, _)| p1)],
        memb_priv: [store
            .callback_bul
            .get_memb_witness(&tik)
            .unwrap_or_default()],
        nmemb_priv: [store
            .callback_bul
            .get_nmemb_witness(&tik)
            .unwrap_or_default()],
    };

    let mut folding_scheme: NF = NF::init(&nova_params, f_circ, init_state.clone()).unwrap();

    let start = SystemTime::now();

    folding_scheme
        .prove_step(
            &mut rng,
            [u.to_fold_repr(), prs1.to_fold_repr()].concat(),
            None,
        )
        .unwrap();

    println!("Fold step time: {:?}", start.elapsed().unwrap());

    let start = SystemTime::now();

    folding_scheme
        .prove_step(
            &mut rng,
            [u.to_fold_repr(), prs2.to_fold_repr()].concat(),
            None,
        )
        .unwrap();

    println!("Fold step time: {:?}", start.elapsed().unwrap());

    let start = SystemTime::now();

    let _proof = RandomizedIVCProof::new(&folding_scheme, &mut rng).unwrap();

    println!("Finalizing proof time: {:?}", start.elapsed().unwrap());

    // println!("User at the end : {:?}", u);
}
