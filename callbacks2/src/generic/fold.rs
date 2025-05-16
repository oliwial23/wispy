use std::marker::PhantomData;

use ark_r1cs_std::{convert::ToConstraintFieldGadget, select::CondSelectGadget};

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::SynthesisError;
use folding_schemes::frontend::FCircuit;

use crate::{
    crypto::{
        enc::{AECipherSigZK, CPACipher},
        hash::FieldHash,
    },
    generic::{
        callbacks::{CallbackCom, CallbackTicket},
        scan::{scan_apply_method_zk, scan_method, PubScanArgsVar},
    },
};

use crate::generic::{
    bulletin::PublicCallbackBul,
    callbacks::{CallbackComVar, CallbackTicketVar},
    object::{Ser, SerVar, ZKFields, ZKFieldsVar},
    scan::{PrivScanArgs, PrivScanArgsVar, PubScanArgs},
    user::{User, UserData, UserVar},
};

/// Serialize elements into a foldable representation for use in PSE's folding-schemes.
pub trait FoldSer<F: PrimeField, ArgsVar: AllocVar<Self, F>> {
    /// Get the length of the serialized representation.
    fn repr_len() -> usize;

    /// Construct the serialized representation.
    fn to_fold_repr(&self) -> Vec<Ser<F>>;

    /// Construct the object from a serialized representation (deserialize).
    fn from_fold_repr(ser: &[Ser<F>]) -> Self;

    /// Deserialize the serialized representation into the object in-circuit.
    fn from_fold_repr_zk(var: &[SerVar<F>]) -> Result<ArgsVar, SynthesisError>;

    /// Construct the serialized representation in-circuit.
    fn to_fold_repr_zk(var: &ArgsVar) -> Result<Vec<SerVar<F>>, SynthesisError>;
}

impl<F: PrimeField> FoldSer<F, FpVar<F>> for F {
    fn repr_len() -> usize {
        1
    }

    fn to_fold_repr(&self) -> Vec<crate::generic::object::Ser<F>> {
        vec![*self]
    }

    fn from_fold_repr(ser: &[crate::generic::object::Ser<F>]) -> Self {
        ser[0]
    }

    fn from_fold_repr_zk(
        var: &[crate::generic::object::SerVar<F>],
    ) -> Result<FpVar<F>, SynthesisError> {
        Ok(var[0].clone())
    }

    fn to_fold_repr_zk(
        var: &FpVar<F>,
    ) -> Result<Vec<crate::generic::object::SerVar<F>>, SynthesisError> {
        Ok(vec![var.clone()])
    }
}

/// A user which also can be converted into a foldable serialized representation.
///
/// This is necessary for a user to be foldable.
pub trait FoldableUserData<F: PrimeField + Absorb>:
    UserData<F> + FoldSer<F, Self::UserDataVar>
{
}

impl<F: PrimeField> ZKFields<F> {
    /// Deserialize the bookkeeping fields in a user from a folded representation.
    pub fn deserialize(data: &[Ser<F>]) -> Self {
        let ing = match data[5] {
            t if t == F::from(0) => false,
            t if t == F::from(1) => true,
            _ => true,
        };
        Self {
            nul: data[0],
            com_rand: data[1],
            callback_hash: data[2],
            new_in_progress_callback_hash: data[3],
            old_in_progress_callback_hash: data[4],
            is_ingest_over: ing,
        }
    }
}

impl<F: PrimeField> ZKFieldsVar<F> {
    /// Deserialize the bookkeeping fields from a folded representation in-circuit.
    pub fn deserialize(data: &[SerVar<F>]) -> Result<Self, SynthesisError> {
        Ok(Self {
            nul: data[0].clone(),
            com_rand: data[1].clone(),
            callback_hash: data[2].clone(),
            new_in_progress_callback_hash: data[3].clone(),
            old_in_progress_callback_hash: data[4].clone(),
            is_ingest_over: data[5].is_neq(&FpVar::Constant(F::ZERO))?,
        })
    }
}

impl<F: PrimeField> FoldSer<F, ZKFieldsVar<F>> for ZKFields<F> {
    fn repr_len() -> usize {
        6
    }

    fn to_fold_repr(&self) -> Vec<Ser<F>> {
        self.serialize()
    }

    fn from_fold_repr(ser: &[Ser<F>]) -> Self {
        Self::deserialize(ser)
    }

    fn from_fold_repr_zk(var: &[SerVar<F>]) -> Result<ZKFieldsVar<F>, SynthesisError> {
        ZKFieldsVar::deserialize(var)
    }

    fn to_fold_repr_zk(var: &ZKFieldsVar<F>) -> Result<Vec<SerVar<F>>, SynthesisError> {
        ZKFieldsVar::serialize(var)
    }
}

impl<F: PrimeField + Absorb, U: FoldableUserData<F>> FoldSer<F, UserVar<F, U>> for User<F, U> {
    fn repr_len() -> usize {
        U::repr_len() + <ZKFields<F>>::repr_len()
    }

    fn to_fold_repr(&self) -> Vec<Ser<F>> {
        let mut ser = self.data.to_fold_repr();
        ser.extend(self.zk_fields.to_fold_repr());
        ser
    }

    fn from_fold_repr(ser: &[Ser<F>]) -> Self {
        let data = U::from_fold_repr(&ser[0..U::repr_len()]);
        let zk_fields = ZKFields::from_fold_repr(&ser[U::repr_len()..]);
        Self {
            data,
            zk_fields,
            callbacks: vec![],
            scan_index: None,
            in_progress_cbs: vec![],
        }
    }

    fn from_fold_repr_zk(ser: &[SerVar<F>]) -> Result<UserVar<F, U>, SynthesisError> {
        let data = U::from_fold_repr_zk(&ser[0..U::repr_len()])?;
        let zk_fields = ZKFields::from_fold_repr_zk(&ser[U::repr_len()..])?;
        Ok(UserVar { data, zk_fields })
    }

    fn to_fold_repr_zk(var: &UserVar<F, U>) -> Result<Vec<SerVar<F>>, SynthesisError> {
        let mut servar = U::to_fold_repr_zk(&var.data)?;
        servar.extend(<ZKFields<F>>::to_fold_repr_zk(&var.zk_fields)?);
        Ok(servar)
    }
}

impl<
        F: PrimeField + Absorb,
        CBArgs: Clone,
        Crypto: AECipherSigZK<F, CBArgs>,
        CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    > FoldSer<F, PrivScanArgsVar<F, CBArgs, Crypto, CBul, 1>>
    for PrivScanArgs<F, CBArgs, Crypto, CBul, 1>
where
    Crypto::SigPK: FoldSer<F, Crypto::SigPKV>,
    Crypto::EncKey: FoldSer<F, Crypto::EncKeyVar>,
    Crypto::Ct: FoldSer<F, <Crypto::EncKey as CPACipher<F>>::CV>,
    CBul::MembershipWitness: FoldSer<F, CBul::MembershipWitnessVar>,
    CBul::NonMembershipWitness: FoldSer<F, CBul::NonMembershipWitnessVar>,
{
    fn from_fold_repr(ser: &[Ser<F>]) -> Self {
        let mut lc = 0;
        let tik = Crypto::SigPK::from_fold_repr(&ser[0..Crypto::SigPK::repr_len()]);
        lc += Crypto::SigPK::repr_len();
        let cb_method_id = ser[lc];
        lc += 1;
        let expirable = ser[lc] != F::ZERO;
        lc += 1;
        let expiration = ser[lc];
        lc += 1;
        let enc_key = Crypto::EncKey::from_fold_repr(&ser[lc..(lc + Crypto::EncKey::repr_len())]);
        lc += Crypto::EncKey::repr_len();
        let com_rand = ser[lc];
        lc += 1;
        let enc_args = Crypto::Ct::from_fold_repr(&ser[lc..(lc + Crypto::Ct::repr_len())]);
        lc += Crypto::Ct::repr_len();
        let post_times = ser[lc];
        lc += 1;
        let memb_priv = CBul::MembershipWitness::from_fold_repr(
            &ser[lc..(lc + CBul::MembershipWitness::repr_len())],
        );
        lc += CBul::MembershipWitness::repr_len();
        let nmemb_priv = CBul::NonMembershipWitness::from_fold_repr(
            &ser[lc..(lc + CBul::NonMembershipWitness::repr_len())],
        );

        let cb_entry: CallbackTicket<F, CBArgs, Crypto> = CallbackTicket {
            tik,
            cb_method_id,
            expirable,
            expiration,
            enc_key,
        };

        let priv_ticket = CallbackCom { cb_entry, com_rand };

        PrivScanArgs {
            priv_n_tickets: [priv_ticket],
            enc_args: [enc_args],
            post_times: [post_times],
            memb_priv: [memb_priv],
            nmemb_priv: [nmemb_priv],
        }
    }

    fn from_fold_repr_zk(
        ser: &[SerVar<F>],
    ) -> Result<PrivScanArgsVar<F, CBArgs, Crypto, CBul, 1>, SynthesisError> {
        let mut lc = 0;
        let tik = Crypto::SigPK::from_fold_repr_zk(&ser[0..Crypto::SigPK::repr_len()])?;
        lc += Crypto::SigPK::repr_len();
        let cb_method_id = ser[lc].clone();
        lc += 1;
        let expirable = ser[lc].is_neq(&FpVar::Constant(F::ZERO))?;
        lc += 1;
        let expiration = ser[lc].clone();
        lc += 1;
        let enc_key =
            Crypto::EncKey::from_fold_repr_zk(&ser[lc..(lc + Crypto::EncKey::repr_len())])?;
        lc += Crypto::EncKey::repr_len();
        let com_rand = ser[lc].clone();
        lc += 1;
        let enc_args = Crypto::Ct::from_fold_repr_zk(&ser[lc..(lc + Crypto::Ct::repr_len())])?;
        lc += Crypto::Ct::repr_len();
        let post_times = ser[lc].clone();
        lc += 1;
        let memb_priv = CBul::MembershipWitness::from_fold_repr_zk(
            &ser[lc..(lc + CBul::MembershipWitness::repr_len())],
        )?;
        lc += CBul::MembershipWitness::repr_len();
        let nmemb_priv = CBul::NonMembershipWitness::from_fold_repr_zk(
            &ser[lc..(lc + CBul::NonMembershipWitness::repr_len())],
        )?;

        let cb_entry: CallbackTicketVar<F, CBArgs, Crypto> = CallbackTicketVar {
            tik,
            cb_method_id,
            expirable,
            expiration,
            enc_key,
        };

        let priv_ticket = CallbackComVar { cb_entry, com_rand };

        Ok(PrivScanArgsVar {
            priv_n_tickets: [priv_ticket],
            enc_args: [enc_args],
            post_times: [post_times],
            memb_priv: [memb_priv],
            nmemb_priv: [nmemb_priv],
        })
    }

    fn repr_len() -> usize {
        Crypto::SigPK::repr_len()
            + 1
            + 1
            + 1
            + Crypto::EncKey::repr_len()
            + 1
            + Crypto::Ct::repr_len()
            + 1
            + CBul::MembershipWitness::repr_len()
            + CBul::NonMembershipWitness::repr_len()
    }

    fn to_fold_repr(&self) -> Vec<Ser<F>> {
        let mut ser = self.priv_n_tickets[0].cb_entry.tik.to_fold_repr();
        ser.push(self.priv_n_tickets[0].cb_entry.cb_method_id);
        ser.push(F::from(self.priv_n_tickets[0].cb_entry.expirable));
        ser.push(self.priv_n_tickets[0].cb_entry.expiration);
        ser.extend(self.priv_n_tickets[0].cb_entry.enc_key.to_fold_repr());
        ser.push(self.priv_n_tickets[0].com_rand);
        ser.extend(self.enc_args[0].to_fold_repr());
        ser.push(self.post_times[0]);
        ser.extend(self.memb_priv[0].to_fold_repr());
        ser.extend(self.nmemb_priv[0].to_fold_repr());
        ser
    }

    fn to_fold_repr_zk(
        var: &PrivScanArgsVar<F, CBArgs, Crypto, CBul, 1>,
    ) -> Result<Vec<SerVar<F>>, SynthesisError> {
        let mut ser = Crypto::SigPK::to_fold_repr_zk(&var.priv_n_tickets[0].cb_entry.tik)?;
        ser.push(var.priv_n_tickets[0].cb_entry.cb_method_id.clone());
        ser.extend(
            var.priv_n_tickets[0]
                .cb_entry
                .expirable
                .to_constraint_field()?,
        );
        ser.push(var.priv_n_tickets[0].cb_entry.expiration.clone());
        ser.extend(Crypto::EncKey::to_fold_repr_zk(
            &var.priv_n_tickets[0].cb_entry.enc_key,
        )?);
        ser.push(var.priv_n_tickets[0].com_rand.clone());
        ser.extend(Crypto::Ct::to_fold_repr_zk(&var.enc_args[0])?);
        ser.push(var.post_times[0].clone());
        ser.extend(CBul::MembershipWitness::to_fold_repr_zk(&var.memb_priv[0])?);
        ser.extend(CBul::NonMembershipWitness::to_fold_repr_zk(
            &var.nmemb_priv[0],
        )?);
        Ok(ser)
    }
}

/// This allows for users to perform a folding scan instead of scanning incremenetally.
///
/// This implements `FCircuit` from PSE's folding-schemes, and so it may be used with any folding
/// scheme supported by FCircuit.
///
/// The parameters passed in include the public arguments for the scan. The private arguments are
/// treated as extra witnesses during the folding process.
///
/// At each folding step, [`PrivScanArgs`] are deserialized from the folding representation. This
/// struct will always have a callback count of `1`, as we only fold the scan one step at a time.
#[derive(Clone)]
pub struct FoldingScan<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone + std::fmt::Debug,
    CBArgsVar: AllocVar<CBArgs, F> + Clone,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    H: FieldHash<F>,
> {
    _f: PhantomData<F>,
    _u: PhantomData<U>,
    _c: PhantomData<Crypto>,
    _h: PhantomData<H>,
    /// The public arguments during the scan.
    pub const_args: PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, 1>,
}

impl<
        F: PrimeField + Absorb,
        U: UserData<F>,
        CBArgs: Clone + std::fmt::Debug,
        CBArgsVar: AllocVar<CBArgs, F> + Clone,
        Crypto: AECipherSigZK<F, CBArgs>,
        CBul: PublicCallbackBul<F, CBArgs, Crypto>,
        H: FieldHash<F>,
    > std::fmt::Debug for FoldingScan<F, U, CBArgs, CBArgsVar, Crypto, CBul, H>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Folding scan")
    }
}

impl<
        F: PrimeField + Absorb,
        U: FoldableUserData<F>,
        CBArgs: Clone + std::fmt::Debug,
        CBArgsVar: AllocVar<CBArgs, F> + Clone,
        Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar>,
        CBul: PublicCallbackBul<F, CBArgs, Crypto> + Clone + std::fmt::Debug,
        H: FieldHash<F>,
    > FCircuit<F> for FoldingScan<F, U, CBArgs, CBArgsVar, Crypto, CBul, H>
where
    Crypto::SigPK: FoldSer<F, Crypto::SigPKV>,
    Crypto::EncKey: FoldSer<F, Crypto::EncKeyVar>,
    Crypto::Ct: FoldSer<F, <Crypto::EncKey as CPACipher<F>>::CV>,
    CBul::MembershipWitness: FoldSer<F, CBul::MembershipWitnessVar>,
    CBul::NonMembershipWitness: FoldSer<F, CBul::NonMembershipWitnessVar>,
    U::UserDataVar: CondSelectGadget<F> + EqGadget<F>,
{
    type Params = PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, 1>;

    fn new(init: Self::Params) -> Result<Self, folding_schemes::Error> {
        Ok(Self {
            _f: PhantomData,
            _u: PhantomData,
            _c: PhantomData,
            _h: PhantomData,
            const_args: init,
        })
    }

    fn state_len(&self) -> usize {
        1
    }

    fn external_inputs_len(&self) -> usize {
        User::<F, U>::repr_len() + <PrivScanArgs<F, CBArgs, Crypto, CBul, 1>>::repr_len()
    }

    fn step_native(
        // this method uses self, so that each FCircuit implementation (and different frontends)
        // can hold a state if needed to store data to compute the next state.
        &self,
        _i: usize,
        _z_i: Vec<F>,
        external_inputs: Vec<F>, // inputs that are not part of the state
    ) -> Result<Vec<F>, folding_schemes::Error> {
        let u = User::<F, U>::from_fold_repr(&external_inputs[0..User::<F, U>::repr_len()]);
        let priv_args = <PrivScanArgs<F, CBArgs, Crypto, CBul, 1>>::from_fold_repr(
            &external_inputs[User::<F, U>::repr_len()..],
        );
        let new_user = scan_method::<F, U, CBArgs, CBArgsVar, Crypto, CBul, H, 1>(
            &u,
            self.const_args.clone(),
            priv_args,
        );
        Ok(vec![new_user.commit::<H>()])
    }

    fn generate_step_constraints(
        // this method uses self, so that each FCircuit implementation (and different frontends)
        // can hold a state if needed to store data to generate the constraints.
        &self,
        cs: ark_relations::r1cs::ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<ark_r1cs_std::fields::fp::FpVar<F>>,
        external_inputs: Vec<ark_r1cs_std::fields::fp::FpVar<F>>, // inputs that are not part of the state
    ) -> Result<Vec<ark_r1cs_std::fields::fp::FpVar<F>>, ark_relations::r1cs::SynthesisError> {
        let u = User::<F, U>::from_fold_repr_zk(&external_inputs[0..User::<F, U>::repr_len()])?;
        User::commit_in_zk::<H>(u.clone())?.enforce_equal(&z_i[0])?;
        let priv_args = <PrivScanArgs<F, CBArgs, Crypto, CBul, 1>>::from_fold_repr_zk(
            &external_inputs[User::<F, U>::repr_len()..],
        )?;
        let p = PubScanArgsVar::new_constant(cs.clone(), self.const_args.clone())?;
        let new_user =
            scan_apply_method_zk::<F, U, CBArgs, CBArgsVar, Crypto, CBul, H, 1>(&u, p, priv_args)?;
        Ok(vec![User::commit_in_zk::<H>(new_user)?])
    }
}
