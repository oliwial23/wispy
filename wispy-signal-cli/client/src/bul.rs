use ark_r1cs_std::prelude::Boolean;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_snark::SNARK;
use common::{zk::MsgUser, Args, ArgsVar, CStore, Cr, OStore, F};
use reqwest::{blocking::Client, Url};
use zk_callbacks::{
    generic::{
        bulletin::{PublicCallbackBul, PublicUserBul},
        object::{Com, ComVar, Nul, Time, TimeVar},
    },
    impls::centralized::crypto::{FakeSigPubkey, FakeSigPubkeyVar, NoSigOTP},
};

#[derive(Debug, Clone)]
pub struct BulNet {
    pub client: Client,
    pub api: Url,
}

impl BulNet {
    pub fn new(api: Url) -> Self {
        let c = Client::new();

        Self { client: c, api }
    }

    pub fn join_bul(&self, object: Com<F>) -> Result<(), String> {
        let url = self.api.join("api/user/join").map_err(|e| e.to_string())?;

        let mut bytes = Vec::new();
        object
            .serialize_with_mode(&mut bytes, Compress::No)
            .unwrap();

        let res = self
            .client
            .post(url)
            .header("Content-Type", "application/octet-stream")
            .body(bytes)
            .send()
            .map_err(|e| e.to_string())?;

        if res.status().is_success() {
            Ok(())
        } else {
            Err(format!("Join failed with status {}", res.status()))
        }
    }

    pub fn post(
        &self,
        endpoint: &str,
        payload: Vec<u8>,
    ) -> Result<reqwest::blocking::Response, reqwest::Error> {
        let url = self.api.join(endpoint).expect("Invalid endpoint");
        self.client.post(url).body(payload).send()
    }
}

impl PublicUserBul<F, MsgUser> for BulNet {
    type MembershipWitness = <OStore as PublicUserBul<F, MsgUser>>::MembershipWitness;

    type MembershipWitnessVar = <OStore as PublicUserBul<F, MsgUser>>::MembershipWitnessVar;

    type MembershipPub = <OStore as PublicUserBul<F, MsgUser>>::MembershipPub;

    type MembershipPubVar = <OStore as PublicUserBul<F, MsgUser>>::MembershipPubVar;

    fn verify_in<PubArgs, Snark: SNARK<F>, const NUMCBS: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        _args: PubArgs,
        _proof: Snark::Proof,
        _memb_data: Self::MembershipPub,
        _verif_key: &Snark::VerifyingKey,
    ) -> bool {
        let bul = self
            .client
            .get(self.api.join("user/bulletin").unwrap())
            .send()
            .unwrap()
            .bytes()
            .unwrap();

        let db =
            <Vec<(Com<F>, Nul<F>, Vec<Com<F>>, Self::MembershipWitness)>>::deserialize_with_mode(
                &*bul,
                Compress::No,
                Validate::Yes,
            )
            .unwrap();

        for (c, n, l, _) in db.iter() {
            if *c == object && *n == old_nul && *l == cb_com_list {
                return true;
            }
        }
        false
    }

    fn get_membership_data(
        &self,
        object: Com<F>,
    ) -> Option<(Self::MembershipPub, Self::MembershipWitness)> {
        let ckey = self
            .client
            .get(self.api.join("api/user/pubkey").unwrap())
            .send()
            .unwrap()
            .bytes()
            .unwrap();

        let key =
            Self::MembershipPub::deserialize_with_mode(&*ckey, Compress::No, Validate::No).unwrap();

        let bul = self
            .client
            .get(self.api.join("api/user/bulletin").unwrap())
            .send()
            .unwrap()
            .bytes()
            .unwrap();

        let db =
            <Vec<(Com<F>, Nul<F>, Vec<Com<F>>, Self::MembershipWitness)>>::deserialize_with_mode(
                &*bul,
                Compress::No,
                Validate::Yes,
            )
            .unwrap();

        for (c, _, _, s) in db.iter() {
            if *c == object {
                return Some((key, s.clone()));
            }
        }
        None
    }

    fn enforce_membership_of(
        data_var: ComVar<F>,
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        <OStore as PublicUserBul<F, MsgUser>>::enforce_membership_of(
            data_var,
            extra_witness,
            extra_pub,
        )
    }
}

impl PublicCallbackBul<F, Args, Cr> for BulNet {
    type MembershipWitness = <CStore as PublicCallbackBul<F, F, NoSigOTP<F>>>::MembershipWitness;

    type MembershipWitnessVar = <CStore as PublicCallbackBul<F, Args, Cr>>::MembershipWitnessVar;

    type NonMembershipWitness = <CStore as PublicCallbackBul<F, Args, Cr>>::NonMembershipWitness;

    type NonMembershipWitnessVar =
        <CStore as PublicCallbackBul<F, Args, Cr>>::NonMembershipWitnessVar;

    type MembershipPub = <CStore as PublicCallbackBul<F, Args, Cr>>::MembershipPub;

    type MembershipPubVar = <CStore as PublicCallbackBul<F, Args, Cr>>::MembershipPubVar;

    type NonMembershipPub = <CStore as PublicCallbackBul<F, Args, Cr>>::NonMembershipPub;

    type NonMembershipPubVar = <CStore as PublicCallbackBul<F, Args, Cr>>::NonMembershipPubVar;

    fn verify_in(&self, tik: FakeSigPubkey<F>) -> Option<(Args, Time<F>)> {
        let bul = self
            .client
            .get(self.api.join("api/callbacks/bulletin").unwrap())
            .send()
            .unwrap()
            .bytes()
            .unwrap();

        let db = <Vec<(FakeSigPubkey<F>, Args, Time<F>, Self::MembershipWitness)>>::deserialize_with_mode(
            &*bul,
            Compress::No,
            Validate::Yes,
        )
        .unwrap();

        for (t, arg, time, _) in db.iter() {
            if *t == tik {
                return Some((*arg, *time));
            }
        }

        None
    }

    fn verify_not_in(&self, tik: FakeSigPubkey<F>) -> bool {
        let bul = self
            .client
            .get(self.api.join("api/callbacks/bulletin").unwrap())
            .send()
            .unwrap()
            .bytes()
            .unwrap();

        let db = <Vec<(FakeSigPubkey<F>, Args, Time<F>, Self::MembershipWitness)>>::deserialize_with_mode(
            &*bul,
            Compress::No,
            Validate::Yes,
        )
        .unwrap();

        for (t, _, _, _) in db.iter() {
            if *t == tik {
                return false;
            }
        }

        true
    }

    fn get_membership_data(
        &self,
        tik: FakeSigPubkey<F>,
    ) -> (
        Self::MembershipPub,
        Self::MembershipWitness,
        Self::NonMembershipPub,
        Self::NonMembershipWitness,
    ) {
        let mckey = self
            .client
            .get(self.api.join("api/callbacks/membership_pubkey").unwrap())
            .send()
            .unwrap()
            .bytes()
            .unwrap();

        let mkey = Self::MembershipPub::deserialize_with_mode(&*mckey, Compress::No, Validate::Yes)
            .unwrap();

        let nckey = self
            .client
            .get(self.api.join("api/callbacks/nonmembership_pubkey").unwrap())
            .send()
            .unwrap()
            .bytes()
            .unwrap();

        let nkey = Self::MembershipPub::deserialize_with_mode(&*nckey, Compress::No, Validate::Yes)
            .unwrap();

        let bul = self
            .client
            .get(self.api.join("api/callbacks/bulletin").unwrap())
            .send()
            .unwrap()
            .bytes()
            .unwrap();

        let db =
            <Vec<(FakeSigPubkey<F>, Args, Time<F>, Self::MembershipWitness)>>::deserialize_with_mode(
                &*bul,
                Compress::No,
                Validate::Yes,
            )
            .unwrap();

        for (t, _, _, s) in db.iter() {
            if *t == tik {
                return (mkey, s.clone(), nkey, Self::NonMembershipWitness::default());
            }
        }

        let nbul = self
            .client
            .get(self.api.join("api/callbacks/nmemb_bulletin").unwrap())
            .send()
            .unwrap()
            .bytes()
            .unwrap();

        let db = <Vec<Self::NonMembershipWitness>>::deserialize_with_mode(
            &*nbul,
            Compress::No,
            Validate::Yes,
        )
        .unwrap();

        for r in db.iter() {
            if r.is_in_range(tik.to()) {
                return (mkey, Self::MembershipWitness::default(), nkey, r.clone());
            }
        }

        panic!("Should never reach here.");
    }

    fn enforce_membership_of(
        tikvar: (FakeSigPubkeyVar<F>, ArgsVar, TimeVar<F>),
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        <CStore as PublicCallbackBul<F, Args, Cr>>::enforce_membership_of(
            tikvar,
            extra_witness,
            extra_pub,
        )
    }

    fn enforce_nonmembership_of(
        tikvar: FakeSigPubkeyVar<F>,
        extra_witness: Self::NonMembershipWitnessVar,
        extra_pub: Self::NonMembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        <CStore as PublicCallbackBul<F, Args, Cr>>::enforce_nonmembership_of(
            tikvar,
            extra_witness,
            extra_pub,
        )
    }
}
