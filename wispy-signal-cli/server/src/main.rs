mod helpers;
mod server;

use anyhow::Result;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use axum::{
    routing::{get, post},
    Router,
};
use common::{
    zk::{
        get_extra_pubdata_for_scan, get_scan_interaction, get_standard_interaction, BadgesArgs,
        BadgesArgsVar,
    },
    Cr, OStore, Snark, Store, F, H, PK, VK,
};

use ark_groth16::Groth16;
use common::zk::pseudonym_pred;
use common::zk::MsgUser;
use common::zk::PseudonymArgs;
use common::zk::PseudonymArgsVar;
use common::E;
use server::{
    forward_authorship, forward_badges, forward_ban_poll, forward_callback, forward_context_ts,
    forward_jsonrpc, forward_jsonrpc_pseudo, forward_poll, forward_reaction, forward_reply,
    forward_reply_pseudo, forward_vote, forward_vote_count, handle_get_arbitrary_pred_proving_key,
    handle_get_arbitrary_pred_proving_key2, handle_get_arbitrary_pred_proving_key3,
    handle_get_callback_bulletin, handle_get_callback_nmemb_bulletin, handle_get_membership_pubkey,
    handle_get_nonmembership_pubkey, handle_get_posts_scan, handle_get_posts_standard,
    handle_get_scan_proving_key, handle_get_standard_proving_key, handle_get_user_bulletin,
    handle_get_user_pubkey, handle_send_ban_request, handle_send_rep_request, handle_user_join,
    handle_verify_arb_pred, pseudonym,
};
use std::{fs::File, net::SocketAddr, sync::Arc};
use tokio::{signal, sync::RwLock};
use tracing::{info, info_span};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use zk_callbacks::generic::interaction::generate_keys_for_statement_in;
use zk_callbacks::impls::centralized::ds::sigstore::GRSchnorrObjStore;
use zk_callbacks::impls::hash::Poseidon;

#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct ServerKeys {
    pub standard_proving_key: PK,
    pub standard_verifying_key: VK,
    pub scan_proving_key: PK,
    pub scan_verifying_key: VK,
    pub pseudonym_pred_proving_key: PK,
    pub pseudonym_pred_verifying_key: VK,
    pub authorship_pred_proving_key: PK,
    pub authorship_pred_verifying_key: VK,
    pub badge_pred_proving_key: PK,
    pub badge_pred_verifying_key: VK,
}

use common::zk::PseudonymArgsPair;
use common::zk::PseudonymArgsPairVar;
use common::zk::{authorship_pred, badge_pred};

pub struct ServerState {
    pub db: Store,
    pub keys: ServerKeys,
}

#[tokio::main]
async fn main() -> Result<()> {
    // let keyfile_path = std::env::var("SERVER_KEYFILE").unwrap_or("./keyfile.bin".to_string());
    let keyfile_path = std::env::var("SERVER_KEYFILE").unwrap_or("server/keyfile.bin".to_string());
    let log_level = std::env::var("SERVER_LOG").unwrap_or("info".to_string());

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::new(format!("server={}", log_level)))
        .init();

    let mut rng = rand::thread_rng();

    // Database Creation
    let span = info_span!("db_generation").entered();
    info!("Creating database...");
    let db = Store::new(&mut rng);
    info!("Created!");
    span.exit();

    // Snark Key Generation
    let span = info_span!("snark_key_generation").entered();

    // Standard interaction keys
    let standard_interaction = get_standard_interaction();
    let (standard_proving_key, standard_verifying_key) = standard_interaction
        .generate_keys::<H, Snark, Cr, OStore>(
            &mut rng,
            Some(db.obj_bul.get_pubkey()),
            None,
            false,
        );

    // Scan interaction keys
    let scan_interaction = get_scan_interaction();
    let (scan_proving_key, scan_verifying_key) = scan_interaction
        .generate_keys::<H, Snark, Cr, OStore>(
            &mut rng,
            Some(db.obj_bul.get_pubkey()),
            Some(get_extra_pubdata_for_scan(
                &db.callback_bul,
                db.callback_bul.get_pubkey(),
                db.callback_bul.nmemb_bul.get_pubkey(),
                F::from(0),
            )),
            true,
        );

    let context = F::from(1234);
    let claimed = F::from(5678);

    let pseudo = PseudonymArgs { context, claimed };

    let (pseudonym_pred_proving_key, pseudonym_pred_verifying_key) = generate_keys_for_statement_in::<
        F,
        Poseidon<2>,
        MsgUser,
        PseudonymArgs<F>,
        PseudonymArgsVar<F>,
        (),
        (),
        Groth16<E>,
        GRSchnorrObjStore,
    >(
        &mut rng,
        pseudonym_pred,
        Some(db.obj_bul.get_pubkey()),
        Some(pseudo.clone()),
    );

    let context2 = F::from(9012);
    let claimed2 = F::from(3456);

    let pseudo2 = PseudonymArgs {
        context: context2,
        claimed: claimed2,
    };

    let pair = PseudonymArgsPair {
        a: pseudo,
        b: pseudo2,
    };

    let (authorship_pred_proving_key, authorship_pred_verifying_key) =
        generate_keys_for_statement_in::<
            F,
            Poseidon<2>,
            MsgUser,
            PseudonymArgsPair<F>,
            PseudonymArgsPairVar<F>,
            (),
            (),
            Groth16<E>,
            GRSchnorrObjStore,
        >(
            &mut rng,
            authorship_pred,
            Some(db.obj_bul.get_pubkey()),
            Some(pair),
        );

    let badge_var = BadgesArgs {
        i: F::from(1),
        claimed: F::from(0),
    };

    let (badge_pred_proving_key, badge_pred_verifying_key) = generate_keys_for_statement_in::<
        F,
        Poseidon<2>,
        MsgUser,
        BadgesArgs<F>,
        BadgesArgsVar<F>,
        (),
        (),
        Groth16<E>,
        GRSchnorrObjStore,
    >(
        &mut rng,
        badge_pred,
        Some(db.obj_bul.get_pubkey()),
        Some(badge_var),
    );

    let keys = ServerKeys {
        standard_proving_key,
        standard_verifying_key,
        scan_proving_key,
        scan_verifying_key,
        pseudonym_pred_proving_key,
        pseudonym_pred_verifying_key,
        authorship_pred_proving_key,
        authorship_pred_verifying_key,
        badge_pred_proving_key,
        badge_pred_verifying_key,
    };

    info!("Writing keys to file...");
    {
        let mut keyfile = File::create(&keyfile_path)?; // <- create new file
        keys.serialize_with_mode(&mut keyfile, Compress::No)?;
    }
    let keyfile = File::open(&keyfile_path)?;
    let keys = ServerKeys::deserialize_with_mode(keyfile, Compress::No, Validate::No)?;

    info!("Completed!");
    span.exit();

    // Application Start
    let state = Arc::new(RwLock::new(ServerState { db, keys }));

    let span = info_span!("start_application").entered();
    info!("Starting application...");

    let app = Router::new()
        .route(
            "/api/interaction/standard/proving_key",
            get(handle_get_standard_proving_key),
        )
        .route(
            "/api/interaction/scan/proving_key",
            get(handle_get_scan_proving_key),
        )
        .route(
            "/api/user/arbitrary_pred_proving_key",
            get(handle_get_arbitrary_pred_proving_key),
        )
        .route(
            "/api/user/arbitrary_pred_proving_key2",
            get(handle_get_arbitrary_pred_proving_key2),
        )
        .route(
            "/api/user/arbitrary_pred_proving_key3",
            get(handle_get_arbitrary_pred_proving_key3),
        )
        .route("/api/user/pubkey", get(handle_get_user_pubkey))
        .route("/api/user/bulletin", get(handle_get_user_bulletin))
        .route(
            "/api/callbacks/membership_pubkey",
            get(handle_get_membership_pubkey),
        )
        .route(
            "/api/callbacks/nonmembership_pubkey",
            get(handle_get_nonmembership_pubkey),
        )
        .route("/api/callbacks/bulletin", get(handle_get_callback_bulletin))
        .route(
            "/api/callbacks/nmemb_bulletin",
            get(handle_get_callback_nmemb_bulletin),
        )
        .route("/api/user/join", post(handle_user_join))
        .route("/api/interact/standard", post(handle_get_posts_standard))
        .route("/api/interact/scan", post(handle_get_posts_scan))
        .route("/api/interact/arbitrary_pred", post(handle_verify_arb_pred))
        // .route("/api/interact/pseudo", post(handle_verify_pseudo))
        .route("/api/jsonrpc", post(forward_jsonrpc))
        .route("/api/jsonrpc/pseudo", post(forward_jsonrpc_pseudo))
        .route("/api/ban", post(handle_send_ban_request))
        .route("/api/pseudonym", get(pseudonym))
        .route("/api/reputation", post(handle_send_rep_request))
        .route("/api/react", post(forward_reaction))
        .route("/api/reply", post(forward_reply))
        .route("/api/reply/pseudo", post(forward_reply_pseudo))
        .route("/api/poll", post(forward_poll))
        .route("/api/banpoll", post(forward_ban_poll))
        .route("/api/vote", post(forward_vote))
        .route("/api/votecount", post(forward_vote_count))
        .route("/api/authorship", post(forward_authorship))
        .route("/api/context", post(forward_context_ts))
        .route("/api/badges", post(forward_badges))
        .route("/api/cb", post(forward_callback))
        .with_state(state);

    span.exit();

    let span = info_span!("web_server").entered();
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            signal::ctrl_c()
                .await
                .expect("failed to listen for shutdown signal");
            println!("Shutting down server...");

            // Cleanup zkpair_log.jsonl
            if let Err(e) = std::fs::remove_file("server/zkpair_log.jsonl") {
                eprintln!("Failed to delete zkpair_log.jsonl: {}", e);
            }
            if let Err(e) = std::fs::remove_file("server/poll_log.jsonl") {
                eprintln!("Failed to delete poll_log.jsonl: {}", e);
            }

            // Cleanup SNARK key file
            let keyfile_path =
                std::env::var("SERVER_KEYFILE").unwrap_or("server/keyfile.bin".to_string());
            if let Err(e) = std::fs::remove_file(&keyfile_path) {
                eprintln!("Failed to delete keyfile {}: {}", keyfile_path, e);
            }
        })
        .await
        .unwrap();

    span.exit();

    Ok(())
}
