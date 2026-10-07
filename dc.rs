// Cargo.toml:
//   tonic = { version = "0.10", features = ["tls", "tls-roots"] }
//   prost = "0.12"
//   prost-types = "0.12"
//   tokio = { version = "1", features = ["rt-multi-thread", "macros", "time"] }
//   solana-sdk = "=1.17.28"
//   solana-client = "=1.17.28"
//   bincode = "1.3"
//   clap = { version = "4", features = ["derive"] }
//   thiserror = "1"
// build.rs: tonic_build::configure().compile(&["protos/auth.proto","protos/searcher.proto","protos/bundle.proto","protos/packet.proto","protos/shared.proto"], &["protos"])
// protos/ is a checkout of jito-labs/mev-protos

use std::{collections::HashMap, error::Error, path::PathBuf, str::FromStr, sync::{Arc, RwLock}, time::{Duration, Instant}};

use clap::Parser;
use solana_client::{client_error::ClientError, nonblocking::rpc_client::RpcClient};
use solana_sdk::{pubkey::{ParsePubkeyError, Pubkey}, signature::{read_keypair_file, Keypair, Signer}, system_instruction, transaction::{Transaction, VersionedTransaction}};
use tonic::{service::Interceptor, transport::{Channel, ClientTlsConfig, Endpoint}, Request, Status};

mod jito {
    pub mod auth { tonic::include_proto!("auth"); }
    pub mod bundle { tonic::include_proto!("bundle"); }
    pub mod packet { tonic::include_proto!("packet"); }
    pub mod searcher { tonic::include_proto!("searcher"); }
    pub mod shared { tonic::include_proto!("shared"); }
}
use jito::auth::{auth_service_client::AuthServiceClient, GenerateAuthChallengeRequest, GenerateAuthTokensRequest, Role};
use jito::bundle::{bundle_result, Bundle, DroppedReason};
use jito::packet::{Meta, Packet};
use jito::searcher::{searcher_service_client::SearcherServiceClient, GetTipAccountsRequest, SendBundleRequest, SubscribeBundleResultsRequest};

#[derive(Debug, thiserror::Error)]
enum E {
    #[error("read keypair {path:?}")]
    Keypair { path: PathBuf, source: Box<dyn Error> },
    #[error("connect to block engine {url}")]
    Connect { url: String, source: tonic::transport::Error },
    #[error("{op} failed")]
    Grpc { op: &'static str, source: Status },
    #[error("block engine response is missing {0}")]
    Missing(&'static str),
    #[error("tip account {0:?} from block engine does not parse")]
    TipAccount(String, #[source] ParsePubkeyError),
    #[error("rpc")]
    Rpc(#[from] ClientError),
    #[error("serialize tx")]
    Serialize(#[from] bincode::Error),
}

trait GrpcCtx<T> { fn op(self, op: &'static str) -> Result<T, E>; }
impl<T> GrpcCtx<T> for Result<T, Status> {
    fn op(self, op: &'static str) -> Result<T, E> { self.map_err(|source| E::Grpc { op, source }) }
}

#[derive(Parser)]
struct Args {
    #[arg(long)]
    block_engine_url: String,
    #[arg(long)]
    rpc_url: String,
    #[arg(long)]
    keypair_path: PathBuf,
    #[arg(long, default_value_t = 200_000)]
    tip_lamports: u64,
    #[arg(long, default_value_t = 5)]
    num_bundles: usize,
    #[arg(long, default_value_t = 12)]
    wait_secs: u64,
}

#[derive(Clone)]
struct ClientInterceptor { bearer_token: Arc<RwLock<String>> }

impl Interceptor for ClientInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let token = self.bearer_token.read().unwrap();
        let value = format!("Bearer {}", *token).parse().map_err(|_| Status::internal("token is not a valid header value"))?;
        request.metadata_mut().insert("authorization", value);
        Ok(request)
    }
}

async fn create_grpc_channel(url: &str) -> Result<Channel, E> {
    let mut endpoint = Endpoint::from_shared(url.to_string()).map_err(|source| E::Connect { url: url.into(), source })?;
    if url.starts_with("https") {
        endpoint = endpoint.tls_config(ClientTlsConfig::new()).map_err(|source| E::Connect { url: url.into(), source })?;
    }
    endpoint.connect().await.map_err(|source| E::Connect { url: url.into(), source })
}

async fn authenticate(channel: Channel, keypair: &Keypair) -> Result<String, E> {
    let mut auth = AuthServiceClient::new(channel);
    let challenge_resp = auth.generate_auth_challenge(GenerateAuthChallengeRequest {
        role: Role::Searcher as i32,
        pubkey: keypair.pubkey().as_ref().to_vec(),
    }).await.op("generate_auth_challenge")?.into_inner();

    let challenge = format!("{}-{}", keypair.pubkey(), challenge_resp.challenge);
    let signed_challenge = keypair.sign_message(challenge.as_bytes()).as_ref().to_vec();
    let tokens = auth.generate_auth_tokens(GenerateAuthTokensRequest {
        challenge,
        client_pubkey: keypair.pubkey().as_ref().to_vec(),
        signed_challenge,
    }).await.op("generate_auth_tokens")?.into_inner();

    Ok(tokens.access_token.ok_or(E::Missing("access_token"))?.value)
}

fn proto_packet_from_versioned_tx(tx: &VersionedTransaction) -> Result<Packet, E> {
    let data = bincode::serialize(tx)?;
    let size = data.len() as u64;
    Ok(Packet { data, meta: Some(Meta { size, addr: String::new(), port: 0, flags: None, sender_stake: 0 }) })
}

async fn run(args: Args) -> Result<(), E> {
    let payer_keypair = read_keypair_file(&args.keypair_path).map_err(|source| E::Keypair { path: args.keypair_path.clone(), source })?;
    let channel = create_grpc_channel(&args.block_engine_url).await?;
    let bearer_token = Arc::new(RwLock::new(authenticate(channel.clone(), &payer_keypair).await?));
    let mut client = SearcherServiceClient::with_interceptor(channel, ClientInterceptor { bearer_token });

    let tip_accounts = client.get_tip_accounts(GetTipAccountsRequest {}).await.op("get_tip_accounts")?.into_inner().accounts;
    let tip_accounts = tip_accounts.into_iter()
        .map(|s| Pubkey::from_str(&s).map_err(|e| E::TipAccount(s, e)))
        .collect::<Result<Vec<_>, _>>()?;
    if tip_accounts.is_empty() { return Err(E::Missing("tip accounts")); }

    let mut bundle_results_subscription = client.subscribe_bundle_results(SubscribeBundleResultsRequest {}).await.op("subscribe_bundle_results")?.into_inner();

    let rpc_client = RpcClient::new(args.rpc_url.clone());

    let mut outcomes: HashMap<String, Option<&'static str>> = HashMap::new();
    for i in 0..args.num_bundles {
        let tip_account = &tip_accounts[i % tip_accounts.len()];
        let blockhash = rpc_client.get_latest_blockhash().await?;
        let tx = VersionedTransaction::from(Transaction::new_signed_with_payer(
            &[system_instruction::transfer(&payer_keypair.pubkey(), tip_account, args.tip_lamports)],
            Some(&payer_keypair.pubkey()),
            &[&payer_keypair],
            blockhash,
        ));
        let bundle = Bundle { header: None, packets: vec![proto_packet_from_versioned_tx(&tx)?] };
        let uuid = client.send_bundle(SendBundleRequest { bundle: Some(bundle) }).await.op("send_bundle")?.into_inner().uuid;
        println!("sent bundle {i} uuid={uuid} tip={} -> {tip_account}", args.tip_lamports);
        outcomes.insert(uuid, None);
    }

    let deadline = Instant::now() + Duration::from_secs(args.wait_secs);
    while outcomes.values().any(|s| !matches!(s, Some("finalized") | Some("dropped") | Some("rejected"))) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() { break; }
        let msg = match tokio::time::timeout(remaining, bundle_results_subscription.message()).await {
            Err(_) => break,
            Ok(m) => m.op("bundle result stream")?,
        };
        let Some(res) = msg else { break };
        let Some(entry) = outcomes.get_mut(&res.bundle_id) else { continue };
        let state = match res.result {
            Some(bundle_result::Result::Accepted(a)) => { println!("{} accepted slot={} by {}", res.bundle_id, a.slot, a.validator_identity); "accepted" }
            Some(bundle_result::Result::Processed(p)) => { println!("{} processed slot={} idx={}", res.bundle_id, p.slot, p.bundle_index); "processed" }
            Some(bundle_result::Result::Finalized(_)) => { println!("{} finalized", res.bundle_id); "finalized" }
            Some(bundle_result::Result::Dropped(d)) => {
                println!("{} dropped: {}", res.bundle_id, DroppedReason::try_from(d.reason).map(|r| r.as_str_name()).unwrap_or("?"));
                "dropped"
            }
            Some(bundle_result::Result::Rejected(r)) => { println!("{} rejected: {:?}", res.bundle_id, r.reason); "rejected" }
            None => continue,
        };
        *entry = Some(state);
    }

    let landed = outcomes.values().filter(|s| matches!(s, Some("processed") | Some("finalized"))).count();
    let unknown = outcomes.values().filter(|s| s.is_none() || matches!(s, Some("accepted"))).count();
    println!("sent={} landed={} no-result={} land rate {:.1}%", outcomes.len(), landed, unknown, 100.0 * landed as f64 / outcomes.len() as f64);
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run(Args::parse()).await {
        eprint!("error: {e}");
        let mut cause = e.source();
        while let Some(c) = cause { eprint!(": {c}"); cause = c.source(); }
        eprintln!();
        std::process::exit(1);
    }
}
