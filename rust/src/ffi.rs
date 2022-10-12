use crate::bitcoind_client::BitcoindClient;
use crate::file_io::FilesystemLogger;
use crate::types::{
    ChainMonitor, ChannelManager, HTLCStatus, InvoicePayer, MillisatAmount, NetworkGraph,
    PaymentInfo, PaymentInfoStorage, PeerManager,
};
use crate::utils::config_network;
use crate::{file_io, utils};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode;
use bitcoin::network::constants::Network;
use bitcoin::BlockHash;
use bitcoin_bech32::WitnessProgram;
use lazy_static::__Deref;
use lazy_static::lazy_static;
use lightning::chain;
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning::chain::channelmonitor::ChannelMonitor;
use lightning::chain::keysinterface::{InMemorySigner, KeysInterface, KeysManager, Recipient};
use lightning::chain::BestBlock;
use lightning::chain::{chainmonitor, Watch};
use lightning::ln::channelmanager;
use lightning::ln::channelmanager::{ChainParameters, ChannelManagerReadArgs};
use lightning::ln::peer_handler::{IgnoringMessageHandler, MessageHandler};
use lightning::routing::gossip::{NodeId, P2PGossipSync};
use lightning::util::config::UserConfig;
use lightning::util::events::{Event, PaymentPurpose};
use lightning::util::ser::ReadableArgs;
use lightning_background_processor::{BackgroundProcessor, GossipSync};
use lightning_block_sync::{init, poll, SpvClient, UnboundedCache};
use lightning_invoice::payment;
use lightning_invoice::utils::DefaultRouter;
use lightning_persister::FilesystemPersister;
use rand::{thread_rng, Rng, RngCore};
use secp256k1::{PublicKey, Secp256k1};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Write;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, SystemTime};

lazy_static! {
    static ref BITCOIND_CLIENT: RwLock<Option<Arc<BitcoindClient>>> = RwLock::new(None);
    static ref KEYS_MANAGER: RwLock<Arc<KeysManager>> =
        RwLock::new(Arc::new(KeysManager::new(&[0; 32], 0, 0)));
    static ref PATH: RwLock<String> = RwLock::new(String::new());
    static ref CHANNEL_MANAGER: RwLock<Option<Arc<ChannelManager>>> = RwLock::new(None);
}
fn check_if_restarting(ldk_data_dir: String) -> bool {
    if let Ok(mut f) = fs::File::open(format!("{}/manager", ldk_data_dir.clone())) {
        return true;
    } else {
        false
    }
}
//
// fn init_static_variables(invoice_payer: Arc<InvoicePayer<E>>, peer_manager: Arc<PeerManager>, channel_manager: Arc<ChannelManager>, network_graph: Arc<NetworkGraph>, inbound_payments: PaymentInfoStorage, outbound_payments: PaymentInfoStorage, network: Network,){
//
// }

fn create_keys_manager(ldk_data_dir: String) {
    let keys_seed_path = format!("{}/keys_seed", ldk_data_dir);
    let keys_seed = if let Ok(seed) = fs::read(keys_seed_path.clone()) {
        assert_eq!(seed.len(), 32);
        let mut key = [0; 32];
        key.copy_from_slice(&seed);
        key
    } else {
        let mut key = [0; 32];
        thread_rng().fill_bytes(&mut key);
        match File::create(keys_seed_path.clone()) {
            Ok(mut f) => {
                f.write_all(&key)
                    .expect("Failed to write node keys seed to disk");
                f.sync_all().expect("Failed to sync node keys seed to disk");
            }
            Err(e) => {
                println!(
                    "ERROR: Unable to create keys seed file {}: {}",
                    keys_seed_path, e
                );
            }
        }
        key
    };
    let cur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let keys_manager = KeysManager::new(&keys_seed, cur.as_secs(), cur.subsec_nanos());
    let mut keysmanager = KEYS_MANAGER.write().unwrap();
    *keysmanager = Arc::new(keys_manager);
}
pub async fn init_bitcoin_client(host: String, port: u16, username: String, password: String) {
    let bitcoind_client = BitcoindClient::new(
        host.clone(),
        port,
        username.clone(),
        password.clone(),
        tokio::runtime::Handle::current(),
    )
    .await
    .unwrap();
    let client = Arc::new(bitcoind_client);
    let mut bclient = BITCOIND_CLIENT.write().unwrap();
    *bclient = Some(client.clone());
}

pub fn init_directory(path: String) {
    let ldk_data_dir = format!("{}/.ldk", path);
    fs::create_dir_all(ldk_data_dir.clone()).unwrap();
    let mut path = PATH.write().unwrap();
    *path = ldk_data_dir;
}

async fn init_channel_manager(
    node_network: Network,
    persister: Arc<FilesystemPersister>,
    chain_monitor: Arc<ChainMonitor>,
    keys_manager: Arc<KeysManager>,
    logger: Arc<FilesystemLogger>,
    ldk_data_dir: String,
) -> (
    ChannelManager,
    Vec<(BlockHash, ChannelMonitor<InMemorySigner>)>,
    BlockHash,
) {
    let bitcoind_client = BITCOIND_CLIENT.read().unwrap().clone().unwrap();
    let mut user_config = UserConfig::default();
    // Step 7: Read ChannelMonitor state from disk
    let mut channelmonitors: Vec<(BlockHash, ChannelMonitor<InMemorySigner>)> = persister
        .read_channelmonitors(keys_manager.clone())
        .unwrap();
    user_config
        .channel_handshake_limits
        .force_announced_channel_preference = false;
    let (channel_manager_blockhash, channel_manager) = {
        if let Ok(mut f) = fs::File::open(format!("{}/manager", ldk_data_dir.clone())) {
            let mut channel_monitor_mut_references = Vec::new();
            for (_, channel_monitor) in channelmonitors.iter_mut() {
                channel_monitor_mut_references.push(channel_monitor);
            }
            let read_args = ChannelManagerReadArgs::new(
                keys_manager.clone(),
                bitcoind_client.clone(),
                chain_monitor.clone(),
                bitcoind_client.clone(),
                logger.clone(),
                user_config,
                channel_monitor_mut_references,
            );

            <(BlockHash, ChannelManager)>::read(&mut f, read_args).unwrap()
        } else {
            // We're starting a fresh node.
            let getinfo_resp = bitcoind_client.get_blockchain_info().await;

            let chain_params = ChainParameters {
                network: node_network,
                best_block: BestBlock::new(
                    getinfo_resp.latest_blockhash,
                    getinfo_resp.latest_height as u32,
                ),
            };
            let fresh_channel_manager = channelmanager::ChannelManager::new(
                bitcoind_client.clone(),
                chain_monitor.clone(),
                bitcoind_client.clone(),
                logger.clone(),
                keys_manager.clone(),
                user_config,
                chain_params,
            );

            (getinfo_resp.latest_blockhash, fresh_channel_manager)
        }
    };

    (channel_manager, channelmonitors, channel_manager_blockhash)
}

pub async fn ldk_init(
    host: String,
    port: u16,
    username: String,
    password: String,
    network: String,
    storage_path: String,
) -> String {
    // Initialize the LDK data directory if necessary.
    init_directory(storage_path);
    let ldk_data_dir = PATH.read().unwrap().clone();
    //Initialize our bitcoind client.
    let node_network = config_network(network);
    init_bitcoin_client(host, port, username, password).await;

    let bitcoind_client = BITCOIND_CLIENT.read().unwrap().clone().unwrap();
    let fee_estimator = bitcoind_client.clone();

    // Step 2: Initialize the Logger
    let logger = Arc::new(FilesystemLogger::new(ldk_data_dir.clone()));

    //  Step 3: Initialize the BroadcasterInterface
    //   BitcoindClient implements the BroadcasterInterface trait, so it'll act as our transaction
    //   broadcaster.
    let broadcaster = bitcoind_client.clone();
    // Step 4: Initialize Persist
    let persister = Arc::new(FilesystemPersister::new(ldk_data_dir.clone()));
    // // Step 5: Initialize the ChainMonitor
    let chain_monitor: Arc<ChainMonitor> = Arc::new(chainmonitor::ChainMonitor::new(
        None,
        broadcaster.clone().clone(),
        logger.clone(),
        fee_estimator.clone(),
        persister.clone(),
    ));

    // Step 6: Initialize the KeysManager
    create_keys_manager(ldk_data_dir.clone());
    let keys_manager = KEYS_MANAGER.read().unwrap().clone();

    // Step 8: Initialize the ChannelManager
    let (channel_manager, mut channelmonitors, channel_manager_blockhash) = init_channel_manager(
        node_network,
        persister.clone(),
        chain_monitor.clone(),
        keys_manager.clone(),
        logger.clone(),
        ldk_data_dir.clone(),
    )
    .await;

    // Step 9: Sync ChannelMonitors and ChannelManager to chain tip
    let mut chain_listener_channel_monitors = Vec::new();
    let mut cache = UnboundedCache::new();
    let mut chain_tip: Option<poll::ValidatedBlockHeader> = None;
    if check_if_restarting(ldk_data_dir.clone()) {
        let mut chain_listeners = vec![(
            channel_manager_blockhash,
            &channel_manager as &dyn chain::Listen,
        )];

        for (blockhash, channel_monitor) in channelmonitors.drain(..) {
            let outpoint = channel_monitor.get_funding_txo().0;
            chain_listener_channel_monitors.push((
                blockhash,
                (
                    channel_monitor,
                    broadcaster.clone(),
                    fee_estimator.clone(),
                    logger.clone(),
                ),
                outpoint,
            ));
        }

        for monitor_listener_info in chain_listener_channel_monitors.iter_mut() {
            chain_listeners.push((
                monitor_listener_info.0,
                &monitor_listener_info.1 as &dyn chain::Listen,
            ));
        }
        chain_tip = Some(
            init::synchronize_listeners(
                &mut bitcoind_client.deref(),
                node_network,
                &mut cache,
                chain_listeners,
            )
            .await
            .unwrap(),
        );
    }
    // Step 10: Give ChannelMonitors to ChainMonitor
    for item in chain_listener_channel_monitors.drain(..) {
        let channel_monitor = item.1 .0;
        let funding_outpoint = item.2;
        chain_monitor
            .watch_channel(funding_outpoint, channel_monitor)
            .unwrap();
    }

    // Step 11: Optional: Initialize the P2PGossipSync
    let genesis = genesis_block(node_network).header.block_hash();
    let network_graph_path = format!("{}/network_graph", ldk_data_dir.clone());
    let network_graph = Arc::new(file_io::read_network(
        Path::new(&network_graph_path),
        genesis,
        logger.clone(),
    ));
    let gossip_sync = Arc::new(P2PGossipSync::new(
        Arc::clone(&network_graph),
        None::<Arc<dyn chain::Access + Send + Sync>>,
        logger.clone(),
    ));
    // Step 12: Initialize the PeerManager
    let channel_manager = Arc::new(channel_manager);
    let mut ephemeral_bytes = [0; 32];
    rand::thread_rng().fill_bytes(&mut ephemeral_bytes);
    let lightning_msg_handler = MessageHandler {
        chan_handler: channel_manager.clone(),
        route_handler: gossip_sync.clone(),
    };
    let peer_manager: Arc<PeerManager> = Arc::new(PeerManager::new(
        lightning_msg_handler,
        keys_manager
            .clone()
            .get_node_secret(Recipient::Node)
            .unwrap(),
        &ephemeral_bytes,
        logger.clone(),
        Arc::new(IgnoringMessageHandler {}),
    ));

    // // Step 13: Initialize networking

    let stop_listen_connect = Arc::new(AtomicBool::new(false));
    let stop_listen = Arc::clone(&stop_listen_connect);
    let peer_mgr_clone = peer_manager.clone();
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
            .await
            .expect("Failed to bind to listen port - is something else already listening on it?");
        loop {
            let peer_mgr = peer_mgr_clone.clone();
            let tcp_stream = listener.accept().await.unwrap().0;
            if stop_listen.load(Ordering::Acquire) {
                return;
            }
            tokio::spawn(async move {
                lightning_net_tokio::setup_inbound(
                    peer_mgr.clone(),
                    tcp_stream.into_std().unwrap(),
                )
                .await;
            });
        }
    });

    // Step 14: Connect and Disconnect Blocks
    if chain_tip.is_none() {
        chain_tip = Some(
            init::validate_best_block_header(&mut bitcoind_client.deref())
                .await
                .unwrap(),
        );
    }
    let channel_manager_listener = channel_manager.clone();
    let chain_monitor_listener = chain_monitor.clone();
    let bitcoind_block_source = bitcoind_client.clone();
    let network = node_network.clone();
    tokio::spawn(async move {
        let mut derefed = bitcoind_block_source.deref();
        let chain_poller = poll::ChainPoller::new(&mut derefed, network);
        let chain_listener = (chain_monitor_listener, channel_manager_listener);
        let mut spv_client = SpvClient::new(
            chain_tip.unwrap(),
            chain_poller,
            &mut cache,
            &chain_listener,
        );
        loop {
            spv_client.poll_best_tip().await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    // Step 15: Handle LDK Events
    let channel_manager_event_listener = channel_manager.clone();
    let keys_manager_listener = keys_manager.clone();
    let inbound_payments: PaymentInfoStorage = Arc::new(Mutex::new(HashMap::new()));
    let outbound_payments: PaymentInfoStorage = Arc::new(Mutex::new(HashMap::new()));
    let inbound_pmts_for_events = inbound_payments.clone();
    let outbound_pmts_for_events = outbound_payments.clone();
    let bitcoind_rpc = bitcoind_client.clone();
    let network_graph_events = network_graph.clone();
    let handle = tokio::runtime::Handle::current();
    let event_handler = move |event: &Event| {
        handle.block_on(handle_ldk_events(
            &channel_manager_event_listener,
            &bitcoind_rpc,
            &network_graph_events,
            &keys_manager_listener,
            &inbound_pmts_for_events,
            &outbound_pmts_for_events,
            node_network.clone(),
            event,
        ));
    };

    // Step 16: Initialize routing ProbabilisticScorer
    let scorer_path = format!("{}/scorer", ldk_data_dir.clone());
    let scorer = Arc::new(Mutex::new(file_io::read_scorer(
        Path::new(&scorer_path),
        Arc::clone(&network_graph),
        Arc::clone(&logger),
    )));

    // Step 17: Create InvoicePayer
    let router = DefaultRouter::new(
        network_graph.clone(),
        logger.clone(),
        keys_manager.get_secure_random_bytes(),
    );
    let invoice_payer = Arc::new(InvoicePayer::new(
        channel_manager.clone(),
        router,
        scorer.clone(),
        logger.clone(),
        event_handler,
        payment::Retry::Timeout(Duration::from_secs(10)),
    ));
    //
    // Step 19: Background Processing
    let background_processor = BackgroundProcessor::start(
        persister.clone(),
        invoice_payer.clone(),
        chain_monitor.clone(),
        channel_manager.clone(),
        GossipSync::p2p(gossip_sync.clone()),
        peer_manager.clone(),
        logger.clone(),
        Some(scorer.clone()),
    );
    // Regularly reconnect to channel peers.
    let connect_cm = Arc::clone(&channel_manager);
    let connect_pm = Arc::clone(&peer_manager);
    let peer_data_path = format!("{}/channel_peer_data", ldk_data_dir.clone());
    let stop_connect = Arc::clone(&stop_listen_connect);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            match file_io::read_channel_peer_data(Path::new(&peer_data_path)) {
                Ok(info) => {
                    let peers = connect_pm.get_peer_node_ids();
                    for node_id in connect_cm
                        .list_channels()
                        .iter()
                        .map(|chan| chan.counterparty.node_id)
                        .filter(|id| !peers.contains(id))
                    {
                        if stop_connect.load(Ordering::Acquire) {
                            return;
                        }
                        for (pubkey, peer_addr) in info.iter() {
                            if *pubkey == node_id {
                                let _ = do_connect_peer(
                                    *pubkey,
                                    peer_addr.clone(),
                                    Arc::clone(&connect_pm),
                                )
                                .await;
                            }
                        }
                    }
                }
                Err(e) => println!("ERROR: error reading channel peer info from disk: {:?}", e),
            }
        }
    });

    let mut c_manager = CHANNEL_MANAGER.write().unwrap();
    *c_manager = Some(channel_manager.clone());
    channel_manager.clone().get_our_node_id().to_string()
}
pub fn get_node_id()->String{
    let c_manager = CHANNEL_MANAGER.read().unwrap().clone().unwrap();
    c_manager.get_our_node_id().to_string()
}
async fn handle_ldk_events(
    channel_manager: &Arc<ChannelManager>,
    bitcoind_client: &BitcoindClient,
    network_graph: &NetworkGraph,
    keys_manager: &KeysManager,
    inbound_payments: &PaymentInfoStorage,
    outbound_payments: &PaymentInfoStorage,
    network: Network,
    event: &Event,
) {
    match event {
        Event::FundingGenerationReady {
            temporary_channel_id,
            counterparty_node_id,
            channel_value_satoshis,
            output_script,
            ..
        } => {
            // Construct the raw transaction with one output, that is paid the amount of the
            // channel.
            let addr = WitnessProgram::from_scriptpubkey(
                &output_script[..],
                match network {
                    Network::Bitcoin => bitcoin_bech32::constants::Network::Bitcoin,
                    Network::Testnet => bitcoin_bech32::constants::Network::Testnet,
                    Network::Regtest => bitcoin_bech32::constants::Network::Regtest,
                    Network::Signet => bitcoin_bech32::constants::Network::Signet,
                },
            )
            .expect("Lightning funding tx should always be to a SegWit output")
            .to_address();
            let mut outputs = vec![HashMap::with_capacity(1)];
            outputs[0].insert(addr, *channel_value_satoshis as f64 / 100_000_000.0);
            let raw_tx = bitcoind_client.create_raw_transaction(outputs).await;

            // Have your wallet put the inputs into the transaction such that the output is
            // satisfied.
            let funded_tx = bitcoind_client.fund_raw_transaction(raw_tx).await;

            // Sign the final funding transaction and broadcast it.
            let signed_tx = bitcoind_client
                .sign_raw_transaction_with_wallet(funded_tx.hex)
                .await;
            assert_eq!(signed_tx.complete, true);
            let final_tx: Transaction =
                encode::deserialize(&utils::to_vec(&signed_tx.hex).unwrap()).unwrap();
            // Give the funding transaction back to LDK for opening the channel.
            if channel_manager
                .funding_transaction_generated(
                    &temporary_channel_id,
                    counterparty_node_id,
                    final_tx,
                )
                .is_err()
            {
                println!(
                    "\nERROR: Channel went away before we could fund it. The peer disconnected or refused the channel.");
                print!("> ");
                io::stdout().flush().unwrap();
            }
        }
        Event::PaymentReceived {
            payment_hash,
            purpose,
            amount_msat,
        } => {
            println!(
                "\nEVENT: received payment from payment hash {} of {} millisatoshis",
                utils::hex_str(&payment_hash.0),
                amount_msat,
            );
            print!("> ");
            io::stdout().flush().unwrap();
            let payment_preimage = match purpose {
                PaymentPurpose::InvoicePayment {
                    payment_preimage, ..
                } => *payment_preimage,
                PaymentPurpose::SpontaneousPayment(preimage) => Some(*preimage),
            };
            channel_manager.claim_funds(payment_preimage.unwrap());
        }
        Event::PaymentClaimed {
            payment_hash,
            purpose,
            amount_msat,
        } => {
            println!(
                "\nEVENT: claimed payment from payment hash {} of {} millisatoshis",
                utils::hex_str(&payment_hash.0),
                amount_msat,
            );
            print!("> ");
            io::stdout().flush().unwrap();
            let (payment_preimage, payment_secret) = match purpose {
                PaymentPurpose::InvoicePayment {
                    payment_preimage,
                    payment_secret,
                    ..
                } => (*payment_preimage, Some(*payment_secret)),
                PaymentPurpose::SpontaneousPayment(preimage) => (Some(*preimage), None),
            };
            let mut payments = inbound_payments.lock().unwrap();
            match payments.entry(*payment_hash) {
                Entry::Occupied(mut e) => {
                    let payment = e.get_mut();
                    payment.status = HTLCStatus::Succeeded;
                    payment.preimage = payment_preimage;
                    payment.secret = payment_secret;
                }
                Entry::Vacant(e) => {
                    e.insert(PaymentInfo {
                        preimage: payment_preimage,
                        secret: payment_secret,
                        status: HTLCStatus::Succeeded,
                        amt_msat: MillisatAmount(Some(*amount_msat)),
                    });
                }
            }
        }
        Event::PaymentSent {
            payment_preimage,
            payment_hash,
            fee_paid_msat,
            ..
        } => {
            let mut payments = outbound_payments.lock().unwrap();
            for (hash, payment) in payments.iter_mut() {
                if *hash == *payment_hash {
                    payment.preimage = Some(*payment_preimage);
                    payment.status = HTLCStatus::Succeeded;
                    println!(
                        "\nEVENT: successfully sent payment of {} millisatoshis{} from \
								 payment hash {:?} with preimage {:?}",
                        payment.amt_msat,
                        if let Some(fee) = fee_paid_msat {
                            format!(" (fee {} msat)", fee)
                        } else {
                            "".to_string()
                        },
                        utils::hex_str(&payment_hash.0),
                        utils::hex_str(&payment_preimage.0)
                    );
                    print!("> ");
                    io::stdout().flush().unwrap();
                }
            }
        }
        Event::OpenChannelRequest { .. } => {
            // Unreachable, we don't set manually_accept_inbound_channels
        }
        Event::PaymentPathSuccessful { .. } => {}
        Event::PaymentPathFailed { .. } => {}
        Event::ProbeSuccessful { .. } => {}
        Event::ProbeFailed { .. } => {}
        Event::PaymentFailed { payment_hash, .. } => {
            print!(
                "\nEVENT: Failed to send payment to payment hash {:?}: exhausted payment retry attempts",
                utils::hex_str(&payment_hash.0)
            );
            print!("> ");
            io::stdout().flush().unwrap();

            let mut payments = outbound_payments.lock().unwrap();
            if payments.contains_key(&payment_hash) {
                let payment = payments.get_mut(&payment_hash).unwrap();
                payment.status = HTLCStatus::Failed;
            }
        }
        Event::PaymentForwarded {
            prev_channel_id,
            next_channel_id,
            fee_earned_msat,
            claim_from_onchain_tx,
        } => {
            let read_only_network_graph = network_graph.read_only();
            let nodes = read_only_network_graph.nodes();
            let channels = channel_manager.list_channels();

            let node_str = |channel_id: &Option<[u8; 32]>| match channel_id {
                None => String::new(),
                Some(channel_id) => match channels.iter().find(|c| c.channel_id == *channel_id) {
                    None => String::new(),
                    Some(channel) => {
                        match nodes.get(&NodeId::from_pubkey(&channel.counterparty.node_id)) {
                            None => "private node".to_string(),
                            Some(node) => match &node.announcement_info {
                                None => "unnamed node".to_string(),
                                Some(announcement) => {
                                    format!("node {}", announcement.alias)
                                }
                            },
                        }
                    }
                },
            };
            let channel_str = |channel_id: &Option<[u8; 32]>| {
                channel_id
                    .map(|channel_id| format!(" with channel {}", utils::hex_str(&channel_id)))
                    .unwrap_or_default()
            };
            let from_prev_str = format!(
                " from {}{}",
                node_str(prev_channel_id),
                channel_str(prev_channel_id)
            );
            let to_next_str = format!(
                " to {}{}",
                node_str(next_channel_id),
                channel_str(next_channel_id)
            );

            let from_onchain_str = if *claim_from_onchain_tx {
                "from onchain downstream claim"
            } else {
                "from HTLC fulfill message"
            };
            if let Some(fee_earned) = fee_earned_msat {
                println!(
                    "\nEVENT: Forwarded payment{}{}, earning {} msat {}",
                    from_prev_str, to_next_str, fee_earned, from_onchain_str
                );
            } else {
                println!(
                    "\nEVENT: Forwarded payment{}{}, claiming onchain {}",
                    from_prev_str, to_next_str, from_onchain_str
                );
            }
            print!("> ");
            io::stdout().flush().unwrap();
        }
        Event::HTLCHandlingFailed { .. } => {}
        Event::PendingHTLCsForwardable { time_forwardable } => {
            let forwarding_channel_manager = channel_manager.clone();
            let min = time_forwardable.as_millis() as u64;
            tokio::spawn(async move {
                let millis_to_sleep = thread_rng().gen_range(min..min * 5) as u64;
                tokio::time::sleep(Duration::from_millis(millis_to_sleep)).await;
                forwarding_channel_manager.process_pending_htlc_forwards();
            });
        }
        Event::SpendableOutputs { outputs } => {
            let destination_address = bitcoind_client.get_new_address().await;
            let output_descriptors = &outputs.iter().map(|a| a).collect::<Vec<_>>();
            let tx_feerate =
                bitcoind_client.get_est_sat_per_1000_weight(ConfirmationTarget::Normal);
            let spending_tx = keys_manager
                .spend_spendable_outputs(
                    output_descriptors,
                    Vec::new(),
                    destination_address.script_pubkey(),
                    tx_feerate,
                    &Secp256k1::new(),
                )
                .unwrap();
            bitcoind_client.broadcast_transaction(&spending_tx);
        }
        Event::ChannelClosed {
            channel_id,
            reason,
            user_channel_id: _,
        } => {
            println!(
                "\nEVENT: Channel {} closed due to: {:?}",
                utils::hex_str(channel_id),
                reason
            );
            print!("> ");
            io::stdout().flush().unwrap();
        }
        Event::DiscardFunding { .. } => {
            // A "real" node should probably "lock" the UTXOs spent in funding transactions until
            // the funding transaction either confirms, or this event is generated.
        }
    }
}

async fn do_connect_peer(
    pubkey: PublicKey,
    peer_addr: SocketAddr,
    peer_manager: Arc<PeerManager>,
) -> Result<(), ()> {
    match lightning_net_tokio::connect_outbound(Arc::clone(&peer_manager), pubkey, peer_addr).await
    {
        Some(connection_closed_future) => {
            let mut connection_closed_future = Box::pin(connection_closed_future);
            loop {
                match futures::poll!(&mut connection_closed_future) {
                    std::task::Poll::Ready(_) => {
                        return Err(());
                    }
                    std::task::Poll::Pending => {}
                }
                // Avoid blocking the tokio context by sleeping a bit
                match peer_manager
                    .get_peer_node_ids()
                    .iter()
                    .find(|id| **id == pubkey)
                {
                    Some(_) => return Ok(()),
                    None => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        }
        None => Err(()),
    }
}

pub fn check_rpc_init() -> bool {
    let client = BITCOIND_CLIENT.read().unwrap().is_some();
    client
}
pub fn open_channel(pub_key: String, host: String, port: u32, amt_satoshis: u64) {}

pub(crate) fn parse_peer_info(
    peer_addr_str: String,
    pub_key_str: String,
) -> Result<(PublicKey, SocketAddr), std::io::Error> {
    let peer_addr = peer_addr_str.to_socket_addrs().map(|mut r| r.next());
    if peer_addr.is_err() || peer_addr.as_ref().unwrap().is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "ERROR: couldn't parse pubkey@host:port into a socket address",
        ));
    }

    let pubkey = utils::to_compressed_pubkey(pub_key_str.as_str());
    if pubkey.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "ERROR: unable to parse given pubkey for node",
        ));
    }

    Ok((pubkey.unwrap(), peer_addr.unwrap().unwrap()))
}
