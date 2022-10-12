
use crate::bitcoind_client::BitcoindClient;
use crate::file_io::FilesystemLogger;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{BlockHash};
use crate::{hex_utils, serialize};
use bitcoin_bech32::WitnessProgram;
use lightning::chain;
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning::chain::chainmonitor;

use lazy_static::__Deref;
use lazy_static::lazy_static;
use lightning::chain::keysinterface::{KeysInterface, KeysManager, Recipient};
use lightning::chain::BestBlock;
use lightning::chain::Watch;
use lightning::ln::channelmanager;
use lightning::ln::channelmanager::{ChainParameters, ChannelManagerReadArgs};
use lightning::ln::peer_handler::{IgnoringMessageHandler, MessageHandler};
use lightning::routing::gossip::{NodeId, P2PGossipSync};
use lightning::util::config::UserConfig;
use lightning::util::events::{Event, PaymentPurpose};
use lightning::util::ser::ReadableArgs;
use lightning_background_processor::{BackgroundProcessor, GossipSync};
use lightning_block_sync::init;
use lightning_block_sync::poll;
use lightning_block_sync::SpvClient;
use lightning_block_sync::UnboundedCache;
use lightning_invoice::{Invoice, payment};
use lightning_invoice::utils::DefaultRouter;
use lightning_persister::FilesystemPersister;
use rand::{thread_rng, Rng, RngCore};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io;
use crate::ffi;
use std::io::Write;
use std::net::ToSocketAddrs;
use std::ops::Deref;
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use futures::FutureExt;
use lightning::routing::router;
use secp256k1::PublicKey;
use crate::file_io;
use crate::types::{ChainMonitor, ChannelInfo, ChannelManager, HTLCStatus, InvoicePayer, LdkInfo, LdkNodeInfo, MillisatAmount, NetworkGraph, PaymentInfo, PaymentInfoStorage, PeerManager};
lazy_static! {
    static ref LDKINFO: RwLock<Option<LdkInfo>> = RwLock::new(None);
}
fn set_ldk_info(
    channel_manager: Arc<ChannelManager>,
    peer_manager:Arc<PeerManager>,
    bitcoind_client: Arc<BitcoindClient>,
    network_graph: Arc<NetworkGraph>,
    keys_manager: Arc<KeysManager>,
    inbound_payments: PaymentInfoStorage,
    outbound_payments: PaymentInfoStorage,
    network: Network,
    path: String,
) {
    let ldk_info = LdkInfo {
        channel_manager: Some(channel_manager),
        peer_manager:Some(peer_manager),
        bitcoind_client: Some(bitcoind_client),
        network_graph: Some(network_graph),
        keys_manager: Some(keys_manager),
        inbound_payments: Some(inbound_payments),
        outbound_payments: Some(outbound_payments),
        network: Some(network),
        path: Some(path),
    };
    let mut l_info = LDKINFO.write().unwrap();
    *l_info = Some(ldk_info);
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
        Event::PaymentReceived {
            payment_hash,
            purpose,
            amount_msat,
        } => {
            io::stdout().flush().unwrap();
            let payment_preimage = match purpose {
                PaymentPurpose::InvoicePayment {
                    payment_preimage, ..
                } => *payment_preimage,
                PaymentPurpose::SpontaneousPayment(preimage) => Some(*preimage),
            };
            channel_manager.claim_funds(payment_preimage.unwrap());
        }

        Event::PaymentSent {
            payment_preimage,
            payment_hash,
            ..
        } => {
            let mut payments = outbound_payments.lock().unwrap();
            for (hash, payment) in payments.iter_mut() {
                if *hash == *payment_hash {
                    payment.preimage = Some(*payment_preimage);
                    payment.status = HTLCStatus::Succeeded;
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
                hex_utils::hex_str(&payment_hash.0)
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
                    .map(|channel_id| format!(" with channel {}", hex_utils::hex_str(&channel_id)))
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
                hex_utils::hex_str(channel_id),
                reason
            );
            print!("> ");
            io::stdout().flush().unwrap();
        }
        Event::DiscardFunding { .. } => {
            // A "real" node should probably "lock" the UTXOs spent in funding transactions until
            // the funding transaction either confirms, or this event is generated.
        }
        _ => {}
    }
}

#[tokio::main(flavor = "current_thread")]
pub async fn start_ldk(
    username: String,
    password: String,
    host: String,
    node_network: String,
    path: String,
    port: u16,
) -> String
{
    let network = serialize::config_network(node_network);
    let ldk_data_dir = format!("{}/.ldk", path);
    fs::create_dir_all(ldk_data_dir.clone()).unwrap();
    // Initialize our bitcoind client.
    let _client = BitcoindClient::new(
        host,
        port,
        username,
        password,
        tokio::runtime::Handle::current(),
    )
        .await.unwrap();
    let bitcoind_client = Arc::new(_client);
    // ## Setup
    // Step 1: Initialize the FeeEstimator
    // BitcoindClient implements the FeeEstimator trait, so it'll act as our fee estimator.
    let fee_estimator = bitcoind_client.clone();
    // Step 2: Initialize the Logger
    let logger = Arc::new(FilesystemLogger::new(ldk_data_dir.clone()));
    // Step 3: Initialize the BroadcasterInterface
    // BitcoindClient implements the BroadcasterInterface trait, so it'll act as our transaction
    // broadcaster.
    let broadcaster = bitcoind_client.clone();
    // Step 4: Initialize Persist
    let persister = Arc::new(FilesystemPersister::new(ldk_data_dir.clone()));
    // Step 5: Initialize the ChainMonitor
    let chain_monitor: Arc<ChainMonitor> = Arc::new(chainmonitor::ChainMonitor::new(
        None,
        broadcaster.clone(),
        logger.clone(),
        fee_estimator.clone(),
        persister.clone(),
    ));
    // Step 6: Initialize the KeysManager
    // The key seed that we use to derive the node privkey (that corresponds to the node pubkey) and
    // other secret key material.
    let keys_seed_path = format!("{}/keys_seed", ldk_data_dir.clone());
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
    let keys_manager = Arc::new(KeysManager::new(
        &keys_seed,
        cur.as_secs(),
        cur.subsec_nanos(),
    ));
    // Step 7: Read ChannelMonitor state from disk
    let mut channelmonitors = persister
        .read_channelmonitors(keys_manager.clone())
        .unwrap();

    // Step 8: Initialize the ChannelManager
    let mut user_config = UserConfig::default();
    user_config
        .channel_handshake_limits
        .force_announced_channel_preference = false;
    let mut restarting_node = true;
    let (channel_manager_blockhash, channel_manager) = {
        if let Ok(mut f) = fs::File::open(format!("{}/manager", ldk_data_dir.clone())) {
            let mut channel_monitor_mut_references = Vec::new();
            for (_, channel_monitor) in channelmonitors.iter_mut() {
                channel_monitor_mut_references.push(channel_monitor);
            }
            let read_args = ChannelManagerReadArgs::new(
                keys_manager.clone(),
                fee_estimator.clone(),
                chain_monitor.clone(),
                broadcaster.clone(),
                logger.clone(),
                user_config,
                channel_monitor_mut_references,
            );
            <(BlockHash, ChannelManager)>::read(&mut f, read_args).unwrap()
        } else {
            // We're starting a fresh node.
            restarting_node = false;
            let getinfo_resp = bitcoind_client.get_blockchain_info().await;

            let chain_params = ChainParameters {
                network: network,
                best_block: BestBlock::new(
                    getinfo_resp.latest_blockhash,
                    getinfo_resp.latest_height as u32,
                ),
            };
            let fresh_channel_manager = channelmanager::ChannelManager::new(
                fee_estimator.clone(),
                chain_monitor.clone(),
                broadcaster.clone(),
                logger.clone(),
                keys_manager.clone(),
                user_config,
                chain_params,
            );
            (getinfo_resp.latest_blockhash, fresh_channel_manager)
        }
    };
    // Step 9: Sync ChannelMonitors and ChannelManager to chain tip
    let mut chain_listener_channel_monitors = Vec::new();
    let mut cache = UnboundedCache::new();
    let mut chain_tip: Option<poll::ValidatedBlockHeader> = None;
    if restarting_node {
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
                network,
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
    let genesis = genesis_block(network).header.block_hash();
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
    let channel_manager: Arc<ChannelManager> = Arc::new(channel_manager);
    let mut ephemeral_bytes = [0; 32];
    rand::thread_rng().fill_bytes(&mut ephemeral_bytes);
    let lightning_msg_handler = MessageHandler {
        chan_handler: channel_manager.clone(),
        route_handler: gossip_sync.clone(),
    };
    let peer_manager: Arc<PeerManager> = Arc::new(PeerManager::new(
        lightning_msg_handler,
        keys_manager.get_node_secret(Recipient::Node).unwrap(),
        &ephemeral_bytes,
        logger.clone(),
        Arc::new(IgnoringMessageHandler {}),
    ));
    // ## Running LDK
    // Step 13: Initialize networking
    let peer_manager_connection_handler = peer_manager.clone();
    let stop_listen_connect = Arc::new(AtomicBool::new(false));
    let stop_listen = Arc::clone(&stop_listen_connect);
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", 9735))
            .await
            .expect("Failed to bind to listen port - is something else already listening on it?");
        loop {
            let peer_mgr = peer_manager_connection_handler.clone();
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
    let network = network;
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
    // TODO: persist payment info to disk
    let inbound_payments: PaymentInfoStorage = Arc::new(Mutex::new(HashMap::new()));
    let outbound_payments: PaymentInfoStorage = Arc::new(Mutex::new(HashMap::new()));
    let inbound_pmts_for_events = inbound_payments.clone();
    let outbound_pmts_for_events = outbound_payments.clone();
    let network = network;
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
            network,
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

    // Step 18: Persist ChannelManager and NetworkGraph
    let persister = Arc::new(FilesystemPersister::new(ldk_data_dir.clone()));

  //  Step 19: Background Processing
    let background_processor = BackgroundProcessor::start(
        persister,
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
                                let _ = ffi::do_connect_peer(
                                    *pubkey,
                                    peer_addr.clone(),
                                    Arc::clone(&connect_pm),
                                )
                                    .await;
                            }
                        }
                    }
                }
                Err(e) => println!(
                    "ERROR: errored reading channel peer info from disk: {:?}",
                    e
                ),
            }
        }
    });
    // Regularly broadcast our node_announcement. This is only required (or possible) if we have
    // some public channels, and is only useful if we have public listen address(es) to announce.
    // In a production environment, this should occur only after the announcement of new channels
    // to avoid churn in the global network graph.
    set_ldk_info(
        channel_manager.clone(),
        peer_manager.clone(),
        bitcoind_client.clone(),
        network_graph.clone(),
        keys_manager.clone(),
        inbound_payments.clone(),
        outbound_payments.clone(),
        network.clone(),
        path.clone(),
    );
    // Disconnect our peers and stop accepting new connections. This ensures we don't continue
    // updating our channel data after we've stopped the background processor.
    // stop_listen_connect.store(true, Ordering::Release);
    // peer_manager.disconnect_all_peers();
    // // Stop the background processor.
    // background_processor.stop().unwrap();
    channel_manager.clone().get_our_node_id().to_string()
}

pub fn get_node_info() ->LdkNodeInfo{
    let ldk_info = LDKINFO.read().unwrap().clone().unwrap();
    let channel_manager = ldk_info.channel_manager.unwrap().clone();
    let peer_manager = ldk_info.peer_manager.unwrap().clone();
    LdkNodeInfo{
        node_pub_key: channel_manager.clone().get_our_node_id().to_string(),
        num_channels: channel_manager.clone().list_channels().len(),
        num_usable_channels:   channel_manager.clone().list_channels().iter().filter(|c| c.is_usable).count(),
        local_balance_msat: channel_manager.clone().list_channels().iter().map(|c| c.balance_msat).sum::<u64>(),
        num_peers: peer_manager.clone().get_peer_node_ids().len()
    }
}
#[tokio::main(flavor = "current_thread")]
pub async fn open_channel(pub_key_str: String, peer_add_str: String, amount: u64, is_public:bool) -> String {
    let ldk_info = LDKINFO.read().unwrap().clone().unwrap();
    let channel_manager = ldk_info.channel_manager.unwrap().clone();
    let peer_manager = ldk_info.peer_manager.unwrap().clone();
    let path = ldk_info.path.unwrap().clone();

    let peer_addr = peer_add_str
        .to_socket_addrs()
        .map(|mut r| r.next())
        .unwrap()
        .unwrap();
    let pubkey = hex_utils::to_compressed_pubkey(&pub_key_str).unwrap();
    ffi::connect_peer_if_necessary(pubkey, peer_addr, peer_manager.clone()).await;
    let res = ffi::open_channel(pubkey, amount, is_public, channel_manager);
    if res.is_ok() {
        let peer_data_path = format!("{}/channel_peer_data", path);
        let info = format!("{}@{}", pub_key_str, peer_add_str);
        let _ = file_io::persist_channel_peer(Path::new(&peer_data_path), info.as_str());
    }
    return res.unwrap();
}

pub fn list_channel()->Vec<ChannelInfo>{
    let mut channels:Vec<ChannelInfo> = Vec::new();
    let ldk_info = LDKINFO.read().unwrap().clone().unwrap();
    let channel_manager = ldk_info.channel_manager.unwrap().clone();
    let network_graph = ldk_info.network_graph.unwrap().clone();
    for chan_info in channel_manager.list_channels() {
        channels.push(ChannelInfo {
            channel_id:hex_utils::hex_str(&chan_info.channel_id[..]),
            funding_txid: match chan_info.funding_txo.is_some(){
                true => Some( chan_info.funding_txo.unwrap().txid.to_string()),
                false => None
            },
            peer_pubkey:   hex_utils::hex_str(&chan_info.counterparty.node_id.serialize()),
            peer_alias: match  network_graph.read_only().nodes().get(&NodeId::from_pubkey(&chan_info.counterparty.node_id)).is_some(){
                true => Some(network_graph.read_only().nodes().get(&NodeId::from_pubkey(&chan_info.counterparty.node_id)).unwrap().announcement_info.as_ref().unwrap().alias.to_string()),
                false => None
            },
            short_channel_id: match chan_info.short_channel_id.is_some() {
                true => Some(chan_info.short_channel_id.unwrap().to_string()),
                false => None
            },
            is_channel_ready: chan_info.is_channel_ready,
            channel_value_satoshis: chan_info.channel_value_satoshis,
            local_balance_msat: chan_info.balance_msat,
            available_balance_for_send_msat: chan_info.outbound_capacity_msat,
            available_balance_for_recv_msat: chan_info.inbound_capacity_msat,
            channel_can_send_payments: chan_info.is_usable,
            public: chan_info.is_public
        })
    }
    channels
}
pub fn list_peers()-> Vec<String>{
    let ldk_info = LDKINFO.read().unwrap().clone().unwrap();
    let peer_manager = ldk_info.peer_manager.unwrap().clone();
    let mut peers:Vec<String> = Vec::new();
    for pub_key in peer_manager.get_peer_node_ids() {
       peers.push(pub_key.to_string());
    }
  peers
}
pub fn close_channel(
    channel_id_str: String, peer_pubkey_str: String
)
{
    let ldk_info = LDKINFO.read().unwrap().clone().unwrap();
    let channel_manager = ldk_info.channel_manager.unwrap().clone();
    let channel_id_vec = hex_utils::to_vec(channel_id_str.as_str());
    /// TODO create a custom exception
    let mut channel_id = [0; 32];
    channel_id.copy_from_slice(&channel_id_vec.unwrap());
    let peer_pubkey_vec = hex_utils::to_vec(peer_pubkey_str.as_str());
    let peer_pubkey = PublicKey::from_slice(&peer_pubkey_vec.unwrap()).unwrap();
    match channel_manager.close_channel(&channel_id, &peer_pubkey) {
        Ok(()) => println!("EVENT: initiating channel close"),
        Err(e) => println!("ERROR: failed to close channel: {:?}", e),
    }
}

pub fn force_close_channel(
    channel_id_str: String, peer_pubkey_str: String
)
{
    let ldk_info = LDKINFO.read().unwrap().clone().unwrap();
    let channel_manager = ldk_info.channel_manager.unwrap().clone();
    let channel_id_vec = hex_utils::to_vec(channel_id_str.as_str());

    let mut channel_id = [0; 32];
    channel_id.copy_from_slice(&channel_id_vec.unwrap());
    let peer_pubkey_vec = hex_utils::to_vec(peer_pubkey_str.as_str());
    let peer_pubkey = PublicKey::from_slice(&peer_pubkey_vec.unwrap()).unwrap();
    match channel_manager.force_close_broadcasting_latest_txn(&channel_id, &peer_pubkey) {
        Ok(()) => println!("EVENT: initiating channel force-close"),
        Err(e) => println!("ERROR: failed to force-close channel: {:?}", e),
    }
}




