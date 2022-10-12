use lightning::chain;
use lightning::chain::chainmonitor;
use lightning::chain::keysinterface::{InMemorySigner, KeysManager};
use lightning::chain::Filter;
use lightning::ln::channelmanager::SimpleArcChannelManager;
use lightning::ln::peer_handler::SimpleArcPeerManager;
use lightning::ln::{PaymentHash, PaymentPreimage, PaymentSecret};
use lightning::routing::gossip::NetworkGraph as NetGraph;
use lightning::routing::scoring::ProbabilisticScorer;
use lightning_invoice::payment;
use lightning_invoice::utils::DefaultRouter;
use lightning_net_tokio::SocketDescriptor;
use lightning_persister::FilesystemPersister;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use bitcoin::Network;
use crate::bitcoind_client::BitcoindClient;
use crate::file_io::FilesystemLogger;
pub(crate) enum HTLCStatus {
    Pending,
    Succeeded,
    Failed,
}

pub(crate) struct MillisatAmount(pub Option<u64>);

impl fmt::Display for MillisatAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            Some(amt) => write!(f, "{}", amt),
            None => write!(f, "unknown"),
        }
    }
}

pub(crate) struct PaymentInfo {
    pub(crate) preimage: Option<PaymentPreimage>,
    pub(crate) secret: Option<PaymentSecret>,
    pub(crate) status: HTLCStatus,
    pub(crate) amt_msat: MillisatAmount,
}

pub(crate) type PaymentInfoStorage = Arc<Mutex<HashMap<PaymentHash, PaymentInfo>>>;

pub(crate) type ChainMonitor = chainmonitor::ChainMonitor<
    InMemorySigner,
    Arc<dyn Filter + Send + Sync>,
    Arc<BitcoindClient>,
    Arc<BitcoindClient>,
    Arc<FilesystemLogger>,
    Arc<FilesystemPersister>,
>;

pub(crate) type PeerManager = SimpleArcPeerManager<
    SocketDescriptor,
    ChainMonitor,
    BitcoindClient,
    BitcoindClient,
    dyn chain::Access + Send + Sync,
    FilesystemLogger,
>;

pub(crate) type ChannelManager =
    SimpleArcChannelManager<ChainMonitor, BitcoindClient, BitcoindClient, FilesystemLogger>;

pub(crate) type InvoicePayer<E> = payment::InvoicePayer<
    Arc<ChannelManager>,
    Router,
    Arc<Mutex<ProbabilisticScorer<Arc<NetworkGraph>, Arc<FilesystemLogger>>>>,
    Arc<FilesystemLogger>,
    E,
>;

pub type Router = DefaultRouter<Arc<NetworkGraph>, Arc<FilesystemLogger>>;

pub type NetworkGraph = NetGraph<Arc<FilesystemLogger>>;

#[derive(Clone)]
pub(crate) struct LdkInfo {
    pub channel_manager: Option<Arc<ChannelManager>>,
    pub bitcoind_client: Option<Arc<BitcoindClient>>,
    pub network_graph: Option<Arc<NetworkGraph>>,
    pub keys_manager: Option<Arc<KeysManager>>,
    pub peer_manager: Option<Arc<PeerManager>>,
    pub inbound_payments: Option<PaymentInfoStorage>,
    pub outbound_payments: Option<PaymentInfoStorage>,
    pub network: Option<Network>,
    pub path: Option<String>,
}
