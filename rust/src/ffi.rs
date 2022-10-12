use crate::file_io;
use crate::hex_utils;
use crate::types::{
    ChannelManager, HTLCStatus, InvoicePayer, MillisatAmount, NetworkGraph, PaymentInfo,
    PaymentInfoStorage, PeerManager,
};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::PublicKey;
use lightning::chain::keysinterface::{KeysInterface, KeysManager, Recipient};
use lightning::ln::msgs::NetAddress;
use lightning::ln::{PaymentHash, PaymentPreimage};
use lightning::routing::gossip::NodeId;
use lightning::util::config::{ChannelHandshakeConfig, ChannelHandshakeLimits, UserConfig};
use lightning::util::events::EventHandler;
use lightning_invoice::payment::PaymentError;
use lightning_invoice::{utils, Currency, Invoice};
use std::env;
use std::fmt::format;
use std::io;
use std::io::{BufRead, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::ops::Deref;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

pub(crate) async fn connect_peer_if_necessary(
    pubkey: PublicKey,
    peer_addr: SocketAddr,
    peer_manager: Arc<PeerManager>,
) -> Result<(), ()> {
    for node_pubkey in peer_manager.get_peer_node_ids() {
        if node_pubkey == pubkey {
            return Ok(());
        }
    }
    let res = do_connect_peer(pubkey, peer_addr, peer_manager).await;
    if res.is_err() {
        println!("ERROR: failed to connect to peer");
    }
    res
}

pub(crate) async fn do_connect_peer(
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

pub(crate) fn open_channel(
    peer_pubkey: PublicKey,
    channel_amt_sat: u64,
    announced_channel: bool,
    channel_manager: Arc<ChannelManager>,
) -> Result< String, String> {
    let config = UserConfig {
        channel_handshake_limits: ChannelHandshakeLimits {
            // lnd's max to_self_delay is 2016, so we want to be compatible.
            their_to_self_delay: 2016,
            ..Default::default()
        },
        channel_handshake_config: ChannelHandshakeConfig {
            announced_channel,
            ..Default::default()
        },
        ..Default::default()
    };

    return match channel_manager.create_channel(peer_pubkey, channel_amt_sat, 0, 0, Some(config)) {
        Ok(_) => {
            println!("Initiated channel with peer {}. ", peer_pubkey);
            Ok(format!("Initiated channel with peer {}. ", peer_pubkey))
        }
        Err(e) => {
            println!("ERROR: failed to open channel: {:?}", e);
            Err(format!("ERROR: {:?}", e))
        }
    }
}

fn send_payment<E: EventHandler>(
    invoice_payer: &InvoicePayer<E>,
    invoice: &Invoice,
    payment_storage: PaymentInfoStorage,
) {
    let status = match invoice_payer.pay_invoice(invoice) {
        Ok(_payment_id) => {
            let payee_pubkey = invoice.recover_payee_pub_key();
            let amt_msat = invoice.amount_milli_satoshis().unwrap();
            println!(
                "EVENT: initiated sending {} msats to {}",
                amt_msat.clone(), payee_pubkey
            );
            print!("> ");
            HTLCStatus::Pending
        }
        Err(PaymentError::Invoice(e)) => {
            println!("ERROR: invalid invoice: {}", e);
            print!("> ");
            return;
        }
        Err(PaymentError::Routing(e)) => {
            println!("ERROR: failed to find route: {}", e.err);
            print!("> ");
            return;
        }
        Err(PaymentError::Sending(e)) => {
            println!("ERROR: failed to send payment: {:?}", e);
            print!("> ");
            HTLCStatus::Failed
        }
    };
    let payment_hash = PaymentHash(invoice.payment_hash().clone().into_inner());
    let payment_secret = Some(invoice.payment_secret().clone());

    let mut payments = payment_storage.lock().unwrap();
    payments.insert(
        payment_hash,
        PaymentInfo {
            preimage: None,
            secret: payment_secret,
            status,
            amt_msat: MillisatAmount(invoice.amount_milli_satoshis()),
        },
    );
}



fn close_channel(
    channel_id: [u8; 32],
    counterparty_node_id: PublicKey,
    channel_manager: Arc<ChannelManager>,
) {
    match channel_manager.close_channel(&channel_id, &counterparty_node_id) {
        Ok(()) => println!("EVENT: initiating channel close"),
        Err(e) => println!("ERROR: failed to close channel: {:?}", e),
    }
}

fn force_close_channel(
    channel_id: [u8; 32],
    counterparty_node_id: PublicKey,
    channel_manager: Arc<ChannelManager>,
) {
    match channel_manager.force_close_broadcasting_latest_txn(&channel_id, &counterparty_node_id) {
        Ok(()) => println!("EVENT: initiating channel force-close"),
        Err(e) => println!("ERROR: failed to force-close channel: {:?}", e),
    }
}

pub(crate) fn parse_peer_info(
    peer_pubkey_and_ip_addr: String,
) -> Result<(PublicKey, SocketAddr), std::io::Error>
{
    let mut pubkey_and_addr = peer_pubkey_and_ip_addr.split("@");
    let pubkey = pubkey_and_addr.next();
    let peer_addr_str = pubkey_and_addr.next();
    if peer_addr_str.is_none() || peer_addr_str.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "ERROR: incorrectly formatted peer info. Should be formatted as: `pubkey@host:port`",
        ));
    }

    let peer_addr = peer_addr_str
        .unwrap()
        .to_socket_addrs()
        .map(|mut r| r.next());
    if peer_addr.is_err() || peer_addr.as_ref().unwrap().is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "ERROR: couldn't parse pubkey@host:port into a socket address",
        ));
    }

    let pubkey = hex_utils::to_compressed_pubkey(pubkey.unwrap());
    if pubkey.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "ERROR: unable to parse given pubkey for node",
        ));
    }

    Ok((pubkey.unwrap(), peer_addr.unwrap().unwrap()))
}
