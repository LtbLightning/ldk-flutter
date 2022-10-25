use std::{ io};
use std::collections::HashMap;
use std::io::Write;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use bitcoin::consensus::encode;
use bitcoin::secp256k1::PublicKey;
use lightning::chain::keysinterface::KeysManager;
use crate::core::client::BitcoindClient;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Transaction;
use bitcoin::Network;
use bitcoin_bech32::WitnessProgram;
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning::routing::gossip::NodeId;
use lightning::util::errors::APIError as AError;
use lightning::util::events::{Event, PaymentPurpose};
use rand::{Rng, thread_rng};
use crate::utils::{hex_utils};
use crate::utils::types::{ChannelManager, HTLCStatus, NetworkGraph, PaymentInfoStorage};

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
#[derive(Clone, PartialEq)]
pub enum APIError {
    /// Indicates the API was wholly misused (see err for more). Cases where these can be returned
    /// are documented, but generally indicates some precondition of a function was violated.
    APIMisuseError {
        /// A human-readable error message
        err: String
    },
    /// Due to a high feerate, we were unable to complete the request.
    /// For example, this may be returned if the feerate implies we cannot open a channel at the
    /// requested value, but opening a larger channel would succeed.
    FeeRateTooHigh {
        /// A human-readable error message
        err: String,
        /// The feerate which was too high.
        feerate: u32
    },
    /// A malformed Route was provided (eg overflowed value, node id mismatch, overly-looped route,
    /// too-many-hops, etc).
    RouteError {
        /// A human-readable error message
        err: &'static str
    },
    /// We were unable to complete the request as the Channel required to do so is unable to
    /// complete the request (or was not found). This can take many forms, including disconnected
    /// peer, channel at capacity, channel shutting down, etc.
    ChannelUnavailable {
        /// A human-readable error message
        err: String
    },
    /// An attempt to call watch/update_channel returned an Err (ie you did this!), causing the
    /// attempted action to fail.
    MonitorUpdateFailed,
    /// [`KeysInterface::get_shutdown_scriptpubkey`] returned a shutdown scriptpubkey incompatible
    /// with the channel counterparty as negotiated in [`InitFeatures`].
    ///
    /// Using a SegWit v0 script should resolve this issue. If you cannot, you won't be able to open
    /// a channel or cooperatively close one with this peer (and will have to force-close instead).
    ///
    /// [`KeysInterface::get_shutdown_scriptpubkey`]: crate::chain::keysinterface::KeysInterface::get_shutdown_scriptpubkey
    /// [`InitFeatures`]: crate::ln::features::InitFeatures
    IncompatibleShutdownScript {
        /// The incompatible shutdown script.
        err: String,
    },
}

impl std::fmt::Display for APIError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(fmt, " {}", self)
    }
}

pub fn parse_api_error(err:AError)-> APIError{
  return  match err {
        AError::APIMisuseError { err} => APIError::APIMisuseError { err } ,
        AError::FeeRateTooHigh { err,  feerate} => APIError::FeeRateTooHigh{  err, feerate },
        AError::RouteError { err} => APIError::RouteError {err},
        AError::ChannelUnavailable { err} => APIError::ChannelUnavailable {err},
        AError::MonitorUpdateFailed => APIError::MonitorUpdateFailed,
        AError::IncompatibleShutdownScript {  script } => APIError::IncompatibleShutdownScript {err: format!( "Provided a scriptpubkey format not accepted by peer: {}", script.to_string()) },
    }
}

pub(crate) async fn handle_ldk_events(
    channel_manager: &Arc<ChannelManager>,
    bitcoind_client: &BitcoindClient,
    network_graph: &NetworkGraph,
    network: Network,
    keys_manager: &KeysManager,
    inbound_payments: &PaymentInfoStorage,
    outbound_payments: &PaymentInfoStorage,
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
            let signed_tx = bitcoind_client.sign_raw_transaction_with_wallet(funded_tx.hex).await;
            assert_eq!(signed_tx.complete, true);
            let final_tx: Transaction =
                encode::deserialize(&hex_utils::to_vec(&signed_tx.hex).unwrap()).unwrap();
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
                let millis_to_sleep = thread_rng().gen_range(min,min * 5) as u64;
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


