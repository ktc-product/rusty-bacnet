use bacnet_encoding::apdu::{encode_apdu, Apdu, ComplexAck, ConfirmedRequest, UnconfirmedRequest};
use bacnet_encoding::npdu::{decode_npdu, encode_npdu, Npdu, NpduAddress};
use bacnet_network::router::{RouterOptions, RouterPort};
use bacnet_npdu::NetworkPriority;
use bacnet_transport::loopback::LoopbackTransport;
use bacnet_transport::port::{ReceivedNpdu, TransportPort};
use bacnet_types::enums::{ConfirmedServiceChoice, UnconfirmedServiceChoice};
use bacnet_types::MacAddr;
use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

use super::*;

const WAIT: Duration = Duration::from_secs(1);
/// The endpoint's own network, on the first port.
const HOME: u16 = 1;
/// A second port's network.
const TRUNK: u16 = 2;
const ROUTER_MAC: [u8; 1] = [0x01];
const HOME_PEER: [u8; 1] = [0x10];
const TRUNK_PEER: [u8; 1] = [0x20];

/// The far side of one router port.
struct Peer {
    frames: mpsc::Receiver<ReceivedNpdu>,
    transport: LoopbackTransport,
    /// Where each unicast the router sent on this port went.
    unicasts: mpsc::UnboundedReceiver<MacAddr>,
}

impl Peer {
    /// The next frame that carries an APDU, past the router's announcements.
    async fn next_apdu(&mut self) -> (ReceivedNpdu, Npdu) {
        loop {
            let frame = timeout(WAIT, self.frames.recv())
                .await
                .expect("a frame")
                .expect("the link is open");
            let npdu = decode_npdu(frame.npdu.clone()).unwrap();
            if !npdu.is_network_message() {
                return (frame, npdu);
            }
        }
    }

    async fn send(&self, apdu: &[u8]) {
        let mut npdu = BytesMut::new();
        encode_npdu(
            &mut npdu,
            &Npdu {
                expecting_reply: true,
                payload: Bytes::copy_from_slice(apdu),
                ..Npdu::default()
            },
        )
        .unwrap();
        self.transport
            .send_unicast(&npdu, &ROUTER_MAC)
            .await
            .unwrap();
    }
}

async fn port(network: u16, peer_mac: [u8; 1]) -> (RouterPort<LoopbackTransport>, Peer) {
    let (mut transport, mut peer) = LoopbackTransport::pair(
        MacAddr::from_slice(&ROUTER_MAC),
        MacAddr::from_slice(&peer_mac),
    );
    let unicasts = transport.record_unicast_destinations();
    let frames = peer.start().await.unwrap();
    (
        RouterPort {
            transport,
            network_number: network,
        },
        Peer {
            frames,
            transport: peer,
            unicasts,
        },
    )
}

/// A started router endpoint on HOME and TRUNK, with their peers. A dropped
/// peer closes its link, and with both closed the session ends.
async fn router_endpoint() -> (
    EndpointIngress<LoopbackTransport>,
    IngressReceivers,
    Peer,
    Peer,
) {
    let (home, home_peer) = port(HOME, HOME_PEER).await;
    let (trunk, trunk_peer) = port(TRUNK, TRUNK_PEER).await;
    let mut endpoint =
        EndpointIngress::with_router(vec![home, trunk], RouterOptions::new(), 8).unwrap();
    let receivers = endpoint.start().await.unwrap();
    (endpoint, receivers, home_peer, trunk_peer)
}

fn who_is() -> Vec<u8> {
    let mut encoded = BytesMut::new();
    encode_apdu(
        &mut encoded,
        &Apdu::UnconfirmedRequest(UnconfirmedRequest {
            service_choice: UnconfirmedServiceChoice::WHO_IS,
            service_request: Bytes::new(),
        }),
    )
    .unwrap();
    encoded.to_vec()
}

fn read_property() -> Vec<u8> {
    let mut encoded = BytesMut::new();
    encode_apdu(
        &mut encoded,
        &Apdu::ConfirmedRequest(ConfirmedRequest {
            segmented: false,
            more_follows: false,
            segmented_response_accepted: false,
            max_segments: None,
            max_apdu_length: 480,
            invoke_id: 7,
            sequence_number: None,
            proposed_window_size: None,
            service_choice: ConfirmedServiceChoice::READ_PROPERTY,
            service_request: Bytes::new(),
        }),
    )
    .unwrap();
    encoded.to_vec()
}

fn ack() -> Vec<u8> {
    let mut encoded = BytesMut::new();
    encode_apdu(
        &mut encoded,
        &Apdu::ComplexAck(ComplexAck {
            segmented: false,
            more_follows: false,
            invoke_id: 7,
            sequence_number: None,
            proposed_window_size: None,
            service_choice: ConfirmedServiceChoice::READ_PROPERTY,
            service_ack: Bytes::new(),
        }),
    )
    .unwrap();
    encoded.to_vec()
}

async fn send(egress: &EndpointEgress, destination: EndpointApduDestination) -> Result<(), Error> {
    egress
        .send_apdu(
            who_is(),
            destination,
            false,
            NetworkPriority::Normal,
            Vec::new(),
        )
        .await
}

#[tokio::test]
async fn the_first_ports_network_is_the_endpoints_and_the_router_owns_number_controls() {
    let (_endpoint, receivers, _home, _trunk) = router_endpoint().await;
    assert_eq!(receivers.egress.local_network_number().get(), Some(HOME));
    assert!(receivers.network_controls.is_none());
}

#[tokio::test]
async fn a_direct_send_leaves_by_the_first_port() {
    let (_endpoint, receivers, mut home, _trunk) = router_endpoint().await;
    let direct = EndpointApduDestination::Direct {
        destination_mac: MacAddr::from_slice(&HOME_PEER),
    };
    send(&receivers.egress, direct).await.unwrap();
    let (_, npdu) = home.next_apdu().await;
    assert_eq!(npdu.destination, None);
    assert_eq!(npdu.payload.as_ref(), who_is());
    assert_eq!(home.unicasts.recv().await.as_deref(), Some(&HOME_PEER[..]));
}

#[tokio::test]
async fn a_routed_send_to_one_of_the_routers_networks_goes_to_the_node_there() {
    let (_endpoint, receivers, _home, mut trunk) = router_endpoint().await;
    let routed = EndpointApduDestination::Routed {
        destination_network: TRUNK,
        destination_mac: MacAddr::from_slice(&TRUNK_PEER),
        router_mac: MacAddr::from_slice(&[0x99]),
    };
    send(&receivers.egress, routed).await.unwrap();
    let (_, npdu) = trunk.next_apdu().await;
    assert_eq!(npdu.destination, None);
    assert_eq!(
        trunk.unicasts.recv().await.as_deref(),
        Some(&TRUNK_PEER[..])
    );
}

#[tokio::test]
async fn a_routed_send_beyond_goes_through_the_named_router_on_the_first_port() {
    let (_endpoint, receivers, mut home, _trunk) = router_endpoint().await;
    let routed = EndpointApduDestination::Routed {
        destination_network: 9,
        destination_mac: MacAddr::from_slice(&[0x05]),
        router_mac: MacAddr::from_slice(&[0x30]),
    };
    send(&receivers.egress, routed).await.unwrap();
    let (_, npdu) = home.next_apdu().await;
    assert_eq!(
        npdu.destination,
        Some(NpduAddress {
            network: 9,
            mac_address: MacAddr::from_slice(&[0x05]),
        })
    );
    assert_eq!(home.unicasts.recv().await.as_deref(), Some(&[0x30][..]));
}

#[tokio::test]
async fn a_local_broadcast_goes_out_every_port() {
    let (_endpoint, receivers, mut home, mut trunk) = router_endpoint().await;
    send(&receivers.egress, EndpointApduDestination::LocalBroadcast)
        .await
        .unwrap();
    for peer in [&mut home, &mut trunk] {
        let (frame, npdu) = peer.next_apdu().await;
        assert!(frame.link_layer_group);
        assert_eq!(npdu.destination, None);
    }
}

#[tokio::test]
async fn what_the_router_has_no_path_for_is_refused() {
    let (_endpoint, receivers, _home, _trunk) = router_endpoint().await;
    let global = send(&receivers.egress, EndpointApduDestination::GlobalBroadcast).await;
    assert!(global.is_err());
    let unknown = send(
        &receivers.egress,
        EndpointApduDestination::RemoteBroadcast {
            destination_network: 77,
        },
    )
    .await;
    let Err(Error::Transport(error)) = unknown else {
        panic!("no route to network 77: {unknown:?}");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

#[tokio::test]
async fn a_request_on_a_second_port_is_answered_on_it() {
    let (_endpoint, mut receivers, _home, mut trunk) = router_endpoint().await;
    trunk.send(&read_property()).await;
    let request = timeout(WAIT, receivers.inbound_requests.recv())
        .await
        .expect("the request")
        .expect("open");
    assert_eq!(request.ingress_network, Some(TRUNK));
    assert_eq!(request.source_mac.as_slice(), TRUNK_PEER);

    receivers
        .egress
        .admit_response_apdu(
            ack(),
            request.source_mac.clone(),
            None,
            request.response_route(),
        )
        .unwrap()
        .complete()
        .await
        .result
        .unwrap();
    let (_, npdu) = trunk.next_apdu().await;
    assert_eq!(npdu.payload.as_ref(), ack());
    assert_eq!(
        trunk.unicasts.recv().await.as_deref(),
        Some(&TRUNK_PEER[..])
    );
}

#[tokio::test]
async fn a_confirmed_request_from_a_group_address_on_its_port_reaches_no_role() {
    let (home, _home_peer) = port(HOME, HOME_PEER).await;
    let (mut trunk, trunk_peer) = port(TRUNK, [0xFF]).await;
    trunk
        .transport
        .set_broadcast_mac(MacAddr::from_slice(&[0xFF]));
    let mut endpoint =
        EndpointIngress::with_router(vec![home, trunk], RouterOptions::new(), 8).unwrap();
    let mut receivers = endpoint.start().await.unwrap();

    trunk_peer.send(&read_property()).await;
    let outcome = timeout(WAIT, receivers.policy_outcomes.recv())
        .await
        .expect("the outcome")
        .expect("open");
    assert_eq!(outcome.reason, PolicyReason::GroupSource);
    assert_eq!(outcome.received.ingress_network, Some(TRUNK));
}

#[tokio::test]
async fn a_router_endpoint_needs_a_port() {
    let ports: Vec<RouterPort<LoopbackTransport>> = Vec::new();
    assert!(EndpointIngress::with_router(ports, RouterOptions::new(), 8).is_err());
}
