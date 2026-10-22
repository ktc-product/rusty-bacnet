//! Network messages at a router endpoint's ports, through the session
//! [`RouterEndpointBuilder`] builds: a port it adds as not forwarding takes
//! no part in routing.
//!
//! Clause map (ASHRAE 135): 6.5.2.1 (a non-routing node discards an NPDU
//! for another network), 6.6.3.2 (Who-Is-Router-To-Network), 6.6.3.8
//! (Initialize-Routing-Table). The router's own handling of each message is
//! covered by `bacnet-network`'s router suites and `bacnet-router-core`'s
//! `forwarding` tests; these check that the builder's ports reach it.
//!
//! Network 1 is the endpoint's own link, network 2 a trunk that forwards,
//! network 3 a trunk that doesn't. Each port has a raw peer.

use std::time::Duration;

use bacnet_encoding::npdu::{decode_npdu, encode_npdu, Npdu, NpduAddress};
use bacnet_endpoint::router::RouterEndpointBuilder;
use bacnet_endpoint::session::EndpointSession;
use bacnet_endpoint::DeviceIdentity;
use bacnet_npdu::NetworkMessageType;
use bacnet_transport::loopback::LoopbackTransport;
use bacnet_transport::port::{ReceivedNpdu, TransportPort};
use bacnet_types::MacAddr;
use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(1);
/// How long a peer listens for something the router must not send.
const QUIET: Duration = Duration::from_millis(200);
const ROUTER_MAC: u8 = 0x01;
const PEER_MAC: u8 = 0x0A;
/// An Unconfirmed-Request Who-Is APDU.
const WHO_IS_APDU: [u8; 2] = [0x10, 0x08];

/// The far side of one router port.
struct Peer {
    transport: LoopbackTransport,
    frames: mpsc::Receiver<ReceivedNpdu>,
}

impl Peer {
    async fn send(&self, npdu: Npdu) {
        let mut encoded = BytesMut::new();
        encode_npdu(&mut encoded, &npdu).unwrap();
        self.transport
            .send_unicast(&encoded, &[ROUTER_MAC])
            .await
            .unwrap();
    }

    async fn send_message(&self, kind: NetworkMessageType, data: &[u8]) {
        self.send(Npdu {
            message_type: Some(kind),
            payload: Bytes::copy_from_slice(data),
            ..Npdu::default()
        })
        .await;
    }

    async fn next(&mut self, within: Duration) -> Option<Npdu> {
        let frame = timeout(within, self.frames.recv()).await.ok()??;
        Some(decode_npdu(frame.npdu).unwrap())
    }

    /// The data of the next network message of `kind`, past any other.
    async fn expect(&mut self, kind: NetworkMessageType) -> Bytes {
        loop {
            let npdu = self
                .next(WAIT)
                .await
                .unwrap_or_else(|| panic!("no {kind:?}"));
            if npdu.message_type == Some(kind) {
                return npdu.payload;
            }
        }
    }

    async fn expect_nothing(&mut self) {
        if let Some(npdu) = self.next(QUIET).await {
            panic!("unexpected {npdu:?}");
        }
    }

    /// Read past the router's startup announcements.
    async fn settle(&mut self) {
        while self.next(QUIET).await.is_some() {}
    }
}

struct Site {
    _router: EndpointSession<LoopbackTransport>,
    home: Peer,
    closed: Peer,
    _trunk: Peer,
}

async fn peer() -> (LoopbackTransport, Peer) {
    let (port, mut transport) = LoopbackTransport::pair(vec![ROUTER_MAC], vec![PEER_MAC]);
    let frames = transport.start().await.unwrap();
    (port, Peer { transport, frames })
}

async fn site() -> Site {
    let (home_port, mut home) = peer().await;
    let (trunk_port, mut trunk) = peer().await;
    let (closed_port, mut closed) = peer().await;
    let mut router = RouterEndpointBuilder::new()
        .port(1, home_port, true)
        .port(2, trunk_port, true)
        .port(3, closed_port, false)
        .device(DeviceIdentity::new(100, 42).unwrap())
        .build_session()
        .unwrap();
    router.start().await.unwrap();
    for peer in [&mut home, &mut trunk, &mut closed] {
        peer.settle().await;
    }
    Site {
        _router: router,
        home,
        closed,
        _trunk: trunk,
    }
}

fn networks(data: &[u8]) -> Vec<u16> {
    data.chunks(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect()
}

#[tokio::test]
async fn who_is_router_names_only_the_forwarding_networks() {
    let mut site = site().await;
    site.home
        .send_message(NetworkMessageType::WHO_IS_ROUTER_TO_NETWORK, &[])
        .await;
    let i_am = site
        .home
        .expect(NetworkMessageType::I_AM_ROUTER_TO_NETWORK)
        .await;
    assert_eq!(networks(&i_am), [2]);

    site.home
        .send_message(NetworkMessageType::WHO_IS_ROUTER_TO_NETWORK, &[0, 3])
        .await;
    site.home.expect_nothing().await;
}

#[tokio::test]
async fn a_port_that_does_not_forward_relays_nothing_for_another_network() {
    let mut site = site().await;
    site.closed
        .send(Npdu {
            destination: Some(NpduAddress {
                network: 1,
                mac_address: MacAddr::from_slice(&[PEER_MAC]),
            }),
            payload: Bytes::from_static(&WHO_IS_APDU),
            ..Npdu::default()
        })
        .await;
    site.home.expect_nothing().await;
    site.closed.expect_nothing().await;
}

#[tokio::test]
async fn a_port_that_does_not_forward_answers_no_who_is_router() {
    let mut site = site().await;
    site.closed
        .send_message(NetworkMessageType::WHO_IS_ROUTER_TO_NETWORK, &[])
        .await;
    site.closed.expect_nothing().await;
}

#[tokio::test]
async fn a_port_that_does_not_forward_answers_no_routing_table_query() {
    let mut site = site().await;
    site.closed
        .send_message(NetworkMessageType::INITIALIZE_ROUTING_TABLE, &[0])
        .await;
    site.closed.expect_nothing().await;
}
