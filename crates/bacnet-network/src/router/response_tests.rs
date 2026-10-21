//! Responses the router's own application sends to requests it delivered locally.
use std::time::Duration;

use bacnet_encoding::npdu::{decode_npdu, encode_npdu, Npdu, NpduAddress};
use bacnet_npdu::NetworkPriority;
use bacnet_transport::port::{DirectResponseScope, ReceivedNpdu};
use bacnet_types::{error::Error, MacAddr};
use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc;

use super::r7_reply_tests::{address, port, WireReceiver};
use super::{BACnetRouter, RouterOptions, RouterPort, StartedRouter};

/// The APDUs of a request and its answer. The router carries them without reading them.
const REQUEST: &[u8] = &[0x00, 0x05, 0x37, 0x0c];
const RESPONSE: &[u8] = &[0x20, 0x37, 0x0c];

/// A router on networks 1000 (port MAC 1) and 2000 (port MAC 2), with the sender into its
/// network-1000 port and what that port puts on the wire.
async fn router() -> (StartedRouter, mpsc::Sender<ReceivedNpdu>, WireReceiver) {
    let (a, frames, wire) = port(1);
    let (b, _, _) = port(2);
    let started = BACnetRouter::start(
        vec![
            RouterPort {
                transport: a,
                network_number: 1000,
            },
            RouterPort {
                transport: b,
                network_number: 2000,
            },
        ],
        RouterOptions::new(),
    )
    .await
    .unwrap();
    (started, frames, wire)
}

/// `REQUEST` for the router itself, from station 9, carrying `source` as SNET/SADR when the
/// request came through another router.
async fn deliver(
    started: &mut StartedRouter,
    frames: &mpsc::Sender<ReceivedNpdu>,
    source: Option<NpduAddress>,
) -> crate::response_route::ResponseRoute {
    let npdu = Npdu {
        source,
        expecting_reply: true,
        payload: Bytes::from_static(REQUEST),
        ..Npdu::default()
    };
    let mut bytes = BytesMut::new();
    encode_npdu(&mut bytes, &npdu).unwrap();
    frames
        .send(ReceivedNpdu::unverified(
            bytes.freeze(),
            MacAddr::from_slice(&[9]),
            false,
            vec![],
            None,
        ))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), started.apdus.recv())
        .await
        .unwrap()
        .unwrap()
        .response_route()
}

async fn respond(
    router: &BACnetRouter,
    route: &crate::response_route::ResponseRoute,
    owner: &DirectResponseScope,
) -> Result<(), Error> {
    router
        .send_response_apdu_on_issuance(
            RESPONSE,
            false,
            NetworkPriority::Normal,
            route,
            owner,
            || {},
        )
        .await
}

async fn sent(wire: &mut WireReceiver) -> (Npdu, Vec<u8>) {
    let (bytes, peer) = tokio::time::timeout(Duration::from_secs(1), wire.recv())
        .await
        .unwrap()
        .unwrap();
    (decode_npdu(bytes).unwrap(), peer)
}

#[tokio::test]
async fn a_local_request_is_answered_to_the_station_on_its_port() {
    let (mut started, frames, mut wire) = router().await;
    let route = deliver(&mut started, &frames, None).await;

    respond(&started.router, &route, &DirectResponseScope::default())
        .await
        .unwrap();

    let (response, peer) = sent(&mut wire).await;
    assert_eq!(peer, [9]);
    assert_eq!(response.destination, None);
    assert_eq!(response.payload.as_ref(), RESPONSE);
}

#[tokio::test]
async fn a_routed_request_is_answered_through_the_router_it_came_from() {
    let (mut started, frames, mut wire) = router().await;
    let route = deliver(&mut started, &frames, Some(address(3000, &[7]))).await;

    respond(&started.router, &route, &DirectResponseScope::default())
        .await
        .unwrap();

    let (response, peer) = sent(&mut wire).await;
    assert_eq!(peer, [9]);
    assert_eq!(response.destination, Some(address(3000, &[7])));
    assert_eq!(response.payload.as_ref(), RESPONSE);
}

#[tokio::test]
async fn a_route_another_router_captured_is_refused() {
    let (mut started, frames, mut wire) = router().await;
    let route = deliver(&mut started, &frames, None).await;
    let (other, _, _) = router().await;

    let error = respond(&other.router, &route, &DirectResponseScope::default())
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::Transport(error) if error.kind() == std::io::ErrorKind::PermissionDenied),
        "{error:?}"
    );
    assert!(wire.try_recv().is_err(), "nothing is sent");
}

#[tokio::test]
async fn a_response_for_a_sealed_owner_is_not_sent() {
    let (mut started, frames, mut wire) = router().await;
    let route = deliver(&mut started, &frames, None).await;
    let owner = DirectResponseScope::default();
    owner.seal();

    assert!(respond(&started.router, &route, &owner).await.is_err());
    assert!(wire.try_recv().is_err(), "nothing is sent");
}
