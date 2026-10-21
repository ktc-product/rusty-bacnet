//! Ports that don't forward, on the hosted router.
use std::time::Duration;

use bacnet_encoding::npdu::{decode_npdu, encode_npdu, Npdu};
use bacnet_npdu::NetworkMessageType;
use bacnet_transport::port::ReceivedNpdu;
use bacnet_types::MacAddr;
use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc;

use super::r7_reply_tests::{address, port, WireReceiver};
use super::{BACnetRouter, RouterOptions, RouterPort, StartedRouter};

const REQUEST: &[u8] = &[0x00, 0x05, 0x37, 0x0c];
const STATION: &[u8] = &[7];

/// A router on networks 1000, 2000 and 3000 (port MACs 1, 2 and 3), the
/// sender into its network-1000 port and what each port puts on the wire.
async fn router(
    options: RouterOptions,
) -> (StartedRouter, mpsc::Sender<ReceivedNpdu>, [WireReceiver; 3]) {
    let (a, frames, wire_a) = port(1);
    let (b, _, wire_b) = port(2);
    let (c, _, wire_c) = port(3);
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
            RouterPort {
                transport: c,
                network_number: 3000,
            },
        ],
        options,
    )
    .await
    .unwrap();
    (started, frames, [wire_a, wire_b, wire_c])
}

/// `REQUEST` for station 7 on `network`, from station 9 on network 1000.
async fn send_to(frames: &mpsc::Sender<ReceivedNpdu>, network: u16) {
    let npdu = Npdu {
        destination: Some(address(network, STATION)),
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
}

async fn sent(wire: &mut WireReceiver) -> (Npdu, Vec<u8>) {
    let (bytes, peer) = tokio::time::timeout(Duration::from_secs(1), wire.recv())
        .await
        .unwrap()
        .unwrap();
    (decode_npdu(bytes).unwrap(), peer)
}

#[tokio::test]
async fn a_port_started_not_forwarding_is_not_routed_to() {
    let (started, frames, [mut wire_a, mut wire_b, mut wire_c]) =
        router(RouterOptions::new().not_forwarding(3000)).await;

    send_to(&frames, 2000).await;
    let (relayed, peer) = sent(&mut wire_b).await;
    assert_eq!(
        (relayed.payload.as_ref(), peer.as_slice()),
        (REQUEST, STATION)
    );

    send_to(&frames, 3000).await;
    let (reject, peer) = sent(&mut wire_a).await;
    assert_eq!(peer, [9]);
    assert_eq!(
        reject.message_type,
        Some(NetworkMessageType::REJECT_MESSAGE_TO_NETWORK)
    );
    // Reason 1, not directly connected, for network 3000.
    assert_eq!(reject.payload.as_ref(), [1, 0x0B, 0xB8]);
    assert!(wire_c.try_recv().is_err(), "nothing reaches network 3000");

    drop(started);
}

#[tokio::test]
async fn a_port_set_forwarding_is_routed_to() {
    let (started, frames, [_, _, mut wire_c]) =
        router(RouterOptions::new().not_forwarding(3000)).await;

    started.router.set_forwarding(3000, true).unwrap();
    send_to(&frames, 3000).await;

    let (relayed, peer) = sent(&mut wire_c).await;
    assert_eq!(
        (relayed.payload.as_ref(), peer.as_slice()),
        (REQUEST, STATION)
    );
}

#[tokio::test]
async fn a_network_no_port_is_on_is_refused() {
    let (a, _, _) = port(1);
    let (b, _, _) = port(2);
    let ports = vec![
        RouterPort {
            transport: a,
            network_number: 1000,
        },
        RouterPort {
            transport: b,
            network_number: 2000,
        },
    ];
    assert!(
        BACnetRouter::start(ports, RouterOptions::new().not_forwarding(4000))
            .await
            .is_err()
    );

    let (started, _, _) = router(RouterOptions::new()).await;
    assert!(started.router.set_forwarding(4000, false).is_err());
}
