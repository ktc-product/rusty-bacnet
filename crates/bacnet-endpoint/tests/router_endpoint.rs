//! A Device that routes: one session on three networks through
//! [`RouterEndpointBuilder`], with a session on the far side of each port.
//!
//! Network 1 is the router endpoint's own link, with node A on it. Networks
//! 2 and 3 are trunks, each with a node at station 5: B on 2, C on 3.

use std::time::Duration;

use bacnet_endpoint::router::RouterEndpointBuilder;
use bacnet_endpoint::session::{EndpointSession, SessionConfig, SessionRole};
use bacnet_endpoint::{DeviceIdentity, EndpointApduDestination};
use bacnet_transport::loopback::LoopbackTransport;
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::error::Error;
use bacnet_types::primitives::ObjectIdentifier;
use bacnet_types::MacAddr;

const ROUTER_MAC: u8 = 0x01;
const NODE_A: u8 = 0x0A;
const STATION: u8 = 0x05;

const ROUTER_DEVICE: u32 = 100;
const A_DEVICE: u32 = 200;
const B_DEVICE: u32 = 300;
const C_DEVICE: u32 = 400;

fn config() -> SessionConfig {
    SessionConfig {
        queue_capacity: 16,
        apdu_timeout_ms: 500,
        apdu_retries: 0,
        ..SessionConfig::default()
    }
}

/// A plain session on the far side of one router port.
fn node(transport: LoopbackTransport, device: u32) -> EndpointSession<LoopbackTransport> {
    EndpointSession::new(transport, SessionRole::Both, config())
        .unwrap()
        .device(DeviceIdentity::new(device, 42).unwrap())
}

struct Site {
    router: EndpointSession<LoopbackTransport>,
    a: EndpointSession<LoopbackTransport>,
    b: EndpointSession<LoopbackTransport>,
    c: EndpointSession<LoopbackTransport>,
}

/// The router endpoint and its three nodes, started; trunk 2 forwards when
/// `forwarding` says so, trunk 3 never does.
async fn site(forwarding: bool) -> Site {
    let (home, a) = LoopbackTransport::pair(vec![ROUTER_MAC], vec![NODE_A]);
    let (trunk_2, b) = LoopbackTransport::pair(vec![ROUTER_MAC], vec![STATION]);
    let (trunk_3, c) = LoopbackTransport::pair(vec![ROUTER_MAC], vec![STATION]);
    let mut router = RouterEndpointBuilder::new()
        .port(1, home, true)
        .port(2, trunk_2, forwarding)
        .port(3, trunk_3, false)
        .queue_capacity(16)
        .client_timers(500, 0)
        .device(DeviceIdentity::new(ROUTER_DEVICE, 42).unwrap())
        .build_session()
        .unwrap();
    let mut site = Site {
        router: {
            router.start().await.unwrap();
            router
        },
        a: node(a, A_DEVICE),
        b: node(b, B_DEVICE),
        c: node(c, C_DEVICE),
    };
    for session in [&mut site.a, &mut site.b, &mut site.c] {
        session.start().await.unwrap();
    }
    site
}

fn any_device() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::DEVICE, ObjectIdentifier::MAX_INSTANCE).unwrap()
}

/// The Device instance `session` reads at `destination`.
async fn device_at(
    session: &EndpointSession<LoopbackTransport>,
    destination: EndpointApduDestination,
) -> Result<u32, Error> {
    let ack = session
        .client()
        .unwrap()
        .read_property_with_destination(
            destination,
            Vec::new(),
            any_device(),
            PropertyIdentifier::OBJECT_IDENTIFIER,
            None,
        )
        .await?;
    Ok(ack.object_identifier.instance_number())
}

fn direct(mac: u8) -> EndpointApduDestination {
    EndpointApduDestination::Direct {
        destination_mac: MacAddr::from_slice(&[mac]),
    }
}

fn routed(network: u16, mac: u8) -> EndpointApduDestination {
    EndpointApduDestination::Routed {
        destination_network: network,
        destination_mac: MacAddr::from_slice(&[mac]),
        router_mac: MacAddr::from_slice(&[ROUTER_MAC]),
    }
}

#[tokio::test]
async fn a_node_on_the_routers_own_link_reads_its_device() {
    let site = site(false).await;
    assert_eq!(
        device_at(&site.a, direct(ROUTER_MAC)).await.unwrap(),
        ROUTER_DEVICE
    );
}

#[tokio::test]
async fn a_node_on_a_trunk_reads_the_routers_device() {
    let site = site(false).await;
    assert_eq!(
        device_at(&site.b, direct(ROUTER_MAC)).await.unwrap(),
        ROUTER_DEVICE
    );
}

#[tokio::test]
async fn the_router_reads_the_same_station_on_two_trunks_as_two_devices() {
    let site = site(false).await;
    let (on_2, on_3) = tokio::join!(
        device_at(&site.router, routed(2, STATION)),
        device_at(&site.router, routed(3, STATION)),
    );
    assert_eq!((on_2.unwrap(), on_3.unwrap()), (B_DEVICE, C_DEVICE));
}

#[tokio::test]
async fn a_node_reads_a_trunk_device_through_the_router_when_the_trunk_forwards() {
    let site = site(true).await;
    assert_eq!(
        device_at(&site.a, routed(2, STATION)).await.unwrap(),
        B_DEVICE
    );
}

#[tokio::test]
async fn a_trunk_that_does_not_forward_is_not_reachable_through_the_router() {
    let site = site(false).await;
    let read = tokio::time::timeout(
        Duration::from_secs(5),
        device_at(&site.a, routed(2, STATION)),
    )
    .await
    .expect("the read ends on its own timer");
    assert!(read.is_err(), "{read:?}");
}

#[test]
fn a_router_endpoint_needs_a_port() {
    let builder = RouterEndpointBuilder::<LoopbackTransport>::new();
    assert!(builder.build_session().is_err());
}
