//! Ports that don't forward (`PortConfig::forwarding`): a router relays only
//! between ports that route, answers and announces only their networks, and
//! on the others takes only its own traffic and what it learns from.

mod fixture;

use bacnet_router_core::message::RoutingEntries;
use bacnet_router_core::npdu::{Address, NetworkMessageType, Npdu, RejectMessageReason};
use bacnet_router_core::router::{
    Discard, ForwardingError, Options, OriginateError, PortConfig, Request,
};
use bacnet_router_core::PortId;
use fixture::{
    addr, apdu_to, at, bytes, deliver, deliver_broadcast, drain, i_am, listed, message, port_on,
    reject_data, router_with, sent_reject, Outcome, Recorder, TestRouter, CONFIRMED, NODE_A, OWN_0,
    OWN_1, UNCONFIRMED,
};

/// A station on a trunk.
const STATION: &[u8] = &[0x05];
/// A router on trunk B.
const TRUNK_ROUTER: &[u8] = &[0x09];

/// B/IP on network 1 (port 0), trunk A on network 2 (port 1) and trunk B on
/// network 3 (port 2), with forwarding as `forwarding` gives for each.
fn router(forwarding: [bool; 3]) -> TestRouter {
    let mut ports: [PortConfig; 3] = [port_on(1, OWN_0), port_on(2, OWN_1), port_on(3, &[0x33])];
    for (port, forwards) in ports.iter_mut().zip(forwarding) {
        port.forwarding = forwards;
    }
    router_with(&ports, Options::HOSTED)
}

fn who_is_router() -> Vec<u8> {
    message(NetworkMessageType::WHO_IS_ROUTER_TO_NETWORK, &[])
}

#[test]
fn traffic_is_relayed_only_between_ports_that_route() {
    let mut router = router([true, true, false]);
    let mut host = Recorder::default();

    let (outcome, sent) = deliver(
        &mut router,
        &mut host,
        0,
        NODE_A,
        &apdu_to(2, STATION, CONFIRMED),
        at(1),
    );
    assert_eq!(outcome, Outcome::Handled);
    assert_eq!(sent.len(), 1);
    assert_eq!((sent[0].port, sent[0].to.as_deref()), (1, Some(STATION)));

    let (outcome, sent) = deliver(
        &mut router,
        &mut host,
        0,
        NODE_A,
        &apdu_to(3, STATION, CONFIRMED),
        at(1),
    );
    assert_eq!(outcome, Outcome::Handled);
    assert_eq!(sent.len(), 1);
    assert_eq!((sent[0].port, sent[0].to.as_deref()), (0, Some(NODE_A)));
    assert_eq!(
        sent_reject(&sent[0]),
        (RejectMessageReason::NOT_DIRECTLY_CONNECTED, 3, None)
    );

    let mut global = Npdu::apdu(UNCONFIRMED);
    global.destination = Some(addr(0xFFFF, &[]));
    let (_, sent) = deliver_broadcast(&mut router, &mut host, 0, NODE_A, &bytes(&global), at(1));
    assert_eq!(sent.iter().map(|sent| sent.port).collect::<Vec<_>>(), [1]);
}

#[test]
fn a_port_that_does_not_route_keeps_a_nodes_rules() {
    let mut router = router([true, true, false]);
    let mut host = Recorder::default();

    let (outcome, sent) = deliver(
        &mut router,
        &mut host,
        2,
        STATION,
        &bytes(&Npdu::apdu(CONFIRMED)),
        at(1),
    );
    assert!(matches!(outcome, Outcome::Local { .. }), "{outcome:?}");
    assert!(sent.is_empty());

    for frame in [apdu_to(1, NODE_A, CONFIRMED), who_is_router()] {
        let (outcome, sent) = deliver_broadcast(&mut router, &mut host, 2, STATION, &frame, at(1));
        assert_eq!(outcome, Outcome::Discarded(Discard::NotRouted));
        assert!(sent.is_empty());
    }
    assert_eq!(router.counters().not_routed, 2);
}

#[test]
fn answers_and_announcements_leave_out_a_port_that_does_not_route() {
    let mut router = router([true, true, false]);
    let mut host = Recorder::default();

    router.start();
    let announced = drain(&mut router);
    assert!(announced.iter().all(|sent| sent.port != 2), "{announced:?}");
    let i_am = |port| {
        announced
            .iter()
            .find(|sent| {
                sent.port == port
                    && sent.parsed().message_type
                        == Some(NetworkMessageType::I_AM_ROUTER_TO_NETWORK)
            })
            .map(listed)
    };
    assert_eq!(i_am(0), Some(vec![2]));
    assert_eq!(i_am(1), Some(vec![1]));

    let (_, sent) = deliver_broadcast(&mut router, &mut host, 0, NODE_A, &who_is_router(), at(1));
    assert_eq!(sent.len(), 1);
    assert_eq!(listed(&sent[0]), [2]);

    let for_3 = message(
        NetworkMessageType::WHO_IS_ROUTER_TO_NETWORK,
        &3u16.to_be_bytes(),
    );
    let (_, sent) = deliver_broadcast(&mut router, &mut host, 0, NODE_A, &for_3, at(1));
    assert!(sent.is_empty(), "{sent:?}");

    let query = message(NetworkMessageType::INITIALIZE_ROUTING_TABLE, &[0]);
    let (_, sent) = deliver(&mut router, &mut host, 0, NODE_A, &query, at(1));
    let networks: Vec<u16> = RoutingEntries::parse(sent[0].parsed().payload)
        .unwrap()
        .iter()
        .map(|entry| entry.network)
        .collect();
    assert_eq!(networks, [1, 2]);
}

/// An I-Am-Router on a port that doesn't route teaches the router the
/// network behind it, for its own requests, but is passed on to no one and
/// put in no answer.
#[test]
fn a_port_that_does_not_route_is_learned_from_but_never_relayed() {
    let mut router = router([true, true, false]);
    let mut host = Recorder::default();

    let (outcome, sent) =
        deliver_broadcast(&mut router, &mut host, 2, TRUNK_ROUTER, &i_am(&[44]), at(1));
    assert_eq!(outcome, Outcome::Handled);
    assert!(sent.is_empty(), "{sent:?}");

    let (_, sent) = deliver_broadcast(&mut router, &mut host, 0, NODE_A, &who_is_router(), at(1));
    assert_eq!(listed(&sent[0]), [2]);

    let request = Request::new(
        Address {
            network: 44,
            mac: STATION,
        },
        CONFIRMED,
    );
    router.originate(&request, at(1)).unwrap();
    let sent = drain(&mut router);
    assert_eq!(sent.len(), 1);
    assert_eq!(
        (sent[0].port, sent[0].to.as_deref()),
        (2, Some(TRUNK_ROUTER))
    );
}

/// The router's own request to a network it has no route for sends its
/// Who-Is-Router out every port, ones that don't route included, as a node
/// may: routing off or not, it can find the routers on any of its networks.
#[test]
fn the_routers_own_search_goes_out_every_port() {
    for forwarding in [[true, true, false], [true, false, false]] {
        let mut router = router(forwarding);
        let request = Request::new(
            Address {
                network: 44,
                mac: STATION,
            },
            CONFIRMED,
        );

        assert_eq!(
            router.originate(&request, at(1)),
            Err(OriginateError::NoRoute)
        );
        let ports: Vec<u8> = drain(&mut router).iter().map(|sent| sent.port).collect();
        assert_eq!(ports, [0, 1, 2], "{forwarding:?}");
    }
}

/// A network message the router learns from, arriving on a port that
/// doesn't route but addressed to another network, is neither routed nor
/// answered with a reject.
#[test]
fn a_message_for_another_network_on_a_port_that_does_not_route_draws_nothing() {
    let mut router = router([true, true, false]);
    let mut host = Recorder::default();
    let data = [0, 44];
    let mut i_am = Npdu::message(NetworkMessageType::I_AM_ROUTER_TO_NETWORK, &data);
    i_am.destination = Some(addr(9, NODE_A));

    let (outcome, sent) = deliver(
        &mut router,
        &mut host,
        2,
        TRUNK_ROUTER,
        &bytes(&i_am),
        at(1),
    );

    assert_eq!(outcome, Outcome::Discarded(Discard::NotRouted));
    assert!(sent.is_empty(), "{sent:?}");
}

/// A reply on a port that doesn't route, addressed to the router on another
/// of its networks, as one to a request it sent from that port's address
/// is, reaches the router's own application, a reject as well as an APDU.
#[test]
fn a_reply_to_the_routers_address_on_another_network_reaches_it() {
    let mut router = router([true, true, false]);
    let mut host = Recorder::default();

    let (outcome, sent) = deliver(
        &mut router,
        &mut host,
        2,
        TRUNK_ROUTER,
        &apdu_to(2, OWN_1, CONFIRMED),
        at(1),
    );
    assert!(matches!(outcome, Outcome::Local { .. }), "{outcome:?}");
    assert!(sent.is_empty(), "{sent:?}");

    let data = reject_data(RejectMessageReason::NOT_DIRECTLY_CONNECTED, 44);
    let mut reject = Npdu::message(NetworkMessageType::REJECT_MESSAGE_TO_NETWORK, &data);
    reject.destination = Some(addr(2, OWN_1));
    let (outcome, sent) = deliver(
        &mut router,
        &mut host,
        2,
        TRUNK_ROUTER,
        &bytes(&reject),
        at(1),
    );
    assert!(matches!(outcome, Outcome::ToRouter(_)), "{outcome:?}");
    assert!(sent.is_empty(), "{sent:?}");
}

/// A reject for a device behind a port that doesn't route isn't passed on to it.
#[test]
fn a_reject_for_a_port_that_does_not_route_is_not_passed_on() {
    let mut router = router([true, true, false]);
    let mut host = Recorder::default();
    let data = reject_data(RejectMessageReason::NOT_DIRECTLY_CONNECTED, 44);
    let mut reject = Npdu::message(NetworkMessageType::REJECT_MESSAGE_TO_NETWORK, &data);
    reject.destination = Some(addr(3, STATION));

    let (outcome, sent) = deliver(&mut router, &mut host, 0, NODE_A, &bytes(&reject), at(1));

    assert_eq!(outcome, Outcome::Discarded(Discard::NotRouted));
    assert!(sent.is_empty(), "{sent:?}");
}

/// One forwarding port has nowhere to route to, so the router routes
/// nothing: it announces nothing, answers no router message and drops
/// traffic for other networks (BTL §2.1 tests 10.6.1-10.6.3).
#[test]
fn with_one_forwarding_port_the_router_routes_nothing() {
    let mut router = router([true, false, false]);
    let mut host = Recorder::default();

    router.start();
    assert!(drain(&mut router).is_empty());

    for frame in [apdu_to(2, STATION, CONFIRMED), who_is_router()] {
        let (outcome, sent) = deliver_broadcast(&mut router, &mut host, 0, NODE_A, &frame, at(1));
        assert_eq!(outcome, Outcome::Discarded(Discard::NotRouted));
        assert!(sent.is_empty());
    }
}

#[test]
fn turning_a_port_on_announces_it_and_relays_to_it() {
    let mut router = router([true, true, false]);
    let mut host = Recorder::default();

    router.set_port_forwarding(PortId(2), true).unwrap();
    let announced = drain(&mut router);
    assert!(announced.iter().any(|sent| {
        sent.port == 0
            && sent.parsed().message_type == Some(NetworkMessageType::I_AM_ROUTER_TO_NETWORK)
            && listed(sent) == [2, 3]
    }));

    let (_, sent) = deliver(
        &mut router,
        &mut host,
        0,
        NODE_A,
        &apdu_to(3, STATION, CONFIRMED),
        at(1),
    );
    assert_eq!(sent.len(), 1);
    assert_eq!((sent[0].port, sent[0].to.as_deref()), (2, Some(STATION)));

    assert_eq!(
        router.set_port_forwarding(PortId(3), true),
        Err(ForwardingError::UnknownPort)
    );
}
