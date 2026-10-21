//! A received frame, from its link source to the decision on its APDU.

use super::config::{closed, routes, Options};
use super::counters::bump;
use super::host::Host;
use super::tasks::Task;
use super::Group;
use super::Storage;
pub(super) use crate::node::is_unconfirmed;
use crate::node::{admit, for_this_node};
use crate::npdu::{Address, AddressField, Malformed, NetworkPriority, Npdu, GLOBAL_NETWORK};
use crate::npdu::{NetworkMessageType, RejectMessageReason};
use crate::table::{Reachability, Route};
use crate::{Instant, Mac, PortId};

/// A frame a port received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'f> {
    /// The port.
    pub port: PortId,
    /// The link-layer source address. For a B/IP Forwarded-NPDU it is the
    /// origin the BBMD names, so the SADR the router adds names the origin.
    pub source: &'f [u8],
    /// Whether it arrived as a link-layer broadcast or multicast.
    pub link_group: bool,
    /// The NPDU.
    pub npdu: &'f [u8],
}

/// What a frame means for the router itself. It borrows the frame, not the
/// router, so the caller can poll the actions the frame also prompted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a frame may be for the router's own application"]
pub enum Received<'f> {
    /// An APDU for the router's own application entity, if it has one. It
    /// may come with sends: a global broadcast, or a DLEN 0 broadcast on
    /// the arrival network, is also passed on.
    Local(Local<'f>),
    /// A reject addressed to the router: for its network-control consumer,
    /// if it has one. The table has already taken it.
    ToRouter(Npdu<'f>),
    /// Routed, answered, relayed or taken into the table: see the actions.
    Handled,
    /// Discarded, and counted, for this reason.
    Discarded(Discard),
}

/// An APDU for the router's own application entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Local<'f> {
    /// The APDU.
    pub apdu: &'f [u8],
    /// Where it starts in the frame's NPDU, so a host can slice its own
    /// buffer.
    pub apdu_offset: usize,
    /// SNET and SADR, when a router relayed it.
    pub source: Option<Address<'f>>,
    /// Whether it was sent to a group: a link broadcast with no DNET, a
    /// DLEN 0 broadcast, or a global broadcast.
    pub group: bool,
    /// Whether it was a global broadcast.
    pub global: bool,
    /// Whether its sender expects a reply.
    pub expecting_reply: bool,
    /// Its network priority.
    pub priority: NetworkPriority,
    /// Owned return route and explicitly addressed local source, if any.
    pub reply: super::ReplyPlan,
}

/// Why a frame was discarded. Each reason the router gives has its count
/// in its [`Counters`](super::Counters); a node counts
/// [`NotRouted`](Self::NotRouted) in its own
/// [`Counters`](crate::node::Counters).
///
/// It is `#[non_exhaustive]`, so a new reason isn't a breaking change: a
/// `match` needs a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Discard {
    /// It came on a port the router doesn't have, or its route names one
    /// (a route written through [`Router::table_mut`](super::Router::table_mut)).
    UnknownPort,
    /// Its link source is longer than [`MAX_MAC_LEN`](crate::MAX_MAC_LEN)
    /// (#1198). Nothing is sent back to such a source.
    SourceTooLong {
        /// The source's length.
        length: usize,
    },
    /// A DLEN or SLEN past [`MAX_MAC_LEN`](crate::MAX_MAC_LEN) (#1141).
    /// With a DNET other than 0xFFFF, reject reason 6 is queued.
    AddressTooLong {
        /// Which address.
        field: AddressField,
        /// Its length octet.
        length: u8,
    },
    /// It isn't an NPDU.
    Malformed(Malformed),
    /// A DADR beside DNET 0xFFFF (#1379).
    GlobalWithDadr,
    /// A broadcast whose APDU isn't an Unconfirmed-Request (#1491).
    BroadcastNotUnconfirmed,
    /// For a DADR that is a group address on its delivery port: an APDU
    /// other than an Unconfirmed-Request, a network message, or anything
    /// for a [`Group::Refuse`] address ([`Group`]; #1504, #1677).
    GroupDadr,
    /// Its hop count had run out.
    HopCount,
    /// [`Host::authorize`] refused it.
    Denied,
    /// A network message whose data, or whose addressing, its type doesn't
    /// allow.
    BadMessage,
    /// A received reject that isn't for this router and has nowhere to go:
    /// its DNET is 0xFFFF or the arrival network, or has no route.
    Unroutable,
    /// Its rewrite can't be written: longer than the scratch, or with a
    /// field no NPDU may carry, such as an SNET of 0.
    Unwritable,
    /// A global broadcast seen within the duplicate time to live
    /// ([`Options::duplicates`](super::Options::duplicates), #1698):
    /// neither relayed nor delivered.
    Duplicate,
    /// An NPDU whose DNET names one network is for a device elsewhere, which
    /// a [`Node`](crate::node::Node) drops (Clauses 6.5.2.1, 6.5.2.2 and
    /// 6.5.4). A router drops it too on a port that doesn't route
    /// ([`PortConfig::forwarding`](super::PortConfig::forwarding)), with any
    /// network message there.
    NotRouted,
}

/// Whether the router takes a network message of `kind` on a port that
/// doesn't route: the ones it learns routes, their state or the port's
/// network number from. It answers none of them.
fn learned_on_a_closed_port(kind: NetworkMessageType) -> bool {
    matches!(
        kind,
        NetworkMessageType::I_AM_ROUTER_TO_NETWORK
            | NetworkMessageType::REJECT_MESSAGE_TO_NETWORK
            | NetworkMessageType::ROUTER_BUSY_TO_NETWORK
            | NetworkMessageType::ROUTER_AVAILABLE_TO_NETWORK
            | NetworkMessageType::NETWORK_NUMBER_IS
    )
}

/// What the router knows about the frame in hand.
#[derive(Debug, Clone, Copy)]
pub(super) struct Arrival<'f> {
    /// The arrival port.
    pub(super) port: PortId,
    /// Its network.
    pub(super) network: u16,
    /// The link source.
    pub(super) source: &'f [u8],
    /// The same, stored.
    pub(super) source_mac: Mac,
    /// Whether it was a link broadcast or multicast.
    pub(super) link_group: bool,
    /// The time.
    pub(super) now: Instant,
}

/// The local delivery of `npdu`'s APDU.
fn local<'f>(at: &Arrival<'_>, npdu: &Npdu<'f>, group: bool, global: bool) -> Local<'f> {
    Local {
        apdu: npdu.payload,
        apdu_offset: npdu.payload_offset,
        source: npdu.source,
        group,
        global,
        expecting_reply: npdu.expecting_reply,
        priority: npdu.priority,
        reply: super::ReplyPlan::new(
            at.port,
            at.source,
            (!group).then_some(npdu.destination).flatten(),
            npdu.source,
        )
        .expect("local delivery has valid bounded node addresses"),
    }
}

impl<
        const P: usize,
        const R: usize,
        const H: usize,
        const D: usize,
        const N: usize,
        G: super::GroupClassifier,
        const B: usize,
    > Storage<P, R, H, D, N, G, B>
{
    /// [`Router::receive`](super::Router::receive).
    pub(super) fn receive<'f>(
        &mut self,
        frame: Frame<'f>,
        now: Instant,
        options: &Options,
        host: &mut impl Host,
    ) -> Received<'f> {
        self.drop_undrained();
        let Some(config) = self.ports[..self.port_count].get(usize::from(frame.port.0)) else {
            bump(&mut self.counters.unknown_port);
            return Received::Discarded(Discard::UnknownPort);
        };
        // The checks a node makes too, in one place (crate::node).
        let admitted = match admit(frame.source, frame.npdu) {
            Ok(admitted) => admitted,
            Err(refused) => {
                bump(self.counters.slot(refused.count));
                // A global broadcast draws no reject, and an NPDU without a
                // DNET has no network to name.
                if let Some((source_mac, Some(dnet), source)) = refused.reject_to {
                    if dnet != GLOBAL_NETWORK {
                        let at = Arrival {
                            port: frame.port,
                            network: config.network,
                            source: frame.source,
                            source_mac,
                            link_group: frame.link_group,
                            now,
                        };
                        self.reject(
                            &at,
                            source,
                            dnet,
                            RejectMessageReason::ADDRESSING_ERROR,
                            host,
                        );
                    }
                }
                return Received::Discarded(refused.discard);
            }
        };
        let npdu = admitted.npdu;
        let at = Arrival {
            port: frame.port,
            network: config.network,
            source: frame.source,
            source_mac: admitted.source,
            link_group: frame.link_group,
            now,
        };
        if !self.routes(frame.port) {
            return self.receive_closed(&at, &npdu, options, host);
        }
        if let Some(kind) = npdu.message_type {
            return self.network_message(&at, &npdu, kind, options, host);
        }
        self.route_apdu(&at, &npdu, options, host)
    }

    /// Whether `port` routes ([`PortConfig::forwarding`](super::PortConfig::forwarding)).
    pub(super) fn routes(&self, port: PortId) -> bool {
        routes(
            &self.ports[..self.port_count],
            self.forwarding_ports,
            usize::from(port.0),
        )
    }

    /// Whether the port at `index` doesn't route, among the ports the
    /// router has.
    pub(super) fn closed(&self, index: usize) -> bool {
        closed(&self.ports[..self.port_count], self.forwarding_ports, index)
    }

    /// A frame on a port that doesn't route. An APDU with no DNET, or a
    /// global broadcast, is the router's own application's and goes no
    /// further, as is one addressed to the router on any of its networks: a
    /// reply to a request it sent from another port's address. A network
    /// message the router learns from is taken as on any port when it is
    /// for this network, and a reject also when it is addressed to the
    /// router; what either would pass on goes nowhere ([`Self::forward`]
    /// and the fan-outs leave such a port out). One for another network is
    /// never routed, nor answered with a reject. Anything else is dropped.
    fn receive_closed<'f>(
        &mut self,
        at: &Arrival<'f>,
        npdu: &Npdu<'f>,
        options: &Options,
        host: &mut impl Host,
    ) -> Received<'f> {
        let for_this_network = npdu.destination.is_none_or(|destination| {
            destination.network == GLOBAL_NETWORK || destination.network == at.network
        });
        let to_the_router = npdu
            .destination
            .is_some_and(|destination| !destination.mac.is_empty() && self.is_own(destination));
        match (for_this_node(npdu), npdu.message_type) {
            (Some(global), None) => {
                Received::Local(local(at, npdu, global || at.link_group, global))
            }
            (None, None) if to_the_router => Received::Local(local(at, npdu, false, false)),
            (_, Some(kind))
                if (for_this_network && learned_on_a_closed_port(kind))
                    || (to_the_router && kind == NetworkMessageType::REJECT_MESSAGE_TO_NETWORK) =>
            {
                self.network_message(at, npdu, kind, options, host)
            }
            _ => {
                bump(&mut self.counters.not_routed);
                Received::Discarded(Discard::NotRouted)
            }
        }
    }

    /// Deliver or route an APDU by its DNET.
    fn route_apdu<'f>(
        &mut self,
        at: &Arrival<'f>,
        npdu: &Npdu<'f>,
        options: &Options,
        host: &mut impl Host,
    ) -> Received<'f> {
        let Some(destination) = npdu.destination else {
            return Received::Local(local(at, npdu, at.link_group, false));
        };
        if destination.network == GLOBAL_NETWORK {
            if let Some(duplicates) = options.duplicates {
                // Keyed by its origin: the SNET and SADR it carries, or
                // those a relay would add.
                let (network, source) = npdu.source.map_or((at.network, at.source), |source| {
                    (source.network, source.mac)
                });
                if self
                    .recent
                    .repeat(network, source, npdu.payload, at.now, duplicates.ttl)
                {
                    bump(&mut self.counters.duplicate_drops);
                    return Received::Discarded(Discard::Duplicate);
                }
            }
            self.forward_global(at, npdu, host);
            return Received::Local(local(at, npdu, true, true));
        }
        // The router's own address on any of its networks is its own
        // application's, before any route is looked up (Clause 6.1, Figure
        // 6-12). A DLEN 0 broadcast names no one node, so it is never that.
        if !destination.mac.is_empty() && self.is_own(destination) {
            return Received::Local(local(at, npdu, false, false));
        }
        let Some(route) = self.find_route(at, npdu, destination.network, options, host) else {
            return Received::Handled;
        };
        let mut delivered = None;
        if route.port() == at.port && route.is_direct() {
            let own = &self.ports[usize::from(at.port.0)].mac;
            if !destination.mac.is_empty() && *own == *destination.mac {
                return Received::Local(local(at, npdu, false, false));
            }
            // A DLEN 0 broadcast on the arrival network is delivered, and
            // also sent back out the arrival port below, as the hosted
            // router does (group_dadr_tests.rs:96 pins that relay). One at
            // the port's limit is delivered and also draws reason 4, since
            // the relay gains SNET and SADR.
            if destination.mac.is_empty() {
                delivered = Some(local(at, npdu, true, false));
            }
        }
        let mut npdu = *npdu;
        match self.group_of(&route, &npdu) {
            Group::No => {}
            // An Unconfirmed-Request for a group of the port's own goes out
            // as the port's local broadcast: no DADR on a directly attached
            // network. It reaches the router's application where a DLEN 0
            // broadcast would: when it came from that network.
            Group::Broadcast if is_unconfirmed(npdu.payload) => {
                npdu.destination = Some(Address {
                    network: destination.network,
                    mac: &[],
                });
                if route.port() == at.port {
                    delivered = Some(local(at, &npdu, true, false));
                }
            }
            Group::Broadcast | Group::Refuse => return self.group_drop(),
        }
        let forwarded = self.forward(at, &npdu, &route, host);
        delivered.map_or(forwarded, Received::Local)
    }

    /// The usable route to `dnet`, marked as used; or, when the table has
    /// none or can't use it now, `None`, with the search and the reject
    /// that answer the frame queued (Clauses 6.6.3.1, 6.6.3.5, 6.6.3.6).
    /// Nothing is held back for the search: the sender gets reason 1 at
    /// once, and its next message takes whatever route the search finds.
    pub(super) fn find_route(
        &mut self,
        at: &Arrival<'_>,
        npdu: &Npdu<'_>,
        dnet: u16,
        options: &Options,
        host: &mut impl Host,
    ) -> Option<Route> {
        let route = self.table.lookup(dnet);
        let reachability = self.table.effective_reachability(dnet, at.now);
        let Some(route) = route else {
            if self
                .discovery
                .should_solicit(dnet, at.now, options.discovery_cooldown)
            {
                bump(&mut self.counters.solicitations);
                self.out.push(Task::solicit(at.port, dnet));
            }
            self.reject(
                at,
                npdu.source,
                dnet,
                RejectMessageReason::NOT_DIRECTLY_CONNECTED,
                host,
            );
            return None;
        };
        // A network behind a port that doesn't route is one this router
        // doesn't reach, for anyone but its own application.
        if self.closed(usize::from(route.port().0)) {
            self.reject(
                at,
                npdu.source,
                dnet,
                RejectMessageReason::NOT_DIRECTLY_CONNECTED,
                host,
            );
            return None;
        }
        self.table.touch(dnet, at.now);
        let refusal = match reachability {
            Some(Reachability::Busy) => RejectMessageReason::ROUTER_BUSY,
            Some(Reachability::Unreachable) => RejectMessageReason::NOT_DIRECTLY_CONNECTED,
            _ => return Some(route),
        };
        self.reject(at, npdu.source, dnet, refusal, host);
        None
    }

    /// What `npdu`'s DADR is on its delivery port: read from its port only
    /// when `route` hands it to a node on a directly attached port. A DLEN
    /// 0 broadcast, and a DADR beyond another router, are [`Group::No`].
    pub(super) fn group_of(&self, route: &Route, npdu: &Npdu<'_>) -> Group {
        match npdu.destination {
            Some(destination) if route.is_direct() && !destination.mac.is_empty() => {
                // A public table edit can name an absent port. Leave that
                // route to forward's UnknownPort guard, without classifying.
                self.ports[..self.port_count]
                    .get(usize::from(route.port().0))
                    .map_or(Group::No, |port| port.groups.classify(destination.mac))
            }
            _ => Group::No,
        }
    }

    /// Count a frame dropped for a group DADR (#1504, #1677).
    pub(super) fn group_drop<'f>(&mut self) -> Received<'f> {
        bump(&mut self.counters.group_dadr_drops);
        Received::Discarded(Discard::GroupDadr)
    }
}
