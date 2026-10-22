//! The endpoint as a router's own application: a [`BACnetRouter`] sends and
//! receives for it in place of one link's network layer.
use super::*;
use bacnet_network::network_number::LocalNetworkNumber;
use bacnet_network::response_route::ResponseRoute;
use bacnet_network::router::{
    BACnetRouter, OriginateError, OriginateFailure, Path, PortId, Request, RouterOptions,
    RouterPort, StartedRouter,
};
use bacnet_npdu::Address;
use bacnet_transport::port::{DirectResponseScope, GroupDestinations};
use bacnet_types::network_number::NetworkNumber;

/// A router's ports and options, before it starts.
pub(super) struct RouterSetup<T: TransportPort> {
    pub(super) ports: Vec<RouterPort<T>>,
    pub(super) options: RouterOptions,
}

/// What the endpoint keeps of a started router.
pub(super) struct StartedService {
    pub(super) service: RouterService,
    pub(super) apdus: mpsc::Receiver<ReceivedApdu>,
    pub(super) bip_port: Option<(bacnet_transport::port::BipPort, u16)>,
    pub(super) bip_local_address: Option<std::net::SocketAddrV4>,
    pub(super) bip_broadcast_endpoint: Option<std::net::SocketAddrV4>,
    pub(super) local_network: LocalNetworkNumber,
    pub(super) group_destinations: GroupDestinations,
}

impl<T: TransportPort + 'static> RouterSetup<T> {
    /// The endpoint's own link: the first port.
    pub(super) fn home(&self) -> &T {
        &self.ports[0].transport
    }

    pub(super) fn home_mut(&mut self) -> &mut T {
        &mut self.ports[0].transport
    }

    /// Start the router, taking what the endpoint needs of the first port
    /// before its transport moves into the router.
    pub(super) async fn start(self) -> Result<StartedService, Error> {
        let home = &self.ports[0];
        let home_network = home.network_number;
        let bip_port = home
            .transport
            .bip_port()
            .map(|port| (port, home.transport.local_receive_apdu_capacity()));
        let bip_broadcast_endpoint = home.transport.bip_broadcast_endpoint();
        let group_destinations = home.transport.group_destinations();
        let ports = self
            .ports
            .iter()
            .map(|port| (port.network_number, port.transport.group_destinations()))
            .collect();
        let StartedRouter { router, apdus, .. } =
            BACnetRouter::start(self.ports, self.options).await?;
        let bip_local_address = bip_broadcast_endpoint.and_then(|_| {
            let mac = router.local_mac(home_network)?;
            bacnet_transport::bvll::decode_bip_mac(&mac)
                .ok()
                .map(|(ip, port)| std::net::SocketAddrV4::new(ip.into(), port))
        });
        let local_network = LocalNetworkNumber::default();
        // The router refuses a port on network 0 or 0xFFFF, so it is known.
        if let Some(number) = NetworkNumber::configured(home_network) {
            local_network.publish(number);
        }
        Ok(StartedService {
            service: RouterService {
                router,
                home: home_network,
                ports,
                responses: DirectResponseScope::default(),
            },
            apdus,
            bip_port,
            bip_local_address,
            bip_broadcast_endpoint,
            local_network,
            group_destinations,
        })
    }
}

/// A running router whose application the endpoint is.
pub(super) struct RouterService {
    router: BACnetRouter,
    /// The first port's network: the endpoint's own link.
    home: u16,
    /// Each port's network and group rule, in port order.
    ports: Vec<(u16, GroupDestinations)>,
    /// Lifetime of the endpoint's responses; sealed at stop.
    responses: DirectResponseScope,
}

impl RouterService {
    /// `received` as the endpoint's roles see it: an APDU from a station on a
    /// port other than the first, with no SNET, names that port's network
    /// and the station's MAC as its SNET and SADR, as a router between that
    /// network and the endpoint's own would. Every role then keys the
    /// station as a routed peer, which a `Routed` send to that network and
    /// MAC reaches, and one MAC on two ports is two peers.
    pub(super) fn delivered(&self, mut received: ReceivedApdu) -> ReceivedApdu {
        if let (None, Some(network)) = (&received.source_network, received.ingress_network) {
            if network != self.home {
                received.source_network = Some(bacnet_encoding::npdu::NpduAddress {
                    network,
                    mac_address: received.source_mac.clone(),
                });
            }
        }
        received
    }

    /// Whether `received` came from a link-layer address that is a group
    /// destination on its arrival port.
    pub(super) fn is_group_source(&self, received: &ReceivedApdu) -> bool {
        self.ports
            .iter()
            .find(|(network, _)| Some(*network) == received.ingress_network)
            .is_some_and(|(_, groups)| groups.contains(&received.source_mac))
    }

    /// Send one APDU for the endpoint. A response goes back the way its
    /// request came ([`BACnetRouter::send_response_apdu_on_issuance`]);
    /// anything else is originated by the router, by network:
    ///
    /// - `Direct`: to that MAC on the first port's network.
    /// - `Routed`: to the node on one of the router's networks directly;
    ///   otherwise through the named router on the first port, with no table
    ///   lookup ([`Path::Via`]).
    /// - `RoutedViaLocalBroadcast` and `RemoteBroadcast`: by the table.
    /// - `LocalBroadcast`: a local broadcast on every port.
    /// - `GlobalBroadcast`: refused.
    ///
    /// `Ok` means queued on the egress port, not sent. Data attributes and
    /// local network controls are refused: no port here carries the first,
    /// and the router answers network-number queries itself.
    pub(super) async fn send(
        &self,
        payload: &NetworkServicePayload,
        response_route: Option<&ResponseRoute>,
        destination: &EndpointApduDestination,
        expecting_reply: bool,
        priority: NetworkPriority,
        data_attributes: &[DataAttribute],
    ) -> Result<(), Error> {
        let apdu = match payload {
            NetworkServicePayload::Apdu(apdu) => apdu,
            NetworkServicePayload::LocalControl(_) => {
                return Err(Error::Encoding(
                    "a router endpoint sends no local network controls".into(),
                ))
            }
        };
        if let Some(route) = response_route {
            return self
                .router
                .send_response_apdu_on_issuance(
                    apdu,
                    expecting_reply,
                    priority,
                    route,
                    &self.responses,
                    || {},
                )
                .await;
        }
        if !data_attributes.is_empty() {
            return Err(Error::Encoding(
                "a router endpoint's requests carry no data attributes".into(),
            ));
        }
        let home_groups = &self.ports[0].1;
        validate_effective_group_apdu(apdu, destination, |mac| home_groups.contains(mac))?;
        let originate = |network: u16, mac: &[u8], path: Path<'_>| {
            let mut request = Request::new(Address { network, mac }, apdu);
            request.expecting_reply = expecting_reply;
            request.priority = priority;
            request.path = path;
            self.router.originate(&request).map_err(originate_error)
        };
        match destination {
            EndpointApduDestination::Direct { destination_mac } => {
                originate(self.home, destination_mac, Path::Table)
            }
            EndpointApduDestination::Routed {
                destination_network,
                destination_mac,
                router_mac,
            } => {
                let path = if self.is_attached(*destination_network) {
                    Path::Table
                } else {
                    Path::Via {
                        port: PortId(0),
                        router: router_mac,
                    }
                };
                originate(*destination_network, destination_mac, path)
            }
            EndpointApduDestination::RoutedViaLocalBroadcast {
                destination_network,
                destination_mac,
            } => {
                if destination_mac.is_empty() {
                    return Err(Error::Encoding(
                        "a routed unicast needs a DADR; a remote broadcast has its own destination"
                            .into(),
                    ));
                }
                originate(*destination_network, destination_mac, Path::Table)
            }
            EndpointApduDestination::LocalBroadcast => self
                .ports
                .iter()
                .map(|(network, _)| originate(*network, &[], Path::Table))
                .fold(Ok(()), Result::and),
            EndpointApduDestination::RemoteBroadcast {
                destination_network,
            } => originate(*destination_network, &[], Path::Table),
            EndpointApduDestination::GlobalBroadcast => Err(Error::Encoding(
                "a router endpoint sends no global broadcast".into(),
            )),
        }
    }

    /// Whether one of the router's ports is on `network`.
    fn is_attached(&self, network: u16) -> bool {
        self.ports.iter().any(|(port, _)| *port == network)
    }

    /// Seal the endpoint's responses and stop the router.
    pub(super) async fn stop(&mut self) {
        self.responses.seal();
        self.router.stop().await;
    }
}

/// An originate refusal as a transport error that keeps it as its source.
fn originate_error(failure: OriginateFailure) -> Error {
    let kind = match failure {
        OriginateFailure::Refused(OriginateError::NoRoute | OriginateError::Unreachable) => {
            std::io::ErrorKind::NotFound
        }
        OriginateFailure::Refused(OriginateError::Busy) | OriginateFailure::QueueFull => {
            std::io::ErrorKind::WouldBlock
        }
        OriginateFailure::Stopped => std::io::ErrorKind::NotConnected,
        _ => std::io::ErrorKind::InvalidInput,
    };
    Error::Transport(std::io::Error::new(kind, failure))
}
