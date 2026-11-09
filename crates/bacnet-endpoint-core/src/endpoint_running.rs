//! What a started endpoint's session task sends and receives through: one
//! link's network layer, or a router whose own application the endpoint is.
use super::*;

/// What a started [`NetworkService`] hands the session task and the egress.
pub(super) struct Started<T: TransportPort> {
    pub(super) running: Running<T>,
    pub(super) apdu_rx: Incoming,
    /// Every control the layer receives, for the [`ControlTee`].
    pub(super) layer_controls:
        Option<mpsc::Receiver<bacnet_network::layer::ReceivedNetworkControl>>,
    /// The tee's sender to the endpoint's Number owner.
    pub(super) numbers: Option<mpsc::Sender<bacnet_network::layer::ReceivedNetworkControl>>,
    /// The endpoint's Number owner's receiver.
    pub(super) controls: Option<mpsc::Receiver<bacnet_network::layer::ReceivedNetworkControl>>,
    pub(super) bip_port: Option<(bacnet_transport::port::BipPort, u16)>,
    pub(super) bip6_port: Option<(bacnet_transport::port::Bip6Port, u16)>,
    pub(super) bip_local_address: Option<std::net::SocketAddrV4>,
    pub(super) bip_broadcast_endpoint: Option<std::net::SocketAddrV4>,
    pub(super) local_mac: MacAddr,
    pub(super) local_network: bacnet_network::network_number::LocalNetworkNumber,
    pub(super) group_destinations: bacnet_transport::port::GroupDestinations,
}

/// What the session task sends and receives through.
pub(super) enum Running<T: TransportPort> {
    /// One link's layer, which a seat shares.
    Link(Arc<NetworkLayer<T>>),
    Router(Box<router::RouterService>),
}

impl<T: TransportPort + 'static> Running<T> {
    /// The endpoint's local network number, once known.
    pub(super) fn local_network(&self) -> Option<u16> {
        match self {
            Self::Link(network) => network.local_network_number().get(),
            Self::Router(router) => Some(router.home_network()),
        }
    }

    /// `received` as the endpoint's roles see it
    /// ([`router::RouterService::delivered`] for a router).
    pub(super) fn delivered(&self, received: ReceivedApdu) -> ReceivedApdu {
        match self {
            Self::Link(_) => received,
            Self::Router(router) => router.delivered(received),
        }
    }

    /// Whether `received` came from a link-layer address that is a group
    /// destination where it arrived.
    pub(super) fn is_group_source(&self, received: &ReceivedApdu) -> bool {
        match self {
            Self::Link(network) => network
                .transport()
                .is_group_destination(&received.source_mac),
            Self::Router(router) => router.is_group_source(received),
        }
    }

    pub(super) async fn send(
        &self,
        payload: &NetworkServicePayload,
        response_route: Option<&ResponseRoute>,
        destination: &EndpointApduDestination,
        expecting_reply: bool,
        priority: NetworkPriority,
        data_attributes: &[DataAttribute],
    ) -> Result<(), Error> {
        match self {
            Self::Link(network) => {
                send_on_link(
                    network,
                    payload,
                    response_route,
                    destination,
                    expecting_reply,
                    priority,
                    data_attributes,
                )
                .await
            }
            Self::Router(router) => {
                router
                    .send(
                        payload,
                        response_route,
                        destination,
                        expecting_reply,
                        priority,
                        data_attributes,
                    )
                    .await
            }
        }
    }

    pub(super) async fn stop(&mut self) -> Result<(), Error> {
        match self {
            Self::Link(network) => network.stop().await,
            Self::Router(router) => router.stop().await,
        }
    }
}

/// Where the session task receives APDUs from.
pub(super) enum Incoming {
    Link(bacnet_network::layer::ApduReceiver),
    Router(mpsc::Receiver<ReceivedApdu>),
}

impl Incoming {
    /// Poll for the next APDU, `None` once the source is closed.
    pub(super) fn poll_recv(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<ReceivedApdu>> {
        match self {
            Self::Link(apdus) => apdus.poll_recv(cx),
            Self::Router(apdus) => apdus.poll_recv(cx),
        }
    }
}

/// One send through a link's network layer.
async fn send_on_link<T: TransportPort + 'static>(
    network: &NetworkLayer<T>,
    payload: &NetworkServicePayload,
    response_route: Option<&ResponseRoute>,
    destination: &EndpointApduDestination,
    expecting_reply: bool,
    priority: NetworkPriority,
    data_attributes: &[DataAttribute],
) -> Result<(), Error> {
    match payload {
        NetworkServicePayload::Apdu(apdu) => {
            if let Some(route) = response_route {
                let (next_hop, destination) = match destination {
                    EndpointApduDestination::Direct { destination_mac } => (destination_mac, None),
                    EndpointApduDestination::Routed {
                        destination_network,
                        destination_mac,
                        router_mac,
                    } => (
                        router_mac,
                        Some(bacnet_encoding::npdu::NpduAddress {
                            network: *destination_network,
                            mac_address: destination_mac.clone(),
                        }),
                    ),
                    _ => {
                        return Err(Error::Encoding(
                            "response requires a unicast destination".into(),
                        ));
                    }
                };
                network
                    .send_response_apdu_on_issuance(
                        IssuedApdu {
                            apdu,
                            next_hop,
                            destination: destination.as_ref(),
                            expecting_reply,
                            priority,
                        },
                        route,
                        || {},
                    )
                    .await
            } else {
                send_network_service_apdu(
                    network,
                    apdu,
                    destination,
                    expecting_reply,
                    priority,
                    data_attributes,
                )
                .await
            }
        }
        NetworkServicePayload::LocalControl(npdu) => network.transport().send_broadcast(npdu).await,
    }
}
