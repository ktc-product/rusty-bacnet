use super::*;

/// One APDU handed to a local-issuance send.
#[derive(Debug, Clone, Copy)]
pub struct IssuedApdu<'a> {
    /// Encoded APDU to wrap in an NPDU.
    pub apdu: &'a [u8],
    /// Local data-link destination.
    pub next_hop: &'a [u8],
    /// Routed NPDU destination (DNET/DADR), when the peer is behind a router.
    pub destination: Option<&'a NpduAddress>,
    /// Whether the NPDU sets the data-expecting-reply flag.
    pub expecting_reply: bool,
    /// Network priority of the NPDU.
    pub priority: NetworkPriority,
}

impl<T: TransportPort> NetworkLayer<T> {
    /// Encode a prompt data-link response after checking both this network
    /// owner and the captured router/direct authority. The caller hands these
    /// bytes to its one-shot DER sender without an intervening await.
    pub fn encode_response_for_handoff(
        &self,
        issued: IssuedApdu<'_>,
        route: &crate::response_route::ResponseRoute,
    ) -> Result<BytesMut, Error> {
        if !self.response_scope.guard().is_open() {
            return Err(Error::Transport(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "response network owner unavailable",
            )));
        }
        route.encode_reply_npdu(
            issued.apdu,
            issued.destination,
            issued.expecting_reply,
            issued.priority,
        )
    }

    /// Seal original-route response issuance before joining owned server work.
    /// Queued writes observe this irreversible seal; writes already started
    /// remain bounded but cannot be retracted. Network stop/drop also seals.
    pub fn seal_responses(&self) {
        self.response_scope.seal();
    }
}

impl<T: TransportPort + 'static> NetworkLayer<T> {
    /// Issue one local unicast operation after encoding its complete NPDU.
    ///
    /// `destination` selects routed NPDU addressing; `next_hop` is always the
    /// local data-link destination. The synchronous callback runs exactly once
    /// after encoding succeeds, immediately before calling/polling the transport
    /// send. Constructing this future does not call it. Encoding failure never
    /// calls it; later transport failure does not undo issuance. This boundary
    /// does not establish physical emission or remote receipt. A `destination`
    /// on network 0 or 0xFFFF is an encoding failure: this unicast reaches
    /// one next hop, and a global broadcast goes out through
    /// [`NetworkLayer::broadcast_global_apdu`] instead (#1380). A
    /// `destination` with no DADR is a remote broadcast, which carries only
    /// an Unconfirmed-Request APDU (Clause 6.3), so any other APDU to it is
    /// an encoding failure too (#1479). With no `destination`, a `next_hop`
    /// that is the link's broadcast or another group address is a local
    /// broadcast as well, but this send takes `next_hop` as given: unlike
    /// [`NetworkLayer::send_apdu`], it doesn't send an Unconfirmed-Request
    /// for one as the link's broadcast, and nothing checks it, since a
    /// response goes back to the MAC its request came from (B/IP refuses a
    /// group address there, #1677).
    ///
    /// Used by server transaction owners whose lifetime ends at local issuance,
    /// independently of the transport future's eventual Result.
    pub async fn send_apdu_on_issuance(
        &self,
        apdu: &[u8],
        next_hop: &[u8],
        destination: Option<&NpduAddress>,
        expecting_reply: bool,
        priority: NetworkPriority,
        on_issuance: impl FnOnce() + Send,
    ) -> Result<(), Error> {
        crate::response_route::check_response_destination(destination)?;
        if destination.is_some_and(|destination| destination.mac_address.is_empty()) {
            check_broadcast_apdu(apdu, "a destination with no DADR (a remote broadcast)")?;
        }
        let bytes = crate::response_route::encode_checked_response_npdu(
            apdu,
            destination,
            expecting_reply,
            priority,
        )?;
        on_issuance();
        self.transport
            .send_unicast_with_data_attributes(&bytes, next_hop, &[])
            .await
    }

    /// Encode and issue a response using its immutable ingress route.
    ///
    /// Router replies use the captured port/peer and addressed source identity;
    /// direct responses require the matching original socket as well. Missing
    /// or retired authority never falls back to ordinary unicast. Router replies
    /// wait for their bounded send queue: cancellation before selection sends
    /// nothing and drops the callback. The callback is owned by that queue and
    /// runs when its transport send starts, with the local issuance contract of
    /// [`Self::send_apdu_on_issuance`]; neither issuance nor success proves receipt.
    pub async fn send_response_apdu_on_issuance(
        &self,
        issued: IssuedApdu<'_>,
        route: &crate::response_route::ResponseRoute,
        on_issuance: impl FnOnce() + Send + 'static,
    ) -> Result<(), Error> {
        let IssuedApdu {
            apdu,
            next_hop,
            destination,
            expecting_reply,
            priority,
        } = issued;
        crate::response_route::check_response_destination(destination)?;
        if destination.is_some_and(|destination| destination.mac_address.is_empty()) {
            check_broadcast_apdu(apdu, "a destination with no DADR (a remote broadcast)")?;
        }
        let buf = route.encode(apdu, destination, expecting_reply, priority)?;
        let direct = route.direct()?;
        if let Some(router) = route.router() {
            return router
                .reply(buf, priority, direct, &self.response_scope, on_issuance)
                .await;
        }
        on_issuance();
        if let Some(direct) = direct {
            return direct.send(&buf, &self.response_scope).await;
        }
        self.transport
            .send_unicast_with_data_attributes(&buf, next_hop, &[])
            .await
    }
}
