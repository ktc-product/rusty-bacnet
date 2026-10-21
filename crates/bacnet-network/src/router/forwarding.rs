//! Turning a port's forwarding on or off while the router runs.

use bacnet_router_core::PortId;
use bacnet_types::error::Error;

use super::actions::drain;
use super::BACnetRouter;

impl BACnetRouter {
    /// Turn forwarding on or off for the port on `network`
    /// ([`RouterOptions::not_forwarding`](super::RouterOptions::not_forwarding)).
    /// When ports route after the change, the startup announcements go out
    /// on them again, so the routers on their networks learn what this one
    /// now reaches.
    pub fn set_forwarding(&self, network: u16, forwarding: bool) -> Result<(), Error> {
        let shared = &*self.shared;
        let port = shared
            .networks
            .iter()
            .position(|&port_network| port_network == network)
            .ok_or_else(|| Error::Encoding(format!("No router port is on network {network}")))?;
        let now = shared.engine.now();
        let mut router = shared.engine.lock();
        // At most 255 ports, so the index fits in a u8.
        router
            .set_port_forwarding(PortId(port as u8), forwarding)
            .map_err(|error| Error::Encoding(error.to_string()))?;
        // Once `stop` has ended the dispatch tasks, there is nothing to
        // announce on.
        if let Some(outputs) = self.outputs.upgrade() {
            drain(&mut router, &[], &outputs.send_txs, now);
        }
        Ok(())
    }
}
