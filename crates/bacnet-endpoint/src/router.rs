//! Endpoint builder for a Device that routes: one session on several
//! networks at once, with a [`BACnetRouter`] as its network layer.
//!
//! The first [`port`](RouterEndpointBuilder::port) is the endpoint's own
//! link, the one a direct send leaves by and whose network is the
//! endpoint's local network. Each port either forwards, so the router
//! relays between it and the other forwarding ports, or doesn't, so it
//! carries only the endpoint's own traffic
//! ([`RouterOptions::not_forwarding`]). The Device answers on every port.
//!
//! ```no_run
//! use bacnet_endpoint::router::RouterEndpointBuilder;
//! use bacnet_endpoint::session::SessionRole;
//! use bacnet_transport::loopback::LoopbackTransport;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), bacnet_types::error::Error> {
//! let (bip, _bip_peer) = LoopbackTransport::pair(vec![0x01], vec![0x02]);
//! let (trunk, _trunk_peer) = LoopbackTransport::pair(vec![0x01], vec![0x03]);
//! let mut session = RouterEndpointBuilder::new()
//!     .port(1, bip, true)
//!     .port(2, trunk, false)
//!     .role(SessionRole::Both)
//!     .build_session()?;
//! session.start().await?;
//! session.stop().await?;
//! # Ok(())
//! # }
//! ```
//!
//! [`BACnetRouter`]: bacnet_network::router::BACnetRouter

use std::sync::Arc;

use bacnet_endpoint_core::endpoint_ingress::EndpointIngress;
use bacnet_network::router::{RouterOptions, RouterPort};
use bacnet_objects::database::ObjectDatabase;
use bacnet_transport::port::TransportPort;
use bacnet_types::error::Error;
use tokio::sync::RwLock;

use crate::session::{EndpointSession, SessionConfig, SessionDatabase, SessionRole};

/// Builder for an endpoint whose network layer is a router on several
/// ports.
pub struct RouterEndpointBuilder<T: TransportPort + 'static> {
    ports: Vec<RouterPort<T>>,
    options: RouterOptions,
    role: SessionRole,
    session: SessionConfig,
    database: Option<SessionDatabase>,
    identity: Option<crate::identity::DeviceIdentity>,
    device_write_authorizer: Option<bacnet_server::mutation::MutationAuthorizer>,
    reinitialize: Option<bacnet_server::server::ReinitializeHandler>,
    reinit_password: Option<String>,
    file_reads: bool,
    file_writes: bool,
    multiple_reads: bool,
    writes: bool,
    write_observer: Option<bacnet_server::server::PropertyWriteObserver>,
}

impl<T: TransportPort + 'static> Default for RouterEndpointBuilder<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: TransportPort + 'static> RouterEndpointBuilder<T> {
    /// A builder with no ports yet.
    pub fn new() -> Self {
        Self {
            ports: Vec::new(),
            options: RouterOptions::new(),
            role: SessionRole::Both,
            session: SessionConfig::default(),
            database: None,
            identity: None,
            device_write_authorizer: None,
            reinitialize: None,
            reinit_password: None,
            file_reads: false,
            file_writes: false,
            multiple_reads: false,
            writes: false,
            write_observer: None,
        }
    }

    /// Adds a port on `network` over `transport`. The first is the
    /// endpoint's own link. With `forwarding` off the port carries only the
    /// endpoint's own traffic ([`RouterOptions::not_forwarding`]).
    pub fn port(mut self, network: u16, transport: T, forwarding: bool) -> Self {
        self.ports.push(RouterPort {
            transport,
            network_number: network,
        });
        if !forwarding {
            self.options = self.options.not_forwarding(network);
        }
        self
    }

    /// Selects the composed roles (default [`Both`](SessionRole::Both)).
    pub fn role(mut self, role: SessionRole) -> Self {
        self.role = role;
        self
    }

    /// Sets the bounded queue capacity for every ingress/egress queue.
    pub fn queue_capacity(mut self, capacity: usize) -> Self {
        self.session.queue_capacity = capacity;
        self
    }

    /// Sets the server role's read work limit (default 256). See
    /// [`SessionConfig::read_work_limit`].
    pub fn read_work_limit(mut self, limit: usize) -> Self {
        self.session.read_work_limit = limit;
        self
    }

    /// Sets client APDU timeout/retries (session-owned timers).
    pub fn client_timers(mut self, timeout_ms: u64, retries: u8) -> Self {
        self.session.apdu_timeout_ms = timeout_ms;
        self.session.apdu_retries = retries;
        self
    }

    /// Least time between the client role's confirmed requests to one
    /// destination (default 0: no pacing). See
    /// [`SessionConfig::min_request_interval_ms`].
    pub fn min_request_interval_ms(mut self, ms: u64) -> Self {
        self.session.min_request_interval_ms = ms;
        self
    }

    /// Attaches the object database for the server responder.
    pub fn database(mut self, db: ObjectDatabase) -> Self {
        self.database = Some(SessionDatabase::Owned(Box::new(db)));
        self
    }

    /// [`database`](Self::database) for one the caller keeps a handle on, so
    /// a session rebuilt for a new set of ports serves the same objects; see
    /// [`EndpointSession::with_shared_database`].
    pub fn shared_database(mut self, db: Arc<RwLock<ObjectDatabase>>) -> Self {
        self.database = Some(SessionDatabase::Shared(db));
        self
    }

    /// Composes the single Device identity. At start, its requested ceiling
    /// resolves against the smallest APDU any port receives. When it lists
    /// Network Ports, [`build_session`](Self::build_session) requires one per
    /// router port, on that port's network.
    pub fn device(mut self, identity: crate::identity::DeviceIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Enables authorized writes to the local Device's Description and
    /// installed Audit recipient. See [`EndpointSession::with_device_writes`].
    pub fn device_writes(
        mut self,
        authorizer: bacnet_server::mutation::MutationAuthorizer,
    ) -> Self {
        self.device_write_authorizer = Some(authorizer);
        self
    }

    /// Enables ReinitializeDevice. See [`EndpointSession::with_reinitialize`].
    pub fn reinitialize<F>(mut self, handler: F) -> Self
    where
        F: Fn(
                &bacnet_server::server::ReinitializeContext,
                &mut ObjectDatabase,
            ) -> Result<(), Error>
            + Send
            + Sync
            + 'static,
    {
        self.reinitialize = Some(std::sync::Arc::new(handler));
        self
    }

    /// Sets the password a ReinitializeDevice request must carry. See
    /// [`EndpointSession::with_reinit_password`].
    pub fn reinit_password(mut self, password: impl Into<String>) -> Self {
        self.reinit_password = Some(password.into());
        self
    }

    /// Enables AtomicReadFile. See [`EndpointSession::with_file_reads`].
    pub fn file_reads(mut self) -> Self {
        self.file_reads = true;
        self
    }

    /// Enables AtomicWriteFile. See [`EndpointSession::with_file_writes`].
    pub fn file_writes(mut self) -> Self {
        self.file_writes = true;
        self
    }

    /// Enables ReadPropertyMultiple. See [`EndpointSession::with_multiple_reads`].
    pub fn multiple_reads(mut self) -> Self {
        self.multiple_reads = true;
        self
    }

    /// Enables WriteProperty to any object. See [`EndpointSession::with_writes`].
    pub fn writes(mut self) -> Self {
        self.writes = true;
        self
    }

    /// See [`EndpointSession::with_write_observer`].
    pub fn write_observer<F>(mut self, observer: F) -> Self
    where
        F: Fn(bacnet_server::server::PropertyWriteData) + Send + Sync + 'static,
    {
        self.write_observer = Some(std::sync::Arc::new(observer));
        self
    }

    /// Builds an unstarted session (caller drives `start()`/`stop()` once).
    ///
    /// Fails with no ports, and when the identity lists Network Ports that
    /// aren't one per router port on its network. Starting fails as
    /// [`BACnetRouter::start`](bacnet_network::router::BACnetRouter::start)
    /// does, for a reserved or repeated network number among them.
    pub fn build_session(self) -> Result<EndpointSession<T>, Error> {
        if let Some(identity) = &self.identity {
            check_network_ports(identity, &self.ports)?;
        }
        let local_receive_capacity = self
            .ports
            .iter()
            .map(|port| port.transport.local_receive_apdu_capacity())
            .min()
            .ok_or_else(|| Error::Encoding("a router endpoint needs a port".into()))?;
        let ingress =
            EndpointIngress::with_router(self.ports, self.options, self.session.queue_capacity)?;
        let mut endpoint = EndpointSession::with_ingress(
            ingress,
            local_receive_capacity,
            self.role,
            self.session,
        )?;
        if let Some(db) = self.database {
            endpoint = db.attach(endpoint);
        }
        if let Some(id) = self.identity {
            endpoint = endpoint.device(id);
        }
        if let Some(authorizer) = self.device_write_authorizer {
            endpoint = endpoint.with_device_writes(authorizer);
        }
        endpoint.reinitialize = self.reinitialize;
        endpoint.reinit_password = self.reinit_password;
        endpoint.file_reads = self.file_reads;
        endpoint.file_writes = self.file_writes;
        endpoint.multiple_reads = self.multiple_reads;
        endpoint.writes = self.writes;
        endpoint.write_observer = self.write_observer;
        Ok(endpoint)
    }
}

/// An identity that lists Network Ports lists one per router port, on that
/// port's network.
fn check_network_ports<T: TransportPort>(
    identity: &crate::identity::DeviceIdentity,
    ports: &[RouterPort<T>],
) -> Result<(), Error> {
    let entries = identity.network_ports();
    if entries.is_empty() {
        return Ok(());
    }
    let one_each = entries.len() == ports.len()
        && ports.iter().all(|port| {
            entries
                .iter()
                .filter(|entry| entry.network_number == u32::from(port.network_number))
                .count()
                == 1
        });
    if one_each {
        Ok(())
    } else {
        Err(Error::Encoding(
            "a router endpoint's identity lists one Network Port per router port, on its network"
                .into(),
        ))
    }
}
