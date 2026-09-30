//! Pre-start execution profile and authority for the endpoint Device responder.

use super::*;
use bacnet_server::mutation::MutationAuthorizer;
use bacnet_types::enums::{ReinitializedState, ServiceSupported};

impl<T: TransportPort + 'static> EndpointSession<T> {
    /// Enables authorized writes to the local Device's `Description` and installed Audit recipient.
    ///
    /// The callback is mandatory and receives the existing redacted mutation
    /// context. A refusal or panic denies the request before mutation. It must
    /// be fast, nonblocking and side-effect-free; see [`MutationAuthorizer`].
    /// Other objects/properties and WritePropertyMultiple remain unsupported.
    /// An authorized NULL relinquishment succeeds without changing Description.
    /// Recipient writes require the complete source runtime installed by source selection.
    ///
    /// Startup requires a server role and exactly one concrete built-in Device
    /// in the attached database. A composed identity must match that Device and
    /// contain only the services the responder executes. Validation errors
    /// precede configuration mutation and transport startup, allowing correction
    /// and retry. The Device and identity then advertise exactly those services;
    /// the default session remains ReadProperty-only.
    ///
    /// # Panics
    /// Panics if startup has already consumed the session configuration.
    pub fn with_device_writes(mut self, authorizer: MutationAuthorizer) -> Self {
        self.assert_configurable();
        self.device_write_authorizer = Some(authorizer);
        self
    }

    /// Enables WriteProperty to any object in the attached database, as each object's write
    /// access allows.
    ///
    /// Startup requirements and the advertised services are those of
    /// [`with_device_writes`](Self::with_device_writes), and startup refuses the two together.
    ///
    /// # Panics
    /// Panics if startup has already consumed the session configuration.
    pub fn with_writes(mut self) -> Self {
        self.assert_configurable();
        self.writes = true;
        self
    }

    /// Enables ReinitializeDevice, carried out by `handler` with the database write-locked.
    ///
    /// Startup requirements and the advertised services are those of
    /// [`with_device_writes`](Self::with_device_writes). Without a password set by
    /// [`with_reinit_password`](Self::with_reinit_password), any peer's request reaches `handler`.
    ///
    /// # Panics
    /// Panics if startup has already consumed the session configuration.
    pub fn with_reinitialize<F>(mut self, handler: F) -> Self
    where
        F: Fn(ReinitializedState, &mut ObjectDatabase) -> Result<(), Error> + Send + Sync + 'static,
    {
        self.assert_configurable();
        self.reinitialize = Some(Arc::new(handler));
        self
    }

    /// Enables AtomicReadFile for the File objects in the attached database.
    ///
    /// Startup requirements and the advertised services are those of
    /// [`with_device_writes`](Self::with_device_writes).
    ///
    /// # Panics
    /// Panics if startup has already consumed the session configuration.
    pub fn with_file_reads(mut self) -> Self {
        self.assert_configurable();
        self.file_reads = true;
        self
    }

    /// Enables AtomicWriteFile for the File objects in the attached database.
    ///
    /// A File's Read_Only property decides whether it accepts a write. Startup
    /// requirements and the advertised services are those of
    /// [`with_device_writes`](Self::with_device_writes).
    ///
    /// # Panics
    /// Panics if startup has already consumed the session configuration.
    pub fn with_file_writes(mut self) -> Self {
        self.assert_configurable();
        self.file_writes = true;
        self
    }

    /// Sets the password a ReinitializeDevice request must carry.
    ///
    /// # Panics
    /// Panics if startup has already consumed the session configuration.
    pub fn with_reinit_password(mut self, password: impl Into<String>) -> Self {
        self.assert_configurable();
        self.reinit_password = Some(password.into());
        self
    }

    /// The services the responder executes with the capabilities enabled on this session.
    fn executed_services(&self) -> Vec<ServiceSupported> {
        let mut services = vec![ServiceSupported::READ_PROPERTY];
        if self.device_write_authorizer.is_some() || self.writes {
            services.push(ServiceSupported::WRITE_PROPERTY);
        }
        if self.reinitialize.is_some() {
            services.push(ServiceSupported::REINITIALIZE_DEVICE);
        }
        if self.file_reads {
            services.push(ServiceSupported::ATOMIC_READ_FILE);
        }
        if self.file_writes {
            services.push(ServiceSupported::ATOMIC_WRITE_FILE);
        }
        services
    }

    pub(super) fn validate_device_execution(&mut self) -> Result<Option<ObjectIdentifier>, Error> {
        if self.writes && self.device_write_authorizer.is_some() {
            return Err(Error::Encoding(
                "WriteProperty to any object and Device writes are exclusive".into(),
            ));
        }
        // The first capability enabled names the one that needs a Device, keeping the
        // Device-writes messages as they were.
        let capability = [
            (
                self.device_write_authorizer.is_some(),
                "Device writes",
                "Device writes require",
            ),
            (self.writes, "WriteProperty", "WriteProperty requires"),
            (
                self.reinitialize.is_some(),
                "ReinitializeDevice",
                "ReinitializeDevice requires",
            ),
            (self.file_reads, "AtomicReadFile", "AtomicReadFile requires"),
            (
                self.file_writes,
                "AtomicWriteFile",
                "AtomicWriteFile requires",
            ),
        ]
        .into_iter()
        .find(|(enabled, ..)| *enabled)
        .map(|(_, name, subject)| (name, subject));
        if self.role == SessionRole::ClientOnly {
            return match capability {
                Some((_, subject)) => Err(Error::Encoding(format!("{subject} a server role"))),
                None => Ok(None),
            };
        }
        let allowed = self.executed_services();
        if self.identity.as_ref().is_some_and(|identity| {
            !identity
                .services()
                .contains(&ServiceSupported::READ_PROPERTY)
                || identity
                    .services()
                    .iter()
                    .any(|service| !allowed.contains(service))
        }) {
            return Err(Error::Encoding(
                "Endpoint identity services do not match the responder's services".into(),
            ));
        }
        let Some((capability, subject)) = capability else {
            return Ok(None);
        };
        let db = self
            .database
            .as_mut()
            .ok_or_else(|| Error::Encoding(format!("{subject} an attached local database")))?;
        let db = Arc::get_mut(db)
            .expect("database is unshared before startup")
            .get_mut();
        let devices = db.find_by_type(ObjectType::DEVICE);
        if devices.len() != 1 || devices[0].instance_number() == ObjectIdentifier::MAX_INSTANCE {
            return Err(Error::Encoding(format!(
                "{subject} exactly one concrete local Device"
            )));
        }
        let oid = devices[0];
        if self
            .identity
            .as_ref()
            .is_some_and(|identity| identity.device_oid() != oid)
        {
            return Err(Error::Encoding(format!(
                "{capability} local Device does not match session identity"
            )));
        }
        if !db
            .get_mut(&oid)
            .expect("Device exists")
            .device_authority_internal()
            .is_some_and(|device| device.object_identifier() == oid)
        {
            return Err(Error::Encoding(format!(
                "{subject} the built-in Device authority"
            )));
        }
        Ok(Some(oid))
    }

    // All fallible configuration validation (including source ownership) precedes
    // this commit. No await/callback or second copy of Device state is involved.
    pub(super) fn commit_device_write_profile(&mut self, target: Option<ObjectIdentifier>) {
        let Some(oid) = target else { return };
        let services = self.executed_services();
        let db = Arc::get_mut(self.database.as_mut().expect("validated database"))
            .expect("database is unshared before startup")
            .get_mut();
        db.get_mut(&oid)
            .expect("validated Device")
            .device_authority_internal()
            .expect("validated Device authority")
            .set_services_supported(&services);
        if let Some(identity) = self.identity.take() {
            self.identity = Some(identity.with_services(&services));
        }
    }
}
