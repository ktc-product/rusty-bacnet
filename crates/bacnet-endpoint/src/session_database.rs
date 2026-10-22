//! A database the caller keeps a handle on, served by the session as it is.
use super::*;

/// The database a builder attaches to the session it builds: its own, or one
/// the caller shares ([`EndpointSession::with_shared_database`]).
pub(crate) enum SessionDatabase {
    Owned(Box<ObjectDatabase>),
    Shared(Arc<RwLock<ObjectDatabase>>),
}

impl SessionDatabase {
    pub(crate) fn attach<T: TransportPort + 'static>(
        self,
        session: EndpointSession<T>,
    ) -> EndpointSession<T> {
        match self {
            Self::Owned(db) => session.with_database(*db),
            Self::Shared(db) => session.with_shared_database(db),
        }
    }
}

impl<T: TransportPort + 'static> EndpointSession<T> {
    /// [`Self::with_database`] for a database the caller keeps a handle on,
    /// such as one a previous session served: the session serves it as it
    /// is, and [`Self::database`] returns the same handle. The same rules
    /// apply to its Device; one removed while the session starts fails the
    /// start.
    /// A source Audit Reporter
    /// ([`with_source_audit_reporter`](Self::with_source_audit_reporter))
    /// needs a database the session alone holds, so starting refuses one.
    ///
    /// # Panics
    /// Panics if startup has already consumed the session configuration.
    pub fn with_shared_database(mut self, db: Arc<RwLock<ObjectDatabase>>) -> Self {
        self.assert_configurable();
        self.database = Some(db);
        self
    }
}
