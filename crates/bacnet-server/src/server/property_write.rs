//! Reporting of the properties a peer's WriteProperty or WritePropertyMultiple changed.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use bacnet_device_core::write::{WriteCommitObserver, WriteTarget, gate_and_decode_write};
use bacnet_objects::database::ObjectDatabase;
use bacnet_types::enums::PropertyIdentifier;
use bacnet_types::error::Error;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};
use tracing::debug;

/// A property a peer's WriteProperty or WritePropertyMultiple changed.
#[derive(Debug, Clone, PartialEq)]
pub struct PropertyWriteData {
    /// Object written.
    pub object_identifier: ObjectIdentifier,
    /// Property written.
    pub property_identifier: PropertyIdentifier,
    /// Array element written; `None` means the whole property.
    pub property_array_index: Option<u32>,
    /// Value written, as the request carried it.
    pub value: PropertyValue,
    /// Priority the request carried, if any.
    pub priority: Option<u8>,
}

/// See [`ServerConfig::on_property_written`](super::ServerConfig::on_property_written).
pub type PropertyWriteObserver = Arc<dyn Fn(PropertyWriteData) + Send + Sync>;

/// Passes every call through to `inner` and keeps what was written.
pub(crate) struct RecordingObserver<'a> {
    inner: Option<&'a mut dyn WriteCommitObserver>,
    written: Vec<PropertyWriteData>,
}

impl<'a> RecordingObserver<'a> {
    pub(crate) fn new(inner: Option<&'a mut dyn WriteCommitObserver>) -> Self {
        Self {
            inner,
            written: Vec::new(),
        }
    }

    pub(crate) fn into_written(self) -> Vec<PropertyWriteData> {
        self.written
    }
}

impl WriteCommitObserver for RecordingObserver<'_> {
    fn before(&mut self, db: &ObjectDatabase, write: WriteTarget<'_>) {
        if let Some(inner) = self.inner.as_deref_mut() {
            inner.before(db, write);
        }
    }

    fn commit_policy(
        &mut self,
        db: &mut ObjectDatabase,
        write: WriteTarget<'_>,
        value: &PropertyValue,
    ) -> Option<Result<(), Error>> {
        self.inner.as_deref_mut()?.commit_policy(db, write, value)
    }

    fn committed(&mut self, db: &mut ObjectDatabase) {
        if let Some(inner) = self.inner.as_deref_mut() {
            inner.committed(db);
        }
    }

    fn failed(&mut self, db: &mut ObjectDatabase, error: &Error) {
        if let Some(inner) = self.inner.as_deref_mut() {
            inner.failed(db, error);
        }
    }

    fn applied(&mut self, db: &ObjectDatabase, oid: ObjectIdentifier) {
        if let Some(inner) = self.inner.as_deref_mut() {
            inner.applied(db, oid);
        }
    }

    fn written(&mut self, db: &ObjectDatabase, write: WriteTarget<'_>) {
        if let Some(inner) = self.inner.as_deref_mut() {
            inner.written(db, write);
        }
        // Decoded as the write decoded it, against the written object's datatype.
        let object = db
            .get(&write.oid)
            .expect("a written object is in the database");
        let value = gate_and_decode_write(object, write.property, write.array_index, write.value)
            .expect("the write decoded this value before making it");
        self.written.push(PropertyWriteData {
            object_identifier: write.oid,
            property_identifier: write.property,
            property_array_index: write.array_index,
            value,
            priority: write.priority,
        });
    }
}

/// Passes each write to `observer`, in order. A panic in the observer is logged.
pub(crate) fn report(observer: Option<&PropertyWriteObserver>, written: Vec<PropertyWriteData>) {
    let Some(observer) = observer else {
        return;
    };
    for write in written {
        let property = write.property_identifier;
        if catch_unwind(AssertUnwindSafe(|| observer(write))).is_err() {
            debug!(?property, "property write observer panicked");
        }
    }
}
