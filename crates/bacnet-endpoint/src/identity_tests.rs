use super::*;
use crate::identity::{build_database_with_extra, client_config, DeviceIdentity};
use bacnet_objects::database::ObjectDatabase;
use bacnet_transport::loopback::LoopbackTransport;
use bacnet_types::enums::PropertyIdentifier;
use bacnet_types::primitives::PropertyValue;

/// APDU_Timeout and Number_Of_APDU_Retries as the Device in `db` reports them.
fn advertised(db: &ObjectDatabase, identity: &DeviceIdentity) -> (PropertyValue, PropertyValue) {
    let device = db.get(&identity.device_oid()).unwrap();
    (
        device
            .read_property(PropertyIdentifier::APDU_TIMEOUT, None)
            .unwrap(),
        device
            .read_property(PropertyIdentifier::NUMBER_OF_APDU_RETRIES, None)
            .unwrap(),
    )
}

/// An unstarted session composed with `identity`.
fn session_with(identity: DeviceIdentity) -> EndpointSession<LoopbackTransport> {
    let (transport, _peer) = LoopbackTransport::pair(vec![0x01], vec![0x02]);
    EndpointSession::new(transport, SessionRole::Both, SessionConfig::default())
        .unwrap()
        .device(identity)
}

#[test]
fn apdu_timers_are_advertised_and_used_by_the_client() {
    let identity = DeviceIdentity::new(1001, 42)
        .unwrap()
        .with_apdu_timers(2500, 2);
    let expected = (PropertyValue::Unsigned(2500), PropertyValue::Unsigned(2));

    assert_eq!(
        advertised(&identity.build_database().unwrap(), &identity),
        expected
    );
    assert_eq!(
        advertised(
            &build_database_with_extra(&identity, vec![]).unwrap(),
            &identity
        ),
        expected
    );
    let client = client_config(&identity);
    assert_eq!((client.apdu_timeout_ms, client.apdu_retries), (2500, 2));
    let session = session_with(identity);
    assert_eq!(
        (session.config.apdu_timeout_ms, session.config.apdu_retries),
        (2500, 2)
    );
    assert_eq!(
        (
            session.client_config.apdu_timeout_ms,
            session.client_config.apdu_retries
        ),
        (2500, 2)
    );
}

#[test]
fn without_apdu_timers_nothing_changes() {
    let identity = DeviceIdentity::new(1001, 42).unwrap();

    assert_eq!(
        advertised(
            &build_database_with_extra(&identity, vec![]).unwrap(),
            &identity
        ),
        (PropertyValue::Unsigned(6000), PropertyValue::Unsigned(3))
    );
    let default = bacnet_client::client::ClientConfig::default();
    let client = client_config(&identity);
    assert_eq!(
        (client.apdu_timeout_ms, client.apdu_retries),
        (default.apdu_timeout_ms, default.apdu_retries)
    );
    let session = session_with(identity);
    assert_eq!(
        (session.config.apdu_timeout_ms, session.config.apdu_retries),
        (1000, 0)
    );
}
