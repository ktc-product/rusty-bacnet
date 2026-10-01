use super::*;
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
    let client = identity.client_config();
    assert_eq!((client.apdu_timeout_ms, client.apdu_retries), (2500, 2));
    let mut session = crate::session::SessionConfig::default();
    identity.apply_to_session_config(&mut session);
    assert_eq!((session.apdu_timeout_ms, session.apdu_retries), (2500, 2));
}

#[test]
fn without_apdu_timers_nothing_changes() {
    let identity = DeviceIdentity::new(1001, 42).unwrap();

    assert_eq!(
        advertised(
            &build_database_with_extra(&identity, vec![]).unwrap(),
            &identity
        ),
        (
            PropertyValue::Unsigned(u64::from(DEFAULT_APDU_TIMEOUT_MS)),
            PropertyValue::Unsigned(u64::from(DEFAULT_APDU_RETRIES))
        )
    );
    let default = bacnet_client::client::ClientConfig::default();
    let client = identity.client_config();
    assert_eq!(
        (client.apdu_timeout_ms, client.apdu_retries),
        (default.apdu_timeout_ms, default.apdu_retries)
    );
}
