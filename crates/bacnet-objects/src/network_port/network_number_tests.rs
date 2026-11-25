use super::tests::mstp_config;
use super::*;
use crate::database::ObjectDatabase;
use bacnet_types::enums::{ErrorClass, ErrorCode, PropertyIdentifier as P};
use bacnet_types::error::RemoteError;

fn trunk(instance: u32, network_number: u16) -> NetworkPortObject {
    let mut port = NetworkPortObject::new_mstp(
        instance,
        format!("trunk {instance}"),
        MstpPortConfig {
            network_number,
            ..mstp_config()
        },
    )
    .unwrap();
    port.allow_network_number_writes();
    port
}

fn read(port: &NetworkPortObject, property: P) -> PropertyValue {
    port.read_property(property, None).unwrap()
}

fn assert_refused(result: Result<(), Error>, class: ErrorClass, code: ErrorCode) {
    match result {
        Err(Error::Remote(RemoteError::Error {
            class: actual_class,
            code: actual_code,
        })) => assert_eq!((actual_class, actual_code), (class, code)),
        other => panic!("expected {class:?} / {code:?}, got {other:?}"),
    }
}

#[test]
fn a_written_network_number_waits_for_activation() {
    let mut port = trunk(2, 2650);

    port.write_property(P::NETWORK_NUMBER, None, PropertyValue::Unsigned(3001), None)
        .unwrap();

    assert_eq!(read(&port, P::NETWORK_NUMBER), PropertyValue::Unsigned(3001));
    assert_eq!(read(&port, P::CHANGES_PENDING), PropertyValue::Boolean(true));

    assert!(port.activate_changes().unwrap());

    assert_eq!(read(&port, P::NETWORK_NUMBER), PropertyValue::Unsigned(3001));
    assert_eq!(read(&port, P::CHANGES_PENDING), PropertyValue::Boolean(false));
    // CONFIGURED.
    assert_eq!(
        read(&port, P::NETWORK_NUMBER_QUALITY),
        PropertyValue::Enumerated(3)
    );
}

#[test]
fn network_number_is_read_only_unless_allowed() {
    let mut port = NetworkPortObject::new_mstp(2, "trunk", mstp_config()).unwrap();

    assert_refused(
        port.write_property(P::NETWORK_NUMBER, None, PropertyValue::Unsigned(3001), None),
        ErrorClass::PROPERTY,
        ErrorCode::WRITE_ACCESS_DENIED,
    );
}

#[test]
fn a_network_number_out_of_range_is_refused() {
    let mut port = trunk(2, 2650);

    for number in [0, 65535] {
        assert_refused(
            port.write_property(P::NETWORK_NUMBER, None, PropertyValue::Unsigned(number), None),
            ErrorClass::PROPERTY,
            ErrorCode::VALUE_OUT_OF_RANGE,
        );
    }
    assert_eq!(read(&port, P::CHANGES_PENDING), PropertyValue::Boolean(false));
}

fn port(instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::NETWORK_PORT, instance).unwrap()
}

/// Ports 2 on 2650 and 3 on 2651.
fn two_trunks() -> ObjectDatabase {
    let mut database = ObjectDatabase::new();
    database.add(Box::new(trunk(2, 2650))).unwrap();
    database.add(Box::new(trunk(3, 2651))).unwrap();
    database
}

fn write(database: &mut ObjectDatabase, instance: u32, number: u64) {
    database
        .get_mut(&port(instance))
        .unwrap()
        .write_property(P::NETWORK_NUMBER, None, PropertyValue::Unsigned(number), None)
        .unwrap();
}

#[test]
fn a_written_network_number_another_port_has_is_refused_at_activation() {
    let mut database = two_trunks();

    write(&mut database, 3, 2650);
    assert!(database.check_network_port_changes().is_err());

    write(&mut database, 3, 3001);
    database.check_network_port_changes().unwrap();
    assert_eq!(database.activate_network_port_changes().unwrap(), 1);
}

#[test]
fn one_network_number_written_to_two_ports_is_refused_at_activation() {
    let mut database = two_trunks();
    write(&mut database, 2, 3001);
    write(&mut database, 3, 3001);

    assert!(database.check_network_port_changes().is_err());
}

#[test]
fn two_ports_can_swap_network_numbers() {
    let mut database = two_trunks();
    write(&mut database, 2, 2651);
    write(&mut database, 3, 2650);

    database.check_network_port_changes().unwrap();
    assert_eq!(database.activate_network_port_changes().unwrap(), 2);

    assert_eq!(
        database.network_numbers_in_effect(),
        [(port(2), 2651), (port(3), 2650)]
    );
}

#[test]
fn network_numbers_in_effect_leave_out_a_pending_write() {
    let mut database = two_trunks();
    write(&mut database, 2, 3001);

    assert_eq!(
        database.network_numbers_in_effect(),
        [(port(2), 2650), (port(3), 2651)]
    );
}
