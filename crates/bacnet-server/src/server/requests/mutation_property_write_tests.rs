//! `ServerConfig::on_property_written` for WriteProperty and WritePropertyMultiple.
use super::mutation_tests::{apdu, oid, value, wpm, Fixture};
use super::*;
use bacnet_services::wpm::WriteAccessSpecification;
use bacnet_services::write_property::WritePropertyRequest;
use std::sync::Mutex as StdMutex;

type Reported = Arc<StdMutex<Vec<PropertyWriteData>>>;

const ACTIVE: PropertyValue = PropertyValue::Enumerated(1);

/// The shared mutation fixture, reporting every write into the returned list.
fn observed() -> (Fixture, Reported) {
    let mut fixture = Fixture::new(None);
    let reported: Reported = Arc::default();
    let sink = Arc::clone(&reported);
    fixture.config.on_property_written =
        Some(Arc::new(move |write| sink.lock().unwrap().push(write)));
    (fixture, reported)
}

fn present_value(instance: u32, priority: Option<u8>) -> PropertyWriteData {
    PropertyWriteData {
        object_identifier: oid(ObjectType::BINARY_VALUE, instance),
        property_identifier: PropertyIdentifier::PRESENT_VALUE,
        property_array_index: None,
        value: ACTIVE,
        priority,
    }
}

fn wp(instance: u32, priority: Option<u8>) -> Bytes {
    let mut data = BytesMut::new();
    WritePropertyRequest {
        object_identifier: oid(ObjectType::BINARY_VALUE, instance),
        property_identifier: PropertyIdentifier::PRESENT_VALUE,
        property_array_index: None,
        property_value: value(ACTIVE),
        priority,
    }
    .encode(&mut data)
    .unwrap();
    data.freeze()
}

fn present_value_spec(instance: u32) -> WriteAccessSpecification {
    WriteAccessSpecification {
        object_identifier: oid(ObjectType::BINARY_VALUE, instance),
        list_of_properties: vec![BACnetPropertyValue {
            property_identifier: PropertyIdentifier::PRESENT_VALUE,
            property_array_index: None,
            value: value(ACTIVE),
            priority: None,
        }],
    }
}

#[tokio::test]
async fn write_property_reports_the_write() {
    let (fixture, reported) = observed();

    let response = fixture
        .dispatch(ConfirmedServiceChoice::WRITE_PROPERTY, wp(2, Some(8)), 1)
        .await
        .unwrap();

    assert!(matches!(apdu(response), Apdu::SimpleAck(_)));
    assert_eq!(*reported.lock().unwrap(), vec![present_value(2, Some(8))]);
}

#[tokio::test]
async fn write_property_that_fails_reports_nothing() {
    let (fixture, reported) = observed();

    let response = fixture
        .dispatch(ConfirmedServiceChoice::WRITE_PROPERTY, wp(99, None), 1)
        .await
        .unwrap();

    assert!(matches!(apdu(response), Apdu::Error(_)));
    assert!(reported.lock().unwrap().is_empty());
}

/// Clause 15.10: the writes before the failing one stand, and only those are reported.
#[tokio::test]
async fn write_property_multiple_reports_the_writes_before_a_failure() {
    let (fixture, reported) = observed();
    let request = wpm(vec![
        present_value_spec(2),
        present_value_spec(99),
        present_value_spec(1),
    ]);

    let response = fixture
        .dispatch(ConfirmedServiceChoice::WRITE_PROPERTY_MULTIPLE, request, 1)
        .await
        .unwrap();

    assert!(matches!(apdu(response), Apdu::Error(_)));
    assert_eq!(*reported.lock().unwrap(), vec![present_value(2, None)]);
}

#[tokio::test]
async fn a_panicking_observer_leaves_the_write_in_place() {
    let mut fixture = Fixture::new(None);
    fixture.config.on_property_written = Some(Arc::new(|_| panic!("observer")));

    let response = fixture
        .dispatch(ConfirmedServiceChoice::WRITE_PROPERTY, wp(2, None), 1)
        .await
        .unwrap();

    assert!(matches!(apdu(response), Apdu::SimpleAck(_)));
    assert_eq!(
        fixture
            .read(
                oid(ObjectType::BINARY_VALUE, 2),
                PropertyIdentifier::PRESENT_VALUE
            )
            .await,
        ACTIVE
    );
}
