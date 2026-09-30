use super::*;
use bacnet_objects::analog::AnalogValueObject;
use bacnet_objects::present_value_access::PresentValueAccess;
use bacnet_types::enums::{ErrorClass, ErrorCode, ObjectType};
use std::net::{Ipv4Addr, UdpSocket};

const DEGREES_CELSIUS: u32 = 62;
const WRITTEN: f32 = 23.5;

fn analog_value(instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::ANALOG_VALUE, instance).unwrap()
}

fn encoded(value: f32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    bacnet_encoding::primitives::encode_property_value(&mut buf, &PropertyValue::Real(value))
        .unwrap();
    buf.to_vec()
}

/// A running endpoint serving WriteProperty to a writable Analog Value 1, a read-only
/// Analog Value 2 and a commandable Analog Value 3, a client to reach it, and the endpoint's
/// B/IP address.
async fn writing_endpoint() -> (
    EndpointSession<bacnet_transport::bip::BipTransport>,
    bacnet_client::client::BACnetClient<bacnet_transport::bip::BipTransport>,
    [u8; 6],
) {
    let reservation = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);

    let identity = crate::DeviceIdentity::new(123, 42).unwrap();
    let objects: Vec<Box<dyn bacnet_objects::traits::BACnetObject>> = vec![
        Box::new(
            AnalogValueObject::with_access(
                1,
                "writable",
                DEGREES_CELSIUS,
                PresentValueAccess::Writable,
            )
            .unwrap(),
        ),
        Box::new(
            AnalogValueObject::with_access(
                2,
                "read-only",
                DEGREES_CELSIUS,
                PresentValueAccess::ReadOnly,
            )
            .unwrap(),
        ),
        Box::new(
            AnalogValueObject::with_access(
                3,
                "commandable",
                DEGREES_CELSIUS,
                PresentValueAccess::Commandable,
            )
            .unwrap(),
        ),
    ];
    let db = crate::identity::build_database_with_extra(&identity, objects).unwrap();

    let mut endpoint =
        crate::bip::BipEndpointBuilder::new(Ipv4Addr::LOCALHOST, port, Ipv4Addr::BROADCAST)
            .role(SessionRole::ServerOnly)
            .database(db)
            .identity(identity)
            .writes()
            .build_session()
            .unwrap();
    endpoint.start().await.unwrap();

    let client = bacnet_client::client::BACnetClient::bip_builder()
        .interface(Ipv4Addr::LOCALHOST)
        .port(0)
        .build()
        .await
        .unwrap();
    let mac = bacnet_transport::bvll::encode_bip_mac([127, 0, 0, 1], port);

    (endpoint, client, mac)
}

async fn present_value(
    client: &bacnet_client::client::BACnetClient<bacnet_transport::bip::BipTransport>,
    mac: &[u8],
    object: ObjectIdentifier,
) -> PropertyValue {
    let ack = client
        .read_property(mac, object, PropertyIdentifier::PRESENT_VALUE, None)
        .await
        .unwrap();
    bacnet_encoding::primitives::decode_application_value(&ack.property_value, 0)
        .unwrap()
        .0
}

fn assert_refused(error: Error, class: ErrorClass, code: ErrorCode) {
    assert!(
        matches!(error, Error::Protocol { class: actual_class, code: actual_code }
            if actual_class == class.to_raw() as u32 && actual_code == code.to_raw() as u32),
        "got {error:?}"
    );
}

#[tokio::test]
async fn write_property_to_a_writable_value_replaces_it() {
    let (mut endpoint, mut client, mac) = writing_endpoint().await;

    client
        .write_property(
            &mac,
            analog_value(1),
            PropertyIdentifier::PRESENT_VALUE,
            None,
            encoded(WRITTEN),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        present_value(&client, &mac, analog_value(1)).await,
        PropertyValue::Real(WRITTEN)
    );

    // The Device advertises exactly what the responder executes.
    let profile = client
        .read_property(
            &mac,
            oid(123),
            PropertyIdentifier::PROTOCOL_SERVICES_SUPPORTED,
            None,
        )
        .await
        .unwrap();
    let (profile, _) =
        bacnet_encoding::primitives::decode_application_value(&profile.property_value, 0).unwrap();
    assert_eq!(services(profile), vec![12, 15]);

    client.stop().await.unwrap();
    endpoint.stop().await.unwrap();
}

#[tokio::test]
async fn write_property_to_a_commandable_value_takes_its_priority() {
    let (mut endpoint, mut client, mac) = writing_endpoint().await;

    client
        .write_property(
            &mac,
            analog_value(3),
            PropertyIdentifier::PRESENT_VALUE,
            None,
            encoded(WRITTEN),
            Some(8),
        )
        .await
        .unwrap();

    let slot = client
        .read_property(
            &mac,
            analog_value(3),
            PropertyIdentifier::PRIORITY_ARRAY,
            Some(8),
        )
        .await
        .unwrap();
    assert_eq!(
        bacnet_encoding::primitives::decode_application_value(&slot.property_value, 0)
            .unwrap()
            .0,
        PropertyValue::Real(WRITTEN)
    );
    assert_eq!(
        present_value(&client, &mac, analog_value(3)).await,
        PropertyValue::Real(WRITTEN)
    );

    client.stop().await.unwrap();
    endpoint.stop().await.unwrap();
}

#[tokio::test]
async fn write_property_to_a_read_only_value_is_denied() {
    let (mut endpoint, mut client, mac) = writing_endpoint().await;
    let before = present_value(&client, &mac, analog_value(2)).await;

    let error = client
        .write_property(
            &mac,
            analog_value(2),
            PropertyIdentifier::PRESENT_VALUE,
            None,
            encoded(WRITTEN),
            None,
        )
        .await
        .unwrap_err();

    assert_refused(error, ErrorClass::PROPERTY, ErrorCode::WRITE_ACCESS_DENIED);
    assert_eq!(present_value(&client, &mac, analog_value(2)).await, before);

    client.stop().await.unwrap();
    endpoint.stop().await.unwrap();
}

#[tokio::test]
async fn write_property_to_a_missing_object_is_an_unknown_object() {
    let (mut endpoint, mut client, mac) = writing_endpoint().await;

    let error = client
        .write_property(
            &mac,
            analog_value(4),
            PropertyIdentifier::PRESENT_VALUE,
            None,
            encoded(WRITTEN),
            None,
        )
        .await
        .unwrap_err();

    assert_refused(error, ErrorClass::OBJECT, ErrorCode::UNKNOWN_OBJECT);

    client.stop().await.unwrap();
    endpoint.stop().await.unwrap();
}

#[tokio::test]
async fn writes_and_device_writes_are_exclusive() {
    let (transport, _peer) = LoopbackTransport::pair(vec![0x01], vec![0x02]);
    let identity = crate::DeviceIdentity::new(123, 42).unwrap();
    let db = crate::identity::build_database_with_extra(&identity, vec![]).unwrap();
    let mut session =
        EndpointSession::new(transport, SessionRole::ServerOnly, SessionConfig::default())
            .unwrap()
            .with_database(db)
            .with_identity(identity)
            .with_writes()
            .with_device_writes(Arc::new(|_| true));

    assert!(session.start().await.is_err());
}

#[tokio::test]
async fn writes_need_a_server_role() {
    let (transport, _peer) = LoopbackTransport::pair(vec![0x01], vec![0x02]);
    let mut session =
        EndpointSession::new(transport, SessionRole::ClientOnly, SessionConfig::default())
            .unwrap()
            .with_writes();

    assert!(session.start().await.is_err());
}
