use super::*;
use bacnet_objects::analog::AnalogInputObject;
use bacnet_types::constructed::{PropertyReference, ReadAccessSpecification};
use bacnet_types::enums::ObjectType;
use std::net::{Ipv4Addr, UdpSocket};

const DEGREES_CELSIUS: u32 = 62;
const ROOM_TEMPERATURE: f32 = 21.5;

fn analog_input(instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::ANALOG_INPUT, instance).unwrap()
}

fn reference(property: PropertyIdentifier) -> PropertyReference {
    PropertyReference {
        property_identifier: property,
        property_array_index: None,
    }
}

fn decoded(bytes: &[u8]) -> PropertyValue {
    bacnet_encoding::primitives::decode_application_value(bytes, 0)
        .unwrap()
        .0
}

/// A running endpoint serving ReadPropertyMultiple for an Analog Input 1, a client to reach it,
/// and the endpoint's B/IP address.
async fn multiple_reading_endpoint() -> (
    EndpointSession<bacnet_transport::bip::BipTransport>,
    bacnet_client::client::BACnetClient<bacnet_transport::bip::BipTransport>,
    [u8; 6],
) {
    let reservation = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);

    let identity = crate::DeviceIdentity::new(123, 42).unwrap();
    let mut input = AnalogInputObject::new(1, "RoomTemp", DEGREES_CELSIUS).unwrap();
    input.set_present_value(ROOM_TEMPERATURE);
    let db = crate::identity::build_database_with_extra(&identity, vec![Box::new(input)]).unwrap();

    let mut endpoint =
        crate::bip::BipEndpointBuilder::new(Ipv4Addr::LOCALHOST, port, Ipv4Addr::BROADCAST)
            .role(SessionRole::ServerOnly)
            .database(db)
            .identity(identity)
            .multiple_reads()
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

#[tokio::test]
async fn read_property_multiple_returns_every_requested_property() {
    let (mut endpoint, mut client, mac) = multiple_reading_endpoint().await;

    let ack = client
        .read_property_multiple(
            &mac,
            vec![ReadAccessSpecification {
                object_identifier: analog_input(1),
                list_of_property_references: vec![
                    reference(PropertyIdentifier::PRESENT_VALUE),
                    reference(PropertyIdentifier::OBJECT_NAME),
                ],
            }],
        )
        .await
        .unwrap();

    let results = &ack.list_of_read_access_results[0].list_of_results;
    assert_eq!(
        decoded(results[0].property_value.as_ref().unwrap()),
        PropertyValue::Real(ROOM_TEMPERATURE)
    );
    assert_eq!(
        decoded(results[1].property_value.as_ref().unwrap()),
        PropertyValue::CharacterString("RoomTemp".into())
    );

    client.stop().await.unwrap();
    endpoint.stop().await.unwrap();
}

/// Read through ReadPropertyMultiple itself, the Device advertises what the responder executes,
/// not the full server's set.
#[tokio::test]
async fn read_property_multiple_reports_the_endpoint_services() {
    let (mut endpoint, mut client, mac) = multiple_reading_endpoint().await;

    let ack = client
        .read_property_multiple(
            &mac,
            vec![ReadAccessSpecification {
                object_identifier: oid(123),
                list_of_property_references: vec![reference(
                    PropertyIdentifier::PROTOCOL_SERVICES_SUPPORTED,
                )],
            }],
        )
        .await
        .unwrap();

    let profile = decoded(
        ack.list_of_read_access_results[0].list_of_results[0]
            .property_value
            .as_ref()
            .unwrap(),
    );
    assert_eq!(services(profile), vec![12, 14]);

    client.stop().await.unwrap();
    endpoint.stop().await.unwrap();
}

/// An identity advertising ReadPropertyMultiple is accepted once the session executes it.
#[tokio::test]
async fn an_identity_advertising_read_property_multiple_starts_with_multiple_reads() {
    let (transport, _peer) = LoopbackTransport::pair(vec![0x01], vec![0x02]);
    let identity = crate::DeviceIdentity::new(123, 42)
        .unwrap()
        .with_services(&[
            ServiceSupported::READ_PROPERTY,
            ServiceSupported::READ_PROPERTY_MULTIPLE,
        ]);
    let db = crate::identity::build_database_with_extra(&identity, vec![]).unwrap();
    let mut session =
        EndpointSession::new(transport, SessionRole::ServerOnly, SessionConfig::default())
            .unwrap()
            .with_database(db)
            .with_identity(identity)
            .with_multiple_reads();

    session.start().await.unwrap();
    session.stop().await.unwrap();
}

#[tokio::test]
async fn multiple_reads_need_a_server_role() {
    let (transport, _peer) = LoopbackTransport::pair(vec![0x01], vec![0x02]);
    let mut session =
        EndpointSession::new(transport, SessionRole::ClientOnly, SessionConfig::default())
            .unwrap()
            .with_multiple_reads();

    let error = session.start().await.unwrap_err();

    assert!(
        error
            .to_string()
            .contains("ReadPropertyMultiple requires a server role"),
        "got {error}"
    );
}
