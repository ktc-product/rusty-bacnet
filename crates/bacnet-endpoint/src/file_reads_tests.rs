use super::*;
use bacnet_objects::file::FileObject;
use bacnet_services::file::{FileAccessMethod, FileReadAckMethod};
use bacnet_types::enums::{ErrorClass, ErrorCode, ObjectType};
use std::net::{Ipv4Addr, UdpSocket};

const CONTENTS: &[u8] = b"configuration";

fn file(instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::FILE, instance).unwrap()
}

/// A running endpoint serving AtomicReadFile for File 1, a client to reach it, and the
/// endpoint's B/IP address.
async fn file_reading_endpoint() -> (
    EndpointSession<bacnet_transport::bip::BipTransport>,
    bacnet_client::client::BACnetClient<bacnet_transport::bip::BipTransport>,
    [u8; 6],
) {
    let reservation = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);

    let identity = crate::DeviceIdentity::new(123, 42).unwrap();
    let mut configuration =
        FileObject::new(1, "configuration", "application/octet-stream").unwrap();
    configuration.set_data(CONTENTS.to_vec());
    let db = crate::identity::build_database_with_extra(&identity, vec![Box::new(configuration)])
        .unwrap();

    let mut endpoint =
        crate::bip::BipEndpointBuilder::new(Ipv4Addr::LOCALHOST, port, Ipv4Addr::BROADCAST)
            .role(SessionRole::ServerOnly)
            .database(db)
            .identity(identity)
            .file_reads()
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
async fn atomic_read_file_returns_the_file_contents() {
    let (mut endpoint, mut client, mac) = file_reading_endpoint().await;

    let ack = client
        .atomic_read_file_decoded(
            &mac,
            file(1),
            FileAccessMethod::Stream {
                file_start_position: 0,
                requested_octet_count: 1024,
            },
        )
        .await
        .unwrap();
    assert!(ack.end_of_file);
    assert_eq!(
        ack.access,
        FileReadAckMethod::Stream {
            file_start_position: 0,
            file_data: CONTENTS.to_vec(),
        }
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
    assert_eq!(services(profile), vec![6, 12]);

    client.stop().await.unwrap();
    endpoint.stop().await.unwrap();
}

#[tokio::test]
async fn atomic_read_file_of_a_missing_file_is_an_unknown_object() {
    let (mut endpoint, mut client, mac) = file_reading_endpoint().await;

    let error = client
        .atomic_read_file(
            &mac,
            file(2),
            FileAccessMethod::Stream {
                file_start_position: 0,
                requested_octet_count: 1024,
            },
        )
        .await
        .unwrap_err();

    assert!(
        matches!(error, Error::Protocol { class, code }
            if class == ErrorClass::OBJECT.to_raw() as u32
                && code == ErrorCode::UNKNOWN_OBJECT.to_raw() as u32),
        "got {error:?}"
    );

    client.stop().await.unwrap();
    endpoint.stop().await.unwrap();
}

/// An identity may not advertise AtomicReadFile unless the session executes it.
#[tokio::test]
async fn an_identity_advertising_atomic_read_file_needs_file_reads() {
    let (transport, _peer) = LoopbackTransport::pair(vec![0x01], vec![0x02]);
    let identity = crate::DeviceIdentity::new(123, 42)
        .unwrap()
        .with_services(&[
            ServiceSupported::READ_PROPERTY,
            ServiceSupported::ATOMIC_READ_FILE,
        ]);
    let db = crate::identity::build_database_with_extra(&identity, vec![]).unwrap();
    let mut session =
        EndpointSession::new(transport, SessionRole::ServerOnly, SessionConfig::default())
            .unwrap()
            .with_database(db)
            .with_identity(identity);

    assert!(session.start().await.is_err());
}

#[tokio::test]
async fn file_reads_need_a_server_role() {
    let (transport, _peer) = LoopbackTransport::pair(vec![0x01], vec![0x02]);
    let mut session =
        EndpointSession::new(transport, SessionRole::ClientOnly, SessionConfig::default())
            .unwrap()
            .with_file_reads();

    assert!(session.start().await.is_err());
}
