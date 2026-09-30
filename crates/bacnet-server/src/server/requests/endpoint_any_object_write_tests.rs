//! WriteProperty to a Command's or a Channel's Present_Value on a responder
//! that serves writes to any object.

use super::*;

/// A responder serving writes to any object accepts a write to a Command's
/// Present_Value, ends the run it starts without making the Command's writes,
/// and leaves In_Process and All_Writes_Successful false.
#[tokio::test]
async fn endpoint_any_object_write_ends_the_command_run_it_starts() {
    use bacnet_objects::command::CommandObject;
    use bacnet_types::constructed::{BACnetActionCommand, BACnetActionList};

    let (responder, mut ingress) = fixture(None).await;
    let responder = responder.with_writes();
    let cmd = ObjectIdentifier::new(ObjectType::COMMAND, 1).unwrap();
    let mut command = CommandObject::new(1, "CMD-1").unwrap();
    command
        .set_action(vec![BACnetActionList {
            commands: vec![BACnetActionCommand {
                device_identifier: None,
                object_identifier: device(),
                property_identifier: PropertyIdentifier::DESCRIPTION,
                property_array_index: None,
                property_value: PropertyValue::CharacterString("commanded".into()),
                priority: None,
                post_delay: None,
                quit_on_failure: false,
                write_successful: true,
            }],
        }])
        .unwrap();
    responder.db().write().await.add(Box::new(command)).unwrap();
    let mut value = BytesMut::new();
    bacnet_encoding::primitives::encode_property_value(&mut value, &PropertyValue::Unsigned(1))
        .unwrap();
    let write = WritePropertyRequest {
        object_identifier: cmd,
        property_identifier: PropertyIdentifier::PRESENT_VALUE,
        property_array_index: None,
        property_value: value.to_vec(),
        priority: None,
    };

    let response = reply(&responder, received(request(&write))).await.0;

    assert!(matches!(response, Apdu::SimpleAck(_)), "{response:?}");
    let db = responder.db().read().await;
    let command = db.get(&cmd).unwrap();
    for (property, expected) in [
        (
            PropertyIdentifier::IN_PROCESS,
            PropertyValue::Boolean(false),
        ),
        (
            PropertyIdentifier::ALL_WRITES_SUCCESSFUL,
            PropertyValue::Boolean(false),
        ),
    ] {
        assert_eq!(
            command.read_property(property, None).unwrap(),
            expected,
            "{property:?}"
        );
    }
    drop(db);
    assert_ne!(
        description(&responder).await,
        PropertyValue::CharacterString("commanded".into())
    );
    ingress.stop().await.unwrap();
}

/// A responder serving writes to any object accepts a write to a Channel's
/// Present_Value, ends the distribution it starts without writing the
/// members, and sets Write_Status to FAILED.
#[tokio::test]
async fn endpoint_any_object_write_ends_the_channel_distribution_it_starts() {
    use bacnet_objects::channel::ChannelObject;
    use bacnet_types::constructed::BACnetDeviceObjectPropertyReference;
    use bacnet_types::enums::WriteStatus;

    let (responder, mut ingress) = fixture(None).await;
    let responder = responder.with_writes();
    let ch = ObjectIdentifier::new(ObjectType::CHANNEL, 1).unwrap();
    let mut channel = ChannelObject::new(1, "CH-1", 7).unwrap();
    channel
        .set_members(vec![BACnetDeviceObjectPropertyReference::new_local(
            device(),
            PropertyIdentifier::DESCRIPTION.to_raw(),
        )])
        .unwrap();
    responder.db().write().await.add(Box::new(channel)).unwrap();
    let mut value = BytesMut::new();
    bacnet_encoding::primitives::encode_app_character_string(&mut value, "commanded").unwrap();
    let write = WritePropertyRequest {
        object_identifier: ch,
        property_identifier: PropertyIdentifier::PRESENT_VALUE,
        property_array_index: None,
        property_value: value.to_vec(),
        priority: None,
    };

    let response = reply(&responder, received(request(&write))).await.0;

    assert!(matches!(response, Apdu::SimpleAck(_)), "{response:?}");
    assert_eq!(
        responder
            .db()
            .read()
            .await
            .get(&ch)
            .unwrap()
            .read_property(PropertyIdentifier::WRITE_STATUS, None)
            .unwrap(),
        PropertyValue::Enumerated(WriteStatus::FAILED.to_raw())
    );
    assert_ne!(
        description(&responder).await,
        PropertyValue::CharacterString("commanded".into())
    );
    ingress.stop().await.unwrap();
}
