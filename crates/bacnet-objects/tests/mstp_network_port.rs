//! An identity declares an MS/TP master's Network Port, and the database it
//! builds serves it.

use bacnet_objects::device_identity::{DeviceIdentity, NetworkPortEntry};
use bacnet_objects::network_port::MstpPortConfig;
use bacnet_types::enums::{ObjectType, PropertyIdentifier as P};
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};
use bacnet_types::MacAddr;

fn config() -> MstpPortConfig {
    MstpPortConfig {
        network_number: 2650,
        apdu_length: 480,
        station: 5,
        max_master: 64,
        max_info_frames: 4,
        baud_rate: 38_400,
    }
}

#[test]
fn the_database_serves_a_declared_mstp_port() {
    let database = DeviceIdentity::new(10, 42)
        .unwrap()
        .with_mstp_port(3, config())
        .unwrap()
        .build_database()
        .unwrap();
    let port = database
        .get(&ObjectIdentifier::new(ObjectType::NETWORK_PORT, 3).unwrap())
        .expect("the Network Port");
    for (p, expected) in [
        (P::NETWORK_TYPE, PropertyValue::Enumerated(2)),
        (P::NETWORK_NUMBER, PropertyValue::Unsigned(2650)),
        (P::MAC_ADDRESS, PropertyValue::OctetString(vec![5])),
        (P::MAX_MASTER, PropertyValue::Unsigned(64)),
        (P::MAX_INFO_FRAMES, PropertyValue::Unsigned(4)),
    ] {
        assert_eq!(port.read_property(p, None).unwrap(), expected, "{p:?}");
    }
}

#[test]
fn an_entry_that_disagrees_with_its_mstp_configuration_is_refused() {
    let identity = || DeviceIdentity::new(10, 42).unwrap();
    let other_network = NetworkPortEntry {
        network_number: 1,
        ..NetworkPortEntry::mstp(3, config())
    };
    let other_mac = NetworkPortEntry {
        mac: MacAddr::from_slice(&[6]),
        ..NetworkPortEntry::mstp(3, config())
    };
    let no_configuration = NetworkPortEntry {
        mstp: None,
        ..NetworkPortEntry::mstp(3, config())
    };
    for entry in [other_network, other_mac, no_configuration] {
        assert!(
            identity().with_network_port(entry.clone()).is_err(),
            "{entry:?}"
        );
    }
}
