//! Configured Network Port snapshots and selected live state (135-2020 Clause 12.56).
//!
//! The B/IP and B/IPv6 constructors supply the flat application-level IPV4
//! and IPV6 profiles (`ip_config`). Configuration is read-only over BACnet:
//! this object has no socket or NIC discovery. Reconstruct it to change
//! local configuration. An explicit B/IP or B/IPv6 owner may publish its
//! actual bind and mode, and learn Network_Number/Quality, without changing
//! configured provenance. In FOREIGN or BBMD mode the object serves that
//! mode's properties, read live from the transport (see `bip_mode`), for
//! either IP version. A BBMD's BDT and registration setting, and a foreign
//! device's BBMD and time-to-live, are writable when the transport can
//! change them, and wait for activation (`pending`), as is a B/IP port's
//! multicast group (`multicast`).
//! The MS/TP constructor adds a master node's Max_Master and
//! Max_Info_Frames to the common application rows. Other snapshots expose
//! only the common rows; they do not claim a complete transport-specific SC
//! or Ethernet profile.

use crate::prelude::*;
use alloc::borrow::Cow;
use bacnet_types::MacAddr;
use bacnet_types::enums::{NetworkType, ObjectType, PropertyIdentifier, Reliability};
use bacnet_types::error::Error;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue, StatusFlags};

use crate::common::{self, read_common_properties};
use crate::traits::BACnetObject;

mod bip6_config;
mod bip_config;
mod bip_mode;
mod ip_config;
mod metadata;
mod mstp_config;
mod multicast;
mod pending;
mod registration;
use bacnet_types::network_number::NetworkNumber;
pub use bip_config::BipPortConfig;
pub(crate) use bip6_config::Bip6Bind;
pub use bip6_config::Bip6PortConfig;
use ip_config::IpConfig;
pub(crate) use ip_config::{PortAddress, PortBind};
pub use mstp_config::MstpPortConfig;

/// A declared application-port snapshot, optionally associated with an owned link.
pub struct NetworkPortObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    status_flags: StatusFlags,
    out_of_service: bool,
    reliability: Reliability,
    network_type: NetworkType,
    network_number: NetworkNumber,
    mac_address: MacAddr,
    apdu_length: u32,
    /// The B/IP or B/IPv6 profile; `None` for the other network types.
    ip: Option<IpConfig>,
    /// The MS/TP master profile; `None` for the other network types.
    mstp: Option<MstpPortConfig>,
    /// The mode the last published owner reported; NORMAL until one
    /// publishes. Like the bind, it stays after that owner stops, until a
    /// new registration reserves the port.
    mode: bip_mode::LiveMode,
    /// Values written to the mode's properties, waiting for activation.
    pending: pending::Pending,
    /// Whether the owner activates written values on ReinitializeDevice;
    /// without it the pending-activation rows refuse writes.
    activation: bool,
    /// The B/IP multicast group the owner lends, and a written one waiting.
    multicast: multicast::Multicast,
    binding: alloc::sync::Weak<()>,
    /// Whether the application runs the port's link itself and keeps it in service.
    kept_in_service: bool,
}

impl NetworkPortObject {
    /// Complete IPV4 snapshot, in NORMAL mode until a registered owner
    /// publishes another. Instance is the declared local Port ID (local
    /// policy: 1..=255); UDP port zero remains valid unbound configuration.
    pub fn new_bip(
        instance: u32,
        name: impl Into<String>,
        config: BipPortConfig,
    ) -> Result<Self, Error> {
        Self::new_ip(instance, name.into(), IpConfig::V4(config))
    }

    /// Complete IPV6 (B/IPv6, Annex U) snapshot, in NORMAL mode until a
    /// registered owner publishes another. The instance policy is B/IP's:
    /// the declared local Port ID, 1..=255. MAC_Address is the configured
    /// VMAC until an owner publishes the one it uses.
    pub fn new_bip6(
        instance: u32,
        name: impl Into<String>,
        config: Bip6PortConfig,
    ) -> Result<Self, Error> {
        Self::new_ip(instance, name.into(), IpConfig::V6(config))
    }

    fn new_ip(instance: u32, name: String, config: IpConfig) -> Result<Self, Error> {
        config.validate(instance)?;
        Ok(Self {
            oid: ObjectIdentifier::new(ObjectType::NETWORK_PORT, instance)?,
            name,
            description: String::new(),
            status_flags: StatusFlags::empty(),
            out_of_service: false,
            reliability: Reliability::NO_FAULT_DETECTED,
            network_type: config.network_type(),
            network_number: NetworkNumber::configured(config.network_number())
                .expect("validated Network Number"),
            mac_address: config.mac(),
            apdu_length: config.apdu_length(),
            ip: Some(config),
            mstp: None,
            mode: Default::default(),
            pending: Default::default(),
            activation: false,
            multicast: Default::default(),
            binding: alloc::sync::Weak::new(),
            kept_in_service: false,
        })
    }

    /// Common application rows for Ethernet or VIRTUAL configuration. This is not a
    /// complete link-specific profile. In particular it exposes no IP fields.
    /// IPV4 must use `new_bip` and IPV6 `new_bip6`; the flat B/IP instance
    /// policy does not apply here.
    pub fn new_non_bip(
        instance: u32,
        name: impl Into<String>,
        network_type: NetworkType,
        network_number: u16,
        mac_address: MacAddr,
        apdu_length: u32,
    ) -> Result<Self, Error> {
        if !matches!(network_type, NetworkType::ETHERNET | NetworkType::VIRTUAL)
            || network_number == u16::MAX
            || apdu_length < 50
        {
            return Err(common::value_out_of_range_error());
        }
        Ok(Self {
            oid: ObjectIdentifier::new(ObjectType::NETWORK_PORT, instance)?,
            name: name.into(),
            description: String::new(),
            status_flags: StatusFlags::empty(),
            out_of_service: false,
            reliability: Reliability::NO_FAULT_DETECTED,
            network_type,
            network_number: NetworkNumber::configured(network_number)
                .expect("validated Network Number"),
            mac_address,
            apdu_length,
            ip: None,
            mstp: None,
            mode: Default::default(),
            pending: Default::default(),
            activation: false,
            multicast: Default::default(),
            binding: alloc::sync::Weak::new(),
            kept_in_service: false,
        })
    }

    /// MS/TP snapshot of a master node (Clause 12.56, Network_Type MSTP):
    /// the common application rows, the station as its one-octet
    /// MAC_Address, Max_Master and Max_Info_Frames, and the baud rate as
    /// Link_Speed. Configuration is read-only; reconstruct it to change.
    pub fn new_mstp(
        instance: u32,
        name: impl Into<String>,
        config: MstpPortConfig,
    ) -> Result<Self, Error> {
        config.validate()?;
        Ok(Self {
            oid: ObjectIdentifier::new(ObjectType::NETWORK_PORT, instance)?,
            name: name.into(),
            description: String::new(),
            status_flags: StatusFlags::empty(),
            out_of_service: false,
            reliability: Reliability::NO_FAULT_DETECTED,
            network_type: NetworkType::MSTP,
            network_number: NetworkNumber::configured(config.network_number)
                .expect("validated Network Number"),
            mac_address: MacAddr::from_slice(&[config.station]),
            apdu_length: config.apdu_length,
            ip: None,
            mstp: Some(config),
            mode: Default::default(),
            pending: Default::default(),
            activation: false,
            multicast: Default::default(),
            binding: alloc::sync::Weak::new(),
            kept_in_service: false,
        })
    }

    /// For a port whose link the application runs itself, without registering it: the port
    /// stays in service, so a client's Out_Of_Service write is refused, as a bound port's is.
    /// Out_Of_Service TRUE must stop communication through the port (Clause 12.56), which the
    /// object can't do for a link it doesn't own.
    pub fn keep_in_service(&mut self) {
        self.out_of_service = false;
        self.kept_in_service = true;
    }

    /// Set the optional descriptive label without altering port configuration.
    pub fn set_description(&mut self, desc: impl Into<String>) {
        self.description = desc.into();
    }
}

impl BACnetObject for NetworkPortObject {
    fn object_identifier(&self) -> ObjectIdentifier {
        self.oid
    }
    fn object_name(&self) -> &str {
        &self.name
    }

    fn read_property(
        &self,
        property: PropertyIdentifier,
        array_index: Option<u32>,
    ) -> Result<PropertyValue, Error> {
        crate::property_metadata::check_read_array_index(self, property, array_index)?;
        use PropertyIdentifier as P;
        if let Some(result) = read_common_properties!(self, property, array_index) {
            return result;
        }
        match property {
            P::OBJECT_TYPE => Ok(PropertyValue::Enumerated(ObjectType::NETWORK_PORT.to_raw())),
            P::NETWORK_TYPE => Ok(PropertyValue::Enumerated(self.network_type.to_raw())),
            P::PROTOCOL_LEVEL => Ok(PropertyValue::Enumerated(2)),
            P::NETWORK_NUMBER => Ok(PropertyValue::Unsigned(
                self.network_number.snapshot().0.into(),
            )),
            P::NETWORK_NUMBER_QUALITY => Ok(PropertyValue::Enumerated(
                self.network_number.snapshot().1.into(),
            )),
            P::MAC_ADDRESS => Ok(PropertyValue::OctetString(self.mac_address.to_vec())),
            P::APDU_LENGTH => Ok(PropertyValue::Unsigned(self.apdu_length.into())),
            // An MS/TP port's configured baud rate; otherwise zero, which says
            // the rate is unknown (Clause 12.56): no NIC speed is measured.
            P::LINK_SPEED => Ok(PropertyValue::Real(
                self.mstp.map_or(0.0, |config| config.baud_rate as f32),
            )),
            P::CHANGES_PENDING => Ok(PropertyValue::Boolean(self.changes_pending())),
            _ => {
                if let Some(config) = self.mstp {
                    return match property {
                        P::MAX_MASTER => Ok(PropertyValue::Unsigned(config.max_master.into())),
                        P::MAX_INFO_FRAMES => {
                            Ok(PropertyValue::Unsigned(config.max_info_frames.into()))
                        }
                        _ => Err(common::unknown_property_error()),
                    };
                }
                let config = self
                    .ip
                    .as_ref()
                    .ok_or_else(common::unknown_property_error)?;
                if property == config.mode_property() {
                    return Ok(PropertyValue::Enumerated(self.mode.ip_mode().to_raw()));
                }
                if pending::nat_row(property) && !self.serves_nat() {
                    return Err(common::unknown_property_error());
                }
                if let Some(result) = self.read_multicast(property) {
                    return result;
                }
                config
                    .read(property, array_index)
                    .or_else(|| self.pending_value(property))
                    .or_else(|| self.mode.read(property))
                    .unwrap_or_else(|| Err(common::unknown_property_error()))
            }
        }
    }

    fn write_property(
        &mut self,
        property: PropertyIdentifier,
        array_index: Option<u32>,
        value: PropertyValue,
        _priority: Option<u8>,
    ) -> Result<(), Error> {
        crate::property_metadata::check_write_array_index(&*self, property, array_index)?;
        if property == PropertyIdentifier::OUT_OF_SERVICE
            && (self.is_bound() || self.kept_in_service)
        {
            return Err(common::write_access_denied_error());
        }
        if let Some(result) =
            common::write_out_of_service(&mut self.out_of_service, property, &value)
        {
            return result;
        }
        if let Some(result) = common::write_description(&mut self.description, property, &value) {
            return result;
        }
        if let Some(result) = self.write_pending(property, array_index, &value) {
            return result;
        }
        if let Some(result) = self.write_multicast(property, array_index, &value) {
            return result;
        }
        // Other configuration writes would need an activation owner (12.56)
        // this snapshot doesn't have.
        if self
            .property_metadata()
            .iter()
            .any(|row| row.property_identifier == property)
        {
            Err(common::write_access_denied_error())
        } else {
            Err(common::unknown_property_error())
        }
    }

    fn property_metadata(&self) -> Cow<'_, [crate::property_metadata::PropertyMetadata]> {
        metadata::for_object(self)
    }

    crate::traits::lend_reliability_eval!();
}

/// The Reliability the application works out for a port it keeps in service, such as a link it
/// can't open. A port a client can take out of service keeps NO_FAULT_DETECTED: one that can
/// report a fault must take a client's Reliability while out of service (Clause 12.56).
impl crate::traits::ReliabilityEval for NetworkPortObject {
    fn set_reliability(&mut self, reliability: Reliability) -> Result<(), Error> {
        if !self.kept_in_service {
            return Err(common::write_access_denied_error());
        }
        if !common::is_reliability_value_valid(reliability) {
            return Err(common::value_out_of_range_error());
        }
        self.reliability = reliability;
        Ok(())
    }
}

#[cfg(test)]
mod bip6_tests;
#[cfg(test)]
mod foreign_pending_tests;
#[cfg(test)]
mod mode_tests;
#[cfg(test)]
mod multicast_tests;
#[cfg(test)]
mod nat_pending_tests;
#[cfg(test)]
mod pending_tests;
#[cfg(test)]
mod required_rows_tests;
#[cfg(test)]
mod round_trip_tests;
#[cfg(test)]
mod tests;
