//! Declared configuration for a flat application-level MS/TP port of a
//! master node.

use crate::common;
use bacnet_types::error::Error;

/// Configured MS/TP snapshot for a master node: its station, the link's
/// token-passing limits, and its baud rate. Every field is the caller's
/// configuration; none is read from a running transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MstpPortConfig {
    /// Caller-configured number; zero means unknown, 65535 is invalid.
    pub network_number: u16,
    /// Port APDU_Length: 480 with standard frames, up to 1476 with
    /// extended ones. Any Unsigned value >= 50 is permitted by the property
    /// clause.
    pub apdu_length: u32,
    /// This node's station, its one-octet MAC_Address: 0 to Max_Master.
    pub station: u8,
    /// Max_Master: the highest station the node passes the token to, at
    /// most 127.
    pub max_master: u8,
    /// Max_Info_Frames: the frames the node sends per token, at least 1.
    pub max_info_frames: u8,
    /// Baud rate, reported as Link_Speed in bits per second; zero means
    /// unknown.
    pub baud_rate: u32,
}

impl MstpPortConfig {
    pub(super) fn validate(&self) -> Result<(), Error> {
        if self.network_number == u16::MAX
            || self.apdu_length < 50
            || self.max_master > 127
            || self.station > self.max_master
            || self.max_info_frames == 0
        {
            return Err(common::value_out_of_range_error());
        }
        Ok(())
    }
}
