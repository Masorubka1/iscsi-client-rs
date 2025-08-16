use anyhow::Result;
use enum_dispatch::enum_dispatch;

use crate::{cfg::config::Config, models::opcode::BhsOpcode};

pub const HEADER_LEN: usize = 48;

/// Common helper-trait for PDUs that may be fragmented into several
/// wire-frames (RFC 7143 ― “F”/“C” bits).
///
/// *Most* iSCSI PDUs are transferred in a single frame, but a few
/// (Text, Login, SCSI Command/Data, …) allow the sender to split the
/// **Data-Segment** into a sequence of chunks whose order is determined
/// by the transport; the target relies only on the *Continue* and *Final*
/// flags found in byte 1 of every Basic-Header-Segment.
///
/// Implementing `SendingData` lets generic helpers (e.g. the
/// `PDUWithData` builder or the `Connection` read-loop) toggle and query
/// those flags **without** knowing the concrete PDU type.
///
/// ### Contract
///
/// | method                | meaning in sender’s point of view                                     | must keep invariant                       |
/// |-----------------------|------------------------------------------------------------------------|-------------------------------------------|
/// | `get_final_bit()`     | `true` ⇒ this frame is the **last** one of the sequence               |                                           |
/// | `set_final_bit()`     | set *F = 1* **and** (if applicable) clear *C = 1*                     | after call, `get_final_bit()==true`       |
/// | `get_continue_bit()`  | `true` ⇒ **at least one** more frame will follow                      |                                           |
/// | `set_continue_bit()`  | clear *F* and set *C* so that the receiver expects more frames        | after call, `get_continue_bit()==true`    |
///
/// ### Notes
///
/// * A well-formed PDU **cannot** have both *F=1* **and** *C=1*.
///   Implementations should enforce that when toggling the flags.
/// * PDUs that are always single-framed (e.g. NOP-In/Out) may implement these
///   methods as *no-ops* or even panic if someone attempts to change the flag.
/// * The trait is kept separate from `BasicHeaderSegment` so that it can also
///   be used for helper wrappers that are not themselves BHS types (e.g.
///   composite builders).
#[enum_dispatch]
pub trait SendingData: Sized {
    /// Return the current state of the **Final (F)** bit.
    fn get_final_bit(&self) -> bool;

    /// Force **F = 1** (and, if your PDU has it, clear **C**).
    fn set_final_bit(&mut self);

    /// Return the current state of the **Continue (C)** bit.
    fn get_continue_bit(&self) -> bool;

    /// Force **C = 1** (and clear **F**).
    fn set_continue_bit(&mut self);
}

/// Common functionality for any iSCSI PDU “Basic Header Segment” (BHS).
///
/// A BHS is always 48 bytes long; higher‐level PDUs then may
/// carry additional AHS sections, a variable-length DataSegment,
/// and optional digests.  This trait encapsulates:
/// 1. extracting lengths out of the BHS,
/// 2. appending to the DataSegment,
/// 3. and finally building the full wire format.
#[enum_dispatch]
pub trait BasicHeaderSegment: Sized + SendingData {
    fn to_bhs_bytes(&self) -> Result<[u8; HEADER_LEN]>;

    /// first u8 of BHS
    fn get_opcode(&self) -> &BhsOpcode;

    /// Expose Initiator Task Tag of this PDU
    fn get_initiator_task_tag(&self) -> u32;

    /// Number of extra AHS bytes (always a multiple of 4).
    fn get_ahs_length_bytes(&self) -> usize;

    /// Number of extra AHS bytes (always a multiple of 4).
    fn set_ahs_length_bytes(&mut self, len: u8);

    /// Get number of actual payload bytes in the DataSegment.
    fn get_data_length_bytes(&self) -> usize;

    /// Set number of actual payload bytes in the DataSegment.
    fn set_data_length_bytes(&mut self, len: u32);

    /// Number of actual payload bytes in the DataSegment.
    fn total_length_bytes(&self) -> usize {
        let padding_ahs = (4 - (self.get_ahs_length_bytes() % 4)) % 4;
        let padding_data_segment = (4 - (self.get_data_length_bytes() % 4)) % 4;
        HEADER_LEN
            + self.get_ahs_length_bytes()
            + padding_ahs
            + self.get_data_length_bytes()
            + padding_data_segment
    }
}

/// A helper-trait for **builder objects** that construct a complete
/// iSCSI PDU: a 48-byte Basic-Header-Segment (BHS) plus the optional
/// **Data-Segment** and digests.
///
/// The concrete type that implements `Builder` usually owns a
/// *(header + payload)* pair and offers additional, PDU-specific setter
/// methods (e.g. `.lun( … )`, `.read()`, …).
///
/// When your application is ready to send the packet you call
/// [`Builder::build`]; the helper splits the payload into chunks that
/// respect *MaxRecvDataSegmentLength* and automatically toggles the
/// **F/C** bits on the header copies.
///
/// ### Associated type
///
/// * `Header` — the *encoded* header bytes returned by `build`.  For most
///   builders this will be `Vec<u8>` or `[u8; 48]`.
///
/// ### Required methods
///
/// * **`append_data(&mut self, more)`** Extends the internal payload buffer
///   with `more` and updates the `DataSegmentLength` field inside the owned
///   header **immediately**. The method mutates `self`; it does **not** return
///   a new builder.
///
/// * **`build(&mut self, cfg)`** Consumes the builder and returns a vector of
///   `(header, body)` tuples.  Each tuple represents **one** wire-frame to be
///   written:
///
///   1. The header slice’s length is always 48 bytes.
///   2. The payload slice may be empty (`Vec::new()`) for PDUs that carry only
///      a header.
///   3. The method splits the payload into
///      `cfg.login.negotiation.max_recv_data_segment_length` sized chunks and
///      sets the **Continue** / **Final** flags accordingly.
///
///   The caller is expected to serialise the returned frames *in order*.
///
/// ### Example
///
/// ```no_run
/// # use anyhow::Result;
/// # use iscsi_client_rs::models::{common::Builder, command::request::ScsiCommandRequestBuilder};
/// # use iscsi_client_rs::cfg::config::Config;
/// # fn send(cfg: &Config) -> Result<()> {
/// let mut req = ScsiCommandRequestBuilder::new()
///     .lun(&[0;8])
///     .read()
///     .finall();
///
/// req.append_data(vec![0xde, 0xad, 0xbe, 0xef]);
///
/// for (hdr, body) in req.build(cfg)? {
///     // socket.write_all(&hdr).await?;
///     // socket.write_all(&body).await?;
/// }
/// # Ok(())
/// # }
/// ```
pub trait Builder: Sized {
    /// The concrete buffer type used to return the encoded header.
    type Header: AsRef<[u8]>;

    /// Append raw bytes to the **Data-Segment** and update the
    /// `DataSegmentLength` field inside the owned header.
    fn append_data(&mut self, more: Vec<u8>);

    /// Finish the builder and produce one or more ready-to-send
    /// `(header_bytes, data_bytes)` frames.
    ///
    /// The `cfg` parameter is typically used to honour negotiated session
    /// limits such as *MaxRecvDataSegmentLength*.
    fn build(&mut self, cfg: &Config) -> Result<(Self::Header, Vec<u8>)>;
}
