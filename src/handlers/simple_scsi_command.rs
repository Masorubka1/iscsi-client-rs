use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Result, bail};
use tracing::info;

use crate::{
    client::client::{Connection, PduResponse},
    models::{
        command::{
            request::{ScsiCommandRequest, ScsiCommandRequestBuilder},
            response::ScsiCommandResponse,
        },
        common::Builder,
    },
};

/// Build a 12-byte SCSI READ(12) CDB.
///
/// - `lba`: logical block address to start reading from
/// - `blocks`: number of contiguous blocks to read
/// - `flags`: bit-fields for RDPROTECT/DPO/FUA (RFC3720 calls it ATTR_BITS)
/// - `control`: low-level control bits (usually zero)
pub fn build_read12(cdb: &mut [u8; 12], lba: u32, blocks: u32, flags: u8, control: u8) {
    cdb[0] = 0xA8; // READ(12) opcode
    cdb[1] = flags; // RDPROTECT/DPO/FUA bits
    cdb[2..6].copy_from_slice(&lba.to_be_bytes());
    cdb[6..10].copy_from_slice(&blocks.to_be_bytes());
    cdb[10] = 0; // group number
    cdb[11] = control; // control byte
}

/// Send a SCSI READ (Data-In) command and await the Data-In / Response PDU.
///
/// - `lun`                 — 8-byte target LUN
/// - `initiator_task_tag`  — unique tag for this command
/// - `cmd_sn`              — command sequence number
/// - `exp_stat_sn`         — expected status-sequence number
/// - `read_length`         — how many bytes to read
pub async fn send_scsi_read(
    conn: &Connection,
    lun: [u8; 8],
    initiator_task_tag: &AtomicU32,
    cmd_sn: &AtomicU32,
    exp_stat_sn: &AtomicU32,
    read_length: u32,
    cdb: &[u8; 12],
) -> Result<(ScsiCommandResponse, Vec<u8>, Option<u32>)> {
    let sn = cmd_sn.fetch_add(1, Ordering::SeqCst);
    let esn = exp_stat_sn.load(Ordering::SeqCst);
    let itt = initiator_task_tag.fetch_add(1, Ordering::SeqCst);

    let builder = ScsiCommandRequestBuilder::new()
        .lun(&lun)
        .initiator_task_tag(itt)
        .cmd_sn(sn)
        .exp_stat_sn(esn)
        .expected_data_transfer_length(read_length)
        .scsi_descriptor_block(cdb)
        .read()
        .finall();

    info!("{:?}, {}", builder.header, hex::encode(&builder.data));

    match conn
        .call::<{ ScsiCommandRequest::HEADER_LEN }, ScsiCommandResponse>(builder)
        .await?
    {
        PduResponse::Normal((hdr, data, digest)) => {
            exp_stat_sn.store(hdr.stat_sn.wrapping_add(1), Ordering::SeqCst);
            Ok((hdr, data, digest))
        },
        PduResponse::Reject((hdr, data, _)) => {
            bail!("SCSI READ rejected: {:?}\nData: {:x?}", hdr, data)
        },
    }
}

/// Build a 12-byte SCSI WRITE(12) CDB.
///
/// - `lba`     : logical block address to start writing to
/// - `blocks`  : number of contiguous blocks to write
/// - `flags`   : bit-fields for WRPROTECT/DPO/FUA (usually 0)
/// - `control` : control byte (usually 0)
pub fn build_write12(cdb: &mut [u8; 12], lba: u32, blocks: u32, flags: u8, control: u8) {
    cdb[0] = 0xAA; // WRITE(12) opcode
    cdb[1] = flags; // WRPROTECT/DPO/FUA bits
    cdb[2..6].copy_from_slice(&lba.to_be_bytes());
    cdb[6..10].copy_from_slice(&blocks.to_be_bytes());
    cdb[10] = 0; // group number
    cdb[11] = control; // control byte
}

/// Send a SCSI WRITE (Data-Out) command with payload and await the Response
/// PDU.
///
/// - `lun`                 — 8-byte target LUN
/// - `initiator_task_tag`  — unique tag for this command
/// - `cmd_sn`              — command sequence number
/// - `exp_stat_sn`         — expected status-sequence number
/// - `write_data`          — the payload to write
pub async fn send_scsi_write(
    conn: &Connection,
    lun: [u8; 8],
    initiator_task_tag: &AtomicU32,
    cmd_sn: &AtomicU32,
    exp_stat_sn: &AtomicU32,
    cdb: &[u8; 12],
    write_data: Vec<u8>,
) -> Result<(ScsiCommandResponse, String)> {
    // pull our sequence numbers
    let sn = cmd_sn.fetch_add(1, Ordering::SeqCst);
    let esn = exp_stat_sn.load(Ordering::SeqCst);
    let itt = initiator_task_tag.fetch_add(1, Ordering::SeqCst);

    // build the WRITE PDU (sets WRITE bit and data length under the hood)
    let builder = ScsiCommandRequestBuilder::new()
        .lun(&lun)
        .initiator_task_tag(itt)
        .cmd_sn(sn)
        .exp_stat_sn(esn)
        .scsi_descriptor_block(cdb)
        .write()
        .finall()
        .expected_data_transfer_length(write_data.len() as u32)
        .append_data(write_data);

    info!("{:?}, {}", builder.header, hex::encode(&builder.data));

    match conn
        .call::<{ ScsiCommandRequest::HEADER_LEN }, ScsiCommandResponse>(builder)
        .await?
    {
        PduResponse::Normal((hdr, data, _digest)) => {
            exp_stat_sn.store(hdr.stat_sn.wrapping_add(1), Ordering::SeqCst);
            Ok((hdr, String::from_utf8(data)?))
        },
        PduResponse::Reject((hdr, data, _)) => {
            bail!("SCSI WRITE rejected: {:?}\nData: {:x?}", hdr, data)
        },
    }
}
