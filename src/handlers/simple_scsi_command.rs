use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Result, bail};
use tracing::info;

use crate::{
    client::client::Connection,
    models::{
        command::{
            common::TaskAttribute, request::ScsiCommandRequestBuilder,
            response::ScsiCommandResponse,
        },
        common::{BasicHeaderSegment, Builder},
        parse::Pdu,
    },
};

/// Build a 16-byte SCSI READ(16) CDB.
///
/// - `lba`: logical block address to start reading from
/// - `blocks`: number of contiguous blocks to read
/// - `flags`: bit-fields for RDPROTECT/DPO/FUA (RFC3720 calls it ATTR_BITS)
/// - `control`: low-level control bits (usually zero)
pub fn build_read16(cdb: &mut [u8; 16], lba: u32, blocks: u32, flags: u8, control: u8) {
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
    cdb: &[u8; 16],
) -> Result<ScsiCommandResponse> {
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
        .task_attribute(TaskAttribute::Simple)
        .finall();

    info!(
        "{:?}, {}",
        builder.header,
        hex::encode(&builder.header.data)
    );

    let itt = builder.header.get_initiator_task_tag();

    conn.send_request(itt, builder).await?;

    match conn.read_response(itt).await? {
        Pdu::ScsiCommandResponse(rsp) => {
            exp_stat_sn.store(rsp.stat_sn.wrapping_add(1), Ordering::SeqCst);
            Ok(rsp)
        },
        other => bail!("got unexpected PDU: {:?}", other.get_opcode()),
    }
}

/// Build a 16-byte SCSI WRITE(16) CDB.
///
/// - `lba`     : logical block address to start writing to
/// - `blocks`  : number of contiguous blocks to write (u16)
/// - `flags`   : WRPROTECT/DPO/FUA bits (6:4 Protection, 3: DPO, 1: FUA)
/// - `control` : control byte
pub fn build_write16(cdb: &mut [u8; 16], lba: u32, blocks: u16, flags: u8, control: u8) {
    cdb[0] = 0xAA; // WRITE(10) opcode
    cdb[1] = flags; // WRPROTECT/DPO/FUA
    cdb[2..6].copy_from_slice(&lba.to_be_bytes());
    cdb[6..8].copy_from_slice(&blocks.to_be_bytes());
    cdb[8] = 0; // group number (обычно 0)
    cdb[9] = control; // control
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
    cdb: &[u8; 16],
    write_data: Vec<u8>,
) -> Result<ScsiCommandResponse> {
    // pull our sequence numbers
    let cmd_sn1 = cmd_sn.fetch_add(1, Ordering::SeqCst);
    let exp_stat_sn1 = exp_stat_sn.load(Ordering::SeqCst);
    let itt = initiator_task_tag.fetch_add(1, Ordering::SeqCst);

    let builder = ScsiCommandRequestBuilder::new()
        .lun(&lun)
        .initiator_task_tag(itt)
        .cmd_sn(cmd_sn1)
        .exp_stat_sn(exp_stat_sn1)
        .expected_data_transfer_length(write_data.len() as u32)
        .scsi_descriptor_block(cdb)
        .write()
        .finall()
        .task_attribute(TaskAttribute::Simple)
        .append_data(write_data.clone());

    info!(
        "{:?}, {}",
        builder.header,
        hex::encode(&builder.header.data)
    );

    let itt = builder.header.get_initiator_task_tag();

    conn.send_request(itt, builder).await?;

    match conn.read_response(itt).await? {
        Pdu::ScsiCommandResponse(rsp) => {
            exp_stat_sn.store(rsp.stat_sn.wrapping_add(1), Ordering::SeqCst);
            Ok(rsp)
        },
        other => bail!("got unexpected PDU: {:?}", other.get_opcode()),
    }
}
