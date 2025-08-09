use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Result, anyhow, bail};
use tracing::info;

use crate::{
    client::client::Connection,
    models::{
        command::{
            common::{ResponseCode, ScsiStatus, TaskAttribute},
            request::{ScsiCommandRequest, ScsiCommandRequestBuilder},
            response::ScsiCommandResponse,
        },
        common::Builder,
        data::{response::ScsiDataIn, sense_data::SenseData},
        data_fromat::PDUWithData,
    },
};

/// Build a padded 16-byte **SCSI READ (10)** CDB.
///
/// * `lba`     – 32-bit Logical-Block Address to start reading from
/// * `blocks`  – number of contiguous blocks to transfer (max 65 535)
/// * `flags`   – RDPROTECT / DPO / FUA bits (6:4 Protection, 3 = DPO, 1 = FUA)
/// * `control` – Control byte
///
/// The first 10 bytes follow SPC-4 §6.13; the remaining six bytes are
/// zero-padding because iSCSI always carries a 16-byte CDB field.
pub fn build_read10(cdb: &mut [u8; 16], lba: u32, blocks: u16, flags: u8, control: u8) {
    cdb.fill(0);
    cdb[0] = 0x28; // READ(10) opcode
    cdb[1] = flags;
    cdb[2..6].copy_from_slice(&lba.to_be_bytes());
    cdb[6] = 0; // Group Number (usually 0)
    cdb[7..9].copy_from_slice(&blocks.to_be_bytes());
    cdb[9] = control; // Control
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
) -> Result<PDUWithData<ScsiDataIn>> {
    let sn = cmd_sn.fetch_add(1, Ordering::SeqCst);
    let esn = exp_stat_sn.load(Ordering::SeqCst);
    let itt = initiator_task_tag.fetch_add(1, Ordering::SeqCst);

    let header = ScsiCommandRequestBuilder::new()
        .lun(&lun)
        .initiator_task_tag(itt)
        .cmd_sn(sn)
        .exp_stat_sn(esn)
        .expected_data_transfer_length(read_length)
        .scsi_descriptor_block(cdb)
        .read()
        .immediate()
        .task_attribute(TaskAttribute::Simple);

    let builder: PDUWithData<ScsiCommandRequest> =
        PDUWithData::from_header(header.header);

    info!("{:?}, {}", builder.header, hex::encode(&builder.data));

    conn.send_request(itt, builder).await?;

    match conn.read_response::<ScsiDataIn>(itt).await {
        Ok(rsp) => {
            exp_stat_sn
                .store(rsp.header.stat_sn_or_rsvd.wrapping_add(1), Ordering::SeqCst);
            Ok(rsp)
        },
        Err(other) => bail!("got unexpected PDU: {:?}", other.to_string()),
    }
}

/// Build a padded 16-byte SCSI WRITE(10) CDB.
///
/// * `lba`     – 32-bit Logical-Block Address
/// * `blocks`  – amount sequenced numbers (u16)
/// * `flags`   – WRPROTECT/DPO/FUA (bits 6:4,3,1)
/// * `control` – control bit
pub fn build_write10(cdb: &mut [u8; 16], lba: u32, blocks: u16, flags: u8, control: u8) {
    cdb.fill(0);
    cdb[0] = 0x2A; // WRITE(10)
    cdb[1] = flags;
    cdb[2..6].copy_from_slice(&lba.to_be_bytes());
    cdb[6] = 0; // group number
    cdb[7..9].copy_from_slice(&blocks.to_be_bytes());
    cdb[9] = control;
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
) -> Result<PDUWithData<ScsiCommandResponse>> {
    let cmd_sn1 = cmd_sn.fetch_add(1, Ordering::SeqCst);
    let exp_stat_sn1 = exp_stat_sn.load(Ordering::SeqCst);
    let itt = initiator_task_tag.fetch_add(1, Ordering::SeqCst);

    let header = ScsiCommandRequestBuilder::new()
        .lun(&lun)
        .initiator_task_tag(itt)
        .cmd_sn(cmd_sn1)
        .exp_stat_sn(exp_stat_sn1)
        .expected_data_transfer_length(write_data.len() as u32)
        .scsi_descriptor_block(cdb)
        .write()
        .task_attribute(TaskAttribute::Simple);

    let mut builder: PDUWithData<ScsiCommandRequest> =
        PDUWithData::from_header(header.header);

    builder.append_data(write_data.clone());

    info!("{:?}, {}", builder.header, hex::encode(&builder.data));

    conn.send_request(itt, builder).await?;

    let rsp: PDUWithData<ScsiCommandResponse> = conn.read_response(itt).await?;
    exp_stat_sn.store(rsp.header.stat_sn.wrapping_add(1), Ordering::SeqCst);

    let hdr = &rsp.header;
    if hdr.response != ResponseCode::CommandCompleted {
        bail!("SCSI WRITE failed: response code = {:?}", hdr.response);
    }
    if hdr.status != ScsiStatus::Good {
        let sense = SenseData::parse(&rsp.data)
            .map_err(|e| anyhow!("failed parsing sense data: {}", e))?;
        bail!(
            "SCSI WRITE failed {:?}\nInfo from sense: ({:?})",
            hdr,
            sense
        );
    }

    Ok(rsp)
}
