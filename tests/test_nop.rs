use std::fs;

use anyhow::Result;
use hex::FromHex;
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config},
    models::{
        common::{Builder, HEADER_LEN},
        data_fromat::PDUWithData,
        nop::{
            request::{NopOutRequest, NopOutRequestBuilder},
            response::NopInResponse,
        },
        opcode::{BhsOpcode, IfFlags, Opcode},
    },
};

// Helper to load a hex fixture and decode it to a byte vector.
fn load_fixture(path: &str) -> Result<Vec<u8>> {
    let s = fs::read_to_string(path)?;
    let cleaned = s.trim().replace(|c: char| c.is_whitespace(), "");
    Ok(Vec::from_hex(&cleaned)?)
}

#[test]
fn test_nop_out_minimal() -> Result<()> {
    let cfg =
        resolve_config_path("tests/config.yaml").and_then(Config::load_from_file)?;

    let bytes = load_fixture("tests/fixtures/nop_out_request.hex")?;
    let parsed_header = NopOutRequest::from_bhs_bytes(&bytes)?;
    let parsed =
        PDUWithData::<NopOutRequest>::parse(parsed_header, &bytes, false, false)?;

    let lun = [0u8; 8];
    let itt = NopOutRequest::DEFAULT_TAG;
    let ttt = 189;
    let cmd_sn = 191;
    let exp_sn = 3699214689;

    let header_builder = NopOutRequestBuilder::new()
        .lun(&lun)
        .initiator_task_tag(itt)
        .target_task_tag(ttt)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_sn)
        .ping();

    let mut builder = PDUWithData::<NopOutRequest>::from_header(header_builder.header);

    assert_eq!(
        &builder.header, &parsed.header,
        "PDU bytes do not match fixture"
    );

    let chunks = builder.build(&cfg).expect("failed to serialize");
    assert_eq!(
        chunks.len(),
        1,
        "NOP-Out (without data) payload must be 1 chunk"
    );

    let (hdr, body) = &chunks[0];
    assert!(body.is_empty(), "NOP-Out payload must be empty");
    assert_eq!(
        &hdr[..],
        &bytes[..HEADER_LEN],
        "NOP-OUT ping header mismatch"
    );
    Ok(())
}

#[test]
fn test_nop_in_parse() -> Result<()> {
    let bytes = load_fixture("tests/fixtures/nop_in_response.hex")?;
    assert!(bytes.len() >= HEADER_LEN);

    let hdr = NopInResponse::from_bhs_bytes(&bytes[..HEADER_LEN])?;
    let parsed = PDUWithData::<NopInResponse>::parse(hdr, &bytes, false, false)?;

    assert!(parsed.data.is_empty());
    assert!(parsed.header_digest.is_none());
    assert!(parsed.data_digest.is_none());

    assert_eq!(
        parsed.header.opcode,
        BhsOpcode {
            flags: IfFlags::empty(),
            opcode: Opcode::NopIn,
        },
        "expected NOP-IN opcode 0x20"
    );
    assert_eq!(parsed.header.stat_sn, 3699214689);
    assert_eq!(parsed.header.exp_cmd_sn, 191);

    Ok(())
}

/*#[test]
fn test_nop_out_header_digest() -> Result<()> {
    let expected = load_fixture("tests/fixtures/nop_out_request_crc_header.hex")?;
    assert_eq!(expected.len(), 48);

    // build the same header with our builder, enabling header-digest
    let lun = [0u8; 8];
    let itt = 0x11112222;
    let ttt = NopInOut::DEFAULT_TAG;
    let cmd_sn = 0x33334444;
    let exp_sn = 0x55556666;
    let builder = NopOutRequestBuilder::new(lun, itt, ttt, exp_sn)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_sn)
        .with_header_digest();

    let (hdr, data) = builder.to_bytes();
    assert!(data.is_empty(), "no payload expected");

    // verify whole 48-byte header matches fixture
    assert_eq!(&hdr[..], &expected[..], "header-digest mismatch");
    Ok(())
}

#[test]
fn test_nop_out_data_digest() -> Result<()> {
    let expected = load_fixture("tests/fixtures/nop_out_request_crc_data.hex")?;
    let lun = [0u8; 8];
    let itt = 0x01020304;
    let ttt = NopInOut::DEFAULT_TAG;
    let cmd_sn = 0x0A0B0C0D;
    let exp_sn = 0x0E0F1011;
    let payload = b"HEARTBEAT".to_vec();

    let builder = NopOutRequestBuilder::new(lun, itt, ttt, exp_sn)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_sn)
        .with_data(payload)
        .with_data_digest();

    let (hdr, mut bytes) = builder.to_bytes();
    let mut actual = Vec::with_capacity(48 + bytes.len());
    actual.extend_from_slice(&hdr);
    actual.append(&mut bytes);

    assert_eq!(&actual[..], &expected[..], "data-digest mismatch");
    Ok(())
}*/
