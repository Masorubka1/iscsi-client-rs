// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::Result;
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config},
    models::{
        common::{BasicHeaderSegment, Builder, HEADER_LEN},
        data_fromat::{PduRequest, PduResponse},
        nop::{
            request::{NopOutRequest, NopOutRequestBuilder},
            response::NopInResponse,
        },
        opcode::{BhsOpcode, Opcode},
    },
};
use zerocopy::FromBytes;

use crate::unit_tests::{load_fixture, parse_imm, parse_mut};

#[test]
fn test_nop_out_minimal() -> Result<()> {
    let cfg =
        resolve_config_path("tests/config.yaml").and_then(Config::load_from_file)?;

    let bytes = load_fixture("tests/unit_tests/fixtures/nop/nop_out_request.hex")?;
    assert!(bytes.len() >= HEADER_LEN);

    let parsed: PduRequest<NopOutRequest> = parse_mut(&bytes, &cfg)?;
    assert!(parsed.data()?.is_empty());
    assert!(parsed.header_digest.is_none());
    assert!(parsed.data_digest.is_none());

    let itt = 1_u32;
    let lun = 0_u64;
    let ttt = NopOutRequest::DEFAULT_TAG;
    let cmd_sn = 0;
    let exp_sn = 1;

    let header_builder = NopOutRequestBuilder::new()
        .lun(lun)
        .initiator_task_tag(itt)
        .target_task_tag(ttt)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_sn)
        .immediate();

    let mut header_buf = [0u8; HEADER_LEN];
    header_builder.header.to_bhs_bytes(&mut header_buf)?;

    let mut builder = PduRequest::<NopOutRequest>::new_request(header_buf, &cfg);

    let (hdr_bytes, body) =
        &builder.build(cfg.login.flow.max_recv_data_segment_length as usize)?;

    assert!(body.is_empty(), "NOP-Out payload must be empty");

    let mut built_hdr = [0u8; HEADER_LEN];
    built_hdr.copy_from_slice(hdr_bytes.as_ref());
    assert_eq!(built_hdr, parsed.header_buf, "NOP-OUT ping header mismatch");

    Ok(())
}

#[test]
fn test_nop_in_parse() -> Result<()> {
    let cfg =
        resolve_config_path("tests/config.yaml").and_then(Config::load_from_file)?;

    let bytes = load_fixture("tests/unit_tests/fixtures/nop/nop_in_response.hex")?;
    assert!(bytes.len() >= HEADER_LEN);

    let parsed: PduResponse<NopInResponse> = parse_imm(&bytes, &cfg)?;
    assert!(parsed.data()?.is_empty());
    assert!(parsed.header_digest.is_none());
    assert!(parsed.data_digest.is_none());

    let hdr = <NopInResponse as FromBytes>::ref_from_bytes(&parsed.header_buf)
        .expect("valid NOP-In BHS");

    let op = BhsOpcode::try_from(hdr.opcode.raw())?;
    assert_eq!(op.opcode, Opcode::NopIn, "expected NOP-IN opcode 0x20");

    assert_eq!(hdr.stat_sn.get(), 3699214689);
    assert_eq!(hdr.exp_cmd_sn.get(), 191);

    Ok(())
}

#[test]
fn nop_payload_boundaries() -> Result<()> {
    let cfg =
        resolve_config_path("tests/config.yaml").and_then(Config::load_from_file)?;
    let limit = cfg.login.flow.max_recv_data_segment_length as usize;

    for len in [0, 1, 3, 4, limit - 1, limit] {
        let header = NopOutRequestBuilder::new().initiator_task_tag(1);
        let mut header_buf = [0u8; HEADER_LEN];
        header.header.to_bhs_bytes(&mut header_buf)?;

        let mut request = PduRequest::<NopOutRequest>::new_request(header_buf, &cfg);
        request.append_data(&vec![0xa5; len])?;
        let (_, body) = request.build(limit)?;

        assert_eq!(request.header_view()?.get_data_length_bytes(), len);
        assert_eq!(body.len(), len.next_multiple_of(4));
    }

    let header = NopOutRequestBuilder::new().initiator_task_tag(2);
    let mut header_buf = [0u8; HEADER_LEN];
    header.header.to_bhs_bytes(&mut header_buf)?;
    let mut oversized = PduRequest::<NopOutRequest>::new_request(header_buf, &cfg);
    oversized.append_data(&vec![0; limit + 1])?;
    assert!(oversized.build(limit).is_err());

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
