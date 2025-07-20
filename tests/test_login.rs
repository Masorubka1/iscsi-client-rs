use std::fs;

use anyhow::Result;
use hex::FromHex;
use iscsi_client_rs::{
    client::pdu_connection::ToBytes,
    login::{
        common::Stage,
        request::{LoginRequest, LoginRequestBuilder},
    },
};

#[test]
fn test_login_request_builder_minimal() -> Result<()> {
    let hex_str = fs::read_to_string("tests/fixtures/login_minimal.hex")?
        .trim() // убираем возможные \n
        .replace(|c: char| c.is_whitespace(), "");

    let bytes: Vec<u8> = Vec::from_hex(&hex_str).expect("Failed to decode hex fixture");
    assert_eq!(bytes.len(), 48, "fixture should decode to 48 bytes");
    let expected = LoginRequest::from_bhs_bytes(&bytes)?;

    let isid: [u8; 6] = [0, 2, 61, 0, 0, 9];
    let tsih: u16 = 0x00;

    let builder = LoginRequestBuilder::new(isid, tsih)
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .with_data(b"InitiatorName=iqn.2004-10.com.ubuntu:01:c676ed18968f\x00".to_vec())
        .with_data(b"InitiatorAlias=iscsi-vm\x00".to_vec())
        .with_data(b"TargetName=iqn.2025-07.com.example:target0\x00".to_vec())
        .with_data(b"SessionType=Normal\x00".to_vec())
        .with_data(b"HeaderDigest=None\x00".to_vec())
        .with_data(b"DataDigest=None\x00".to_vec())
        .with_data(b"DefaultTime2Wait=2\x00".to_vec())
        .with_data(b"DefaultTime2Retain=0\x00".to_vec())
        .with_data(b"IFMarker=No\x00".to_vec())
        .with_data(b"OFMarker=No\x00".to_vec())
        .with_data(b"ErrorRecoveryLevel=0\x00".to_vec())
        .with_data(b"InitialR2T=No\x00".to_vec())
        .with_data(b"ImmediateData=Yes\x00".to_vec())
        .with_data(b"MaxBurstLength=16776192\x00".to_vec())
        .with_data(b"FirstBurstLength=262144\x00".to_vec())
        .with_data(b"MaxOutstandingR2T=1\x00".to_vec())
        .with_data(b"MaxConnections=1\x00".to_vec())
        .with_data(b"DataPDUInOrder=Yes\x00".to_vec())
        .with_data(b"DataSequenceInOrder=Yes\x00".to_vec())
        .with_data(b"MaxRecvDataSegmentLength=262144\x00".to_vec());

    assert_eq!(builder.header, expected, "PDU bytes do not match fixture");

    Ok(())
}

#[test]
fn test_login_request_builder_full() -> Result<()> {
    // 1) Читаем из файла полный hex‐дамп Login Request
    let hex_str = fs::read_to_string("tests/fixtures/login_pdu.bin")?
        .trim()
        .replace(char::is_whitespace, "");
    let bytes: Vec<u8> =
        Vec::from_hex(&hex_str).expect("Failed to decode full-login fixture");

    // 2) Разбиваем на header и body/pad
    let expected_header = &bytes[..48];
    let expected = LoginRequest::from_bhs_bytes(&bytes)?;
    let expected_body = &bytes[48..];

    // 3) Параметры, соответствующие этому дампу
    let isid: [u8; 6] = [0, 2, 61, 0, 0, 9];
    let tsih: u16 = 0;
    // Сборка билдером, включая два кусочка текстовых параметров
    let builder = LoginRequestBuilder::new(isid, tsih)
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .with_data(b"InitiatorName=iqn.2004-10.com.ubuntu:01:c676ed18968f\x00".to_vec())
        .with_data(b"InitiatorAlias=iscsi-vm\x00".to_vec())
        .with_data(b"TargetName=iqn.2025-07.com.example:target0\x00".to_vec())
        .with_data(b"SessionType=Normal\x00".to_vec())
        .with_data(b"HeaderDigest=None\x00".to_vec())
        .with_data(b"DataDigest=None\x00".to_vec())
        .with_data(b"DefaultTime2Wait=2\x00".to_vec())
        .with_data(b"DefaultTime2Retain=0\x00".to_vec())
        .with_data(b"IFMarker=No\x00".to_vec())
        .with_data(b"OFMarker=No\x00".to_vec())
        .with_data(b"ErrorRecoveryLevel=0\x00".to_vec())
        .with_data(b"InitialR2T=No\x00".to_vec())
        .with_data(b"ImmediateData=Yes\x00".to_vec())
        .with_data(b"MaxBurstLength=16776192\x00".to_vec())
        .with_data(b"FirstBurstLength=262144\x00".to_vec())
        .with_data(b"MaxOutstandingR2T=1\x00".to_vec())
        .with_data(b"MaxConnections=1\x00".to_vec())
        .with_data(b"DataPDUInOrder=Yes\x00".to_vec())
        .with_data(b"DataSequenceInOrder=Yes\x00".to_vec())
        .with_data(b"MaxRecvDataSegmentLength=262144\x00".to_vec());

    assert_eq!(&builder.header, &expected, "PDU bytes do not match fixture");

    // 4) Получаем на выходе две части: заголовок и тело+pad
    let (hdr, body) = builder.to_bytes();

    // 5) Сравниваем
    assert_eq!(&hdr[..], expected_header, "BHS не совпал с дампом");
    assert_eq!(
        &body[..],
        expected_body,
        "DataSegment+pad не совпал с дампом"
    );

    Ok(())
}
