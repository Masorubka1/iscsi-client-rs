use anyhow::Result;
use iscsi_client_rs::{client::client::Connection, login::common::login_plain};
use tokio::main;

#[main]
async fn main() -> Result<()> {
    // 1) Подключаемся к (локальному) таргету
    let mut conn = Connection::connect("192.168.64.2:3260").await?;
    println!("Connected to target");

    // 2) Фаза Login
    // SHARED parameters
    let initiator_name = "iqn.2004-10.com.ubuntu:01:c676ed18968f";
    //let chap_user = "myuser";
    //let chap_secret = b"mypassword";
    let isid: [u8; 6] = [0, 2, 61, 0, 0, 9];
    let res = login_plain(&mut conn, isid, initiator_name).await?;
    println!("Res1: {res:?}");
    //login_chap(&mut conn, isid, initiator_name, chap_user, chap_secret).await?;
    /*let mut tsih: u16 = 0x00;

    let mut task_tag = 0u32;
    let mut cmd_sn = 0u32;
    let mut exp_stat_sn = 0u32;

    // 1) Security Negotiation: CSG=0, NSG=1
    let sec_req = LoginRequestBuilder::new(isid, tsih)
        .transit()
        .csg(Stage::Security)
        .nsg(Stage::Operational)
        .task_tag(task_tag)
        .connection_id(1)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_stat_sn)
        .with_data(b"InitiatorName={initiator_name}\x00".to_vec())
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

    let (resp1_headers, resp1_data, _resp1_digest): (LoginResponse, Vec<u8>, Option<usize>) =
        conn.call::<_, LoginResponse>(sec_req).await?;
    println!(
        "Resp1: {:?}\nData1: {}",
        resp1_headers,
        String::from_utf8(resp1_data.clone()).unwrap()
    );

    // Обновляем поля из ответа
    tsih = resp1_headers.tsih;
    cmd_sn = resp1_headers.exp_cmd_sn;
    exp_stat_sn = resp1_headers.max_cmd_sn;
    task_tag += 1;

    let data_text = String::from_utf8(resp1_data)?;
    let mut chap_i = None;
    let mut chap_a = None;
    let mut chap_n = None;
    for kv in data_text.split('\x00') {
        let mut parts = kv.splitn(2, '=');
        match (parts.next(), parts.next()) {
            (Some("CHAP_I"), Some(v)) => chap_i = Some(v.parse::<u8>()?),
            (Some("CHAP_A"), Some(v)) => chap_a = Some(v.parse::<u8>()?),
            (Some("CHAP_N"), Some(hex)) => chap_n = Some(hex::decode(hex)?),
            _ => {}
        }
    }
    let (chap_i, chap_n) = (chap_i.context("no CHAP_I")?, chap_n.context("no CHAP_N")?);

    let mut hasher = md5::Md5::new();
    hasher.write(&[chap_i]);
    hasher.write(chap_secret);
    hasher.write(&chap_n);
    let chap_r = hasher.result();

    // 2) Operational Negotiation: CSG=1, NSG=3
    let op_req = LoginRequestBuilder::new(isid, tsih)
        .transit()
        .cont()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature) // Operational → Full‐Feature
        .versions(resp1_headers.version_max, resp1_headers.version_active)
        .task_tag(task_tag)
        .connection_id(1)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_stat_sn)
        .with_data(format!("AuthMethod=CHAP\x00").into_bytes())
        .with_data(format!("CHAP_I={}\x00", chap_i).into_bytes())
        .with_data(format!("CHAP_R={}\x00", hex::encode(chap_r)).into_bytes())
        .with_data(format!("InitiatorName={}\x00", initiator_name).into_bytes());

    let (resp2_headers, resp2_data, _resp2_digest): (LoginResponse, Vec<u8>, Option<usize>) =
        conn.call::<_, LoginResponse>(op_req).await?;
    println!(
        "Resp2: {:?}\nData2: {}",
        resp2_headers,
        String::from_utf8(resp2_data).unwrap()
    );*/

    // 3) Фаза Full Feature: NOP-Out → NOP-In
    /*let nop_req = RequestBuilder::new(Opcode::Initiator(InitiatorOpcode::NopOut))
        .with_immediate()
        .with_task_tag(2)
        .enable_header_digest();
    conn.send_pdu(&nop_req).await?;
    let nop_resp: ScsiResponse = conn.call().await?;
    println!("Received NOP-In, opcode={:#x}", nop_resp.header.opcode);*/

    Ok(())
}
