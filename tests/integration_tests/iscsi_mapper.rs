use std::{collections::HashMap, env, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use iscsi_client_rs::{
    cfg::{config::Config, logger::init_logger},
    client::{client::ClientConnection, common::RawPdu, pdu_connection::FromBytes},
    models::{
        command::{request::ScsiCommandRequest, response::ScsiCommandResponse},
        common::{BasicHeaderSegment, Builder, HEADER_LEN},
        data::{request::ScsiDataOut, response::ScsiDataIn},
        data_fromat::PDUWithData,
        login::{request::LoginRequest, response::LoginResponse},
        logout::{request::LogoutRequest, response::LogoutResponse},
        nop::{request::NopOutRequest, response::NopInResponse},
        opcode::{BhsOpcode, IfFlags, Opcode},
        parse::Pdu,
        ready_2_transfer::response::ReadyToTransfer,
        reject::{reject_description::RejectReason, response::RejectPdu},
        text::{request::TextRequest, response::TextResponse},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    time::timeout,
};
use tracing::{debug, error, info, warn};

pub fn test_path() -> String {
    std::env::var("TEST_CONFIG").unwrap_or_else(|_| "tests/config.yaml".into())
}

pub fn load_config() -> Result<Config> {
    let pb = PathBuf::from(test_path());
    let cfg = Config::load_from_file(&pb).context(format!("failed to load {pb:?}"))?;
    Ok(cfg)
}

#[allow(dead_code)]
#[tokio::main]
async fn main() -> Result<()> {
    let _lg = init_logger("tests/config_logger.yaml").ok();

    let listen =
        std::env::var("MAPPER_LISTEN").unwrap_or_else(|_| "127.0.0.1:36260".into());
    let target = std::env::var("TARGET_ADDR").unwrap_or_else(|_| "127.0.0.1:3260".into());

    let listener = TcpListener::bind(&listen).await?;
    info!("iSCSI mapper listening on {listen}");
    info!("Forwarding to target {target}");

    loop {
        let (mut cli, addr) = listener.accept().await?;
        let target_addr = target.clone();

        tokio::spawn(async move {
            match TcpStream::connect(&target_addr).await {
                Ok(srv) => {
                    if let Err(e) = handle(&mut cli, srv).await {
                        warn!("session {addr} closed: {e:#}");
                    }
                },
                Err(e) => {
                    error!("connect to target failed: {e:#}");
                    let _ = cli.shutdown().await;
                },
            }
        });
    }
}

async fn read_one(r: &mut (impl AsyncReadExt + Unpin)) -> Result<RawPdu> {
    let mut last_hdr_with_updated_data = [0u8; HEADER_LEN];
    r.read_exact(&mut last_hdr_with_updated_data)
        .await
        .context("read BHS")?;

    let pdu = Pdu::from_bhs_bytes(&last_hdr_with_updated_data)?;

    let mut data = vec![0u8; pdu.total_length_bytes() - HEADER_LEN];
    if pdu.total_length_bytes() - HEADER_LEN > 0 {
        r.read_exact(&mut data).await.context("read rest")?;
    }
    Ok(RawPdu {
        last_hdr_with_updated_data,
        data,
    })
}

fn get_u32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_be_bytes());
}
fn opcode(b: &[u8]) -> u8 {
    b[0] & 0x3f
}

#[derive(Clone)]
struct DirParams {
    header_digest: bool,
    data_digest: bool,
    mrdsl: usize,
}
impl Default for DirParams {
    fn default() -> Self {
        Self {
            header_digest: false,
            data_digest: false,
            mrdsl: 262_144,
        }
    }
}

#[derive(Default)]
struct SeqDelta {
    d_cmd: Option<i64>,
    d_stat: Option<i64>,
    anchor_statsn: Option<u32>,
    anchor_expcmd: Option<u32>,
    have_anchors: bool,
}
impl SeqDelta {
    fn learn_from_t2i(&mut self, bhs: &[u8]) {
        if !self.have_anchors {
            self.anchor_statsn = Some(get_u32(bhs, 24)); // StatSN(real)
            self.anchor_expcmd = Some(get_u32(bhs, 28)); // ExpCmdSN(real)
            self.have_anchors = true;
            debug!(
                "anchors: StatSN(real)={} ExpCmdSN(real)={}",
                self.anchor_statsn.expect("anchor stat"),
                self.anchor_expcmd.expect("anchor expcmd")
            );
        }
    }

    fn apply_t2i_bhs(&self, bhs: &mut [u8]) {
        let dstat = self.d_stat.unwrap_or(0);
        let dcmd = self.d_cmd.unwrap_or(0);
        let stat = get_u32(bhs, 24) as i64 - dstat;
        let expc = get_u32(bhs, 28) as i64 - dcmd;
        let maxc = get_u32(bhs, 32) as i64 - dcmd;
        put_u32(bhs, 24, stat as u32); // StatSN
        put_u32(bhs, 28, expc as u32); // ExpCmdSN
        put_u32(bhs, 32, maxc as u32); // MaxCmdSN
    }
}

#[derive(Default)]
struct SessionState {
    i2t: DirParams,
    t2i: DirParams,
    sn: SeqDelta,
}

fn parse_text_kv(data: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for part in data.split(|&b| b == 0) {
        if part.is_empty() {
            continue;
        }
        let s = String::from_utf8_lossy(part);
        if let Some((k, v)) = s.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    map
}
fn digest_yes(v: &str) -> bool {
    matches!(v.to_ascii_uppercase().as_str(), "CRC32C" | "YES" | "TRUE")
}

fn try_update_negotiation_from_login_req(
    state: &mut SessionState,
    pdu: &PDUWithData<LoginRequest>,
) {
    let kv = parse_text_kv(&pdu.data);
    if let Some(v) = kv.get("MaxRecvDataSegmentLength")
        && let Ok(n) = v.parse::<usize>()
    {
        state.t2i.mrdsl = n.max(1);
        debug!("neg: initiator MRDSL(t2i)={}", n);
    }
    if let Some(v) = kv.get("HeaderDigest") {
        state.t2i.header_digest = digest_yes(v);
        debug!(
            "neg: initiator HeaderDigest(t2i)={}",
            state.t2i.header_digest
        );
    }
    if let Some(v) = kv.get("DataDigest") {
        state.t2i.data_digest = digest_yes(v);
        debug!("neg: initiator DataDigest(t2i)={}", state.t2i.data_digest);
    }
}
fn try_update_negotiation_from_login_resp(
    state: &mut SessionState,
    pdu: &PDUWithData<LoginResponse>,
) {
    let kv = parse_text_kv(&pdu.data);
    if let Some(v) = kv.get("MaxRecvDataSegmentLength")
        && let Ok(n) = v.parse::<usize>()
    {
        state.i2t.mrdsl = n.max(1);
        debug!("neg: target MRDSL(i2t)={}", n);
    }
    if let Some(v) = kv.get("HeaderDigest") {
        state.i2t.header_digest = digest_yes(v);
        debug!("neg: target HeaderDigest(i2t)={}", state.i2t.header_digest);
    }
    if let Some(v) = kv.get("DataDigest") {
        state.i2t.data_digest = digest_yes(v);
        debug!("neg: target DataDigest(i2t)={}", state.i2t.data_digest);
    }
}

fn bhs_fix_logout_reason(mut bhs: [u8; HEADER_LEN]) -> [u8; HEADER_LEN] {
    let opc = opcode(&bhs);
    if opc == Opcode::LogoutReq as u8 || opc == Opcode::LogoutResp as u8 {
        bhs[1] &= 0x7f;
    }
    bhs
}

fn dur_env(var: &str, default_ms: u64) -> Duration {
    env::var(var)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(Duration::from_millis(default_ms))
}

async fn write_all_timeout<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    buf: &[u8],
    to: Duration,
    what: &'static str,
) -> Result<()> {
    timeout(to, w.write_all(buf))
        .await
        .map_err(|_| anyhow!("write timeout for {what} after {:?}", to))??;
    Ok(())
}

async fn build_and_send_i2t<T>(
    pdu: PDUWithData<T>,
    _state: &Arc<Mutex<SessionState>>,
    conn: &Arc<ClientConnection>,
) -> Result<()>
where
    T: BasicHeaderSegment + FromBytes + std::fmt::Debug,
{
    conn.send_segment(pdu).await
}

async fn build_and_send_t2i<T>(
    mut pdu: PDUWithData<T>,
    state: &Arc<Mutex<SessionState>>,
    w: &mut (impl AsyncWriteExt + Unpin),
) -> Result<()>
where
    T: BasicHeaderSegment + FromBytes,
{
    let cfg = load_config()?;
    let write_to = dur_env("MAPPER_WRITE_TIMEOUT_MS", 10_00);

    let frames = vec![pdu.build(&cfg)?];
    for mut pair in frames {
        let (ref mut bhs, ref body) = pair;
        {
            let mut st = state.lock().await;
            st.sn.learn_from_t2i(bhs);

            let stat_in = get_u32(bhs, 24);
            let expc_in = get_u32(bhs, 28);
            let maxc_in = get_u32(bhs, 32);

            st.sn.apply_t2i_bhs(bhs);

            debug!(
                "T->I {:?} StatSN {}→{}  ExpCmdSN {}→{}  MaxCmdSN {}→{}",
                BhsOpcode::try_from(bhs[0])?,
                stat_in,
                get_u32(bhs, 24),
                expc_in,
                get_u32(bhs, 28),
                maxc_in,
                get_u32(bhs, 32)
            );
        }

        write_all_timeout(w, bhs, write_to, "BHS").await?;
        if !body.is_empty() {
            write_all_timeout(w, body, write_to, "Data/AHS").await?;
        }
    }
    Ok(())
}

async fn route_i2t(
    raw: RawPdu,
    state: &Arc<Mutex<SessionState>>,
    conn: &Arc<ClientConnection>,
) -> Result<()> {
    let bhs_fixed = bhs_fix_logout_reason(raw.last_hdr_with_updated_data);
    let (hd, dd, _mrdsl) = {
        let st = state.lock().await;
        (st.i2t.header_digest, st.i2t.data_digest, st.i2t.mrdsl)
    };

    match Pdu::from_bhs_bytes(&bhs_fixed)? {
        Pdu::LoginRequest(h) => {
            let p = PDUWithData::<LoginRequest>::parse(h, &raw.data, hd, dd)?;
            {
                let mut st = state.lock().await;
                try_update_negotiation_from_login_req(&mut st, &p);
            }
            build_and_send_i2t(p, state, conn).await
        },
        Pdu::TextRequest(h) => {
            let p = PDUWithData::<TextRequest>::parse(h, &raw.data, hd, dd)?;
            {
                let mut st = state.lock().await;
                let kv = parse_text_kv(&p.data);
                if let Some(v) = kv.get("MaxRecvDataSegmentLength")
                    && let Ok(n) = v.parse::<usize>()
                {
                    st.t2i.mrdsl = n.max(1);
                    debug!("neg(Text): initiator MRDSL(t2i)={}", n);
                }
            }
            build_and_send_i2t(p, state, conn).await
        },
        Pdu::NopOutRequest(h) => {
            build_and_send_i2t(
                PDUWithData::<NopOutRequest>::parse(h, &raw.data, hd, dd)?,
                state,
                conn,
            )
            .await
        },
        Pdu::ScsiCommandRequest(h) => {
            build_and_send_i2t(
                PDUWithData::<ScsiCommandRequest>::parse(h, &raw.data, hd, dd)?,
                state,
                conn,
            )
            .await
        },
        Pdu::ScsiDataOut(h) => {
            build_and_send_i2t(
                PDUWithData::<ScsiDataOut>::parse(h, &raw.data, hd, dd)?,
                state,
                conn,
            )
            .await
        },
        Pdu::LogoutRequest(h) => {
            build_and_send_i2t(
                PDUWithData::<LogoutRequest>::parse(h, &raw.data, hd, dd)?,
                state,
                conn,
            )
            .await
        },
        Pdu::RejectPdu(h) => {
            build_and_send_i2t(
                PDUWithData::<RejectPdu>::parse(h, &raw.data, hd, dd)?,
                state,
                conn,
            )
            .await
        },
        _ => bail!(
            "unexpected response PDU on initiator->target: opcode=0x{:02x}",
            opcode(&bhs_fixed)
        ),
    }
}

async fn route_t2i(
    raw: RawPdu,
    state: &Arc<Mutex<SessionState>>,
    w: &mut (impl AsyncWriteExt + Unpin),
) -> Result<()> {
    let bhs_fixed = bhs_fix_logout_reason(raw.last_hdr_with_updated_data);
    let (hd, dd, _mrdsl) = {
        let st = state.lock().await;
        (st.t2i.header_digest, st.t2i.data_digest, st.t2i.mrdsl)
    };

    match Pdu::from_bhs_bytes(&bhs_fixed)? {
        Pdu::LoginResponse(h) => {
            let p = PDUWithData::<LoginResponse>::parse(h, &raw.data, hd, dd)?;
            {
                let mut st = state.lock().await;
                try_update_negotiation_from_login_resp(&mut st, &p);
            }
            build_and_send_t2i(p, state, w).await
        },
        Pdu::TextResponse(h) => {
            let p = PDUWithData::<TextResponse>::parse(h, &raw.data, hd, dd)?;
            {
                let mut st = state.lock().await;
                let kv = parse_text_kv(&p.data);
                if let Some(v) = kv.get("MaxRecvDataSegmentLength")
                    && let Ok(n) = v.parse::<usize>()
                {
                    st.i2t.mrdsl = n.max(1);
                    debug!("neg(Text): target MRDSL(i2t)={}", n);
                }
            }
            build_and_send_t2i(p, state, w).await
        },
        Pdu::NopInResponse(h) => {
            build_and_send_t2i(
                PDUWithData::<NopInResponse>::parse(h, &raw.data, hd, dd)?,
                state,
                w,
            )
            .await
        },
        Pdu::ScsiCommandResponse(h) => {
            build_and_send_t2i(
                PDUWithData::<ScsiCommandResponse>::parse(h, &raw.data, hd, dd)?,
                state,
                w,
            )
            .await
        },
        Pdu::ScsiDataIn(h) => {
            build_and_send_t2i(
                PDUWithData::<ScsiDataIn>::parse(h, &raw.data, hd, dd)?,
                state,
                w,
            )
            .await
        },
        Pdu::ReadyToTransfer(h) => {
            build_and_send_t2i(
                PDUWithData::<ReadyToTransfer>::parse(h, &raw.data, hd, dd)?,
                state,
                w,
            )
            .await
        },
        Pdu::LogoutResponse(h) => {
            build_and_send_t2i(
                PDUWithData::<LogoutResponse>::parse(h, &raw.data, hd, dd)?,
                state,
                w,
            )
            .await
        },
        Pdu::RejectPdu(h) => {
            build_and_send_t2i(
                PDUWithData::<RejectPdu>::parse(h, &raw.data, hd, dd)?,
                state,
                w,
            )
            .await
        },
        _ => bail!(
            "unexpected request PDU on target->initiator: opcode=0x{:02x}",
            opcode(&bhs_fixed)
        ),
    }
}

async fn handle(cli: &mut TcpStream, srv: TcpStream) -> Result<()> {
    let (mut cr, cw) = cli.split();
    let (sr, sw) = srv.into_split();

    let cw = Arc::new(Mutex::new(cw));
    let state = Arc::new(Mutex::new(SessionState::default()));

    let cfg = load_config()?;
    let conn = ClientConnection::from_split_no_reader(sr, sw, cfg);

    let i2t_to = dur_env("MAPPER_I2T_READ_TIMEOUT_MS", 30_00);
    let t2i_to = dur_env("MAPPER_T2I_READ_TIMEOUT_MS", 30_00);

    // I -> T
    let st_up = Arc::clone(&state);
    let conn_up = Arc::clone(&conn);
    let cw_up = Arc::clone(&cw);
    let up = async move {
        loop {
            let raw = match timeout(i2t_to, read_one(&mut cr)).await {
                Ok(Ok(p)) => p,
                Ok(Err(e)) if e.to_string().contains("read BHS") => {
                    debug!("I->T: {e}");
                    bail!("client closed");
                },
                Ok(Err(e)) => return Err(e),
                Err(_) => bail!("I->T read timeout after {:?}", i2t_to),
            };

            if let Err(e) = route_i2t(raw, &st_up, &conn_up).await {
                warn!("parse error I->T: {e:#}");
                let mut w = cw_up.lock().await;
                send_reject(&mut *w, RejectReason::InvalidPduField)
                    .await
                    .ok();
                bail!("reject sent to initiator");
            }
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    };

    // T -> I
    let st_dn = Arc::clone(&state);
    let cw_dn = Arc::clone(&cw);
    let down = async move {
        loop {
            let mut r = conn.reader.lock().await;
            let raw = match timeout(t2i_to, read_one(&mut *r)).await {
                Ok(Ok(p)) => p,
                Ok(Err(e)) if e.to_string().contains("read BHS") => {
                    debug!("T->I: {e}");
                    bail!("target closed");
                },
                Ok(Err(e)) => return Err(e),
                Err(_) => bail!("T->I read timeout after {:?}", t2i_to),
            };
            drop(r);

            if let Err(e) = route_t2i(raw, &st_dn, &mut *cw_dn.lock().await).await {
                warn!("parse error T->I: {e:#}");
                let mut w = cw_dn.lock().await;
                send_reject(&mut *w, RejectReason::InvalidPduField)
                    .await
                    .ok();
                bail!("reject sent to initiator (target->initiator parse fail)");
            }
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    };

    tokio::select! {
        r = up => r,
        r = down => r,
    }
}

async fn send_reject(
    w: &mut (impl AsyncWriteExt + Unpin),
    reason: RejectReason,
) -> Result<()> {
    let mut rej = RejectPdu::default();
    rej.opcode = BhsOpcode {
        flags: IfFlags::from_bits_truncate(0),
        opcode: Opcode::Reject,
    };
    rej.reason = reason;
    rej.initiator_task_tag = 0xffffffff;

    let bhs = rej.to_bhs_bytes();
    let write_to = dur_env("MAPPER_WRITE_TIMEOUT_MS", 10_00);
    write_all_timeout(w, &bhs, write_to, "Reject BHS").await?;
    Ok(())
}
