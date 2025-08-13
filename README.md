[![crates.io](https://img.shields.io/crates/v/iscsi-client-rs.svg)](https://crates.io/crates/iscsi-client-rs)
[![docs.rs](https://docs.rs/iscsi-client-rs/badge.svg)](https://docs.rs/iscsi-client-rs)
[![CI](https://github.com/your-org/iscsi-client-rs/workflows/CI/badge.svg)](https://github.com/Masorubka1/iscsi-client-rs/actions)
[![license](https://img.shields.io/crates/l/iscsi-client-rs.svg)](LICENSE)

# iscsi-client-rs

A pure‑Rust iSCSI initiator **library** (with example CLI) for interacting with iSCSI targets over TCP. Build/parse PDUs, perform login (plain or CHAP), and exchange SCSI commands asynchronously.

> ⚠️ **Status**: tested against Linux `tgt` only. Other targets may behave differently. Use with care.

---

## Features

* iSCSI Login across **Security → Operational → Full‑Feature** phases
* **CHAP** (MD5) authentication (challenge parsing + response building)
* Plain login (no authentication)
* Async networking via **Tokio**
* High‑level state machines for:
  * **Login** (plain & CHAP)
  * **NOP** (Nop-Out / Nop-In)
  * **SCSI READ(10)** (Data-In)
  * **SCSI WRITE(10)** (Data-Out; ImmediateData path)
* Zero C dependencies

---

## Quick start

### Install

```toml
# Cargo.toml
[dependencies]
iscsi-client-rs = "*"
```

### Connect + login (state machine)

```rust
use std::sync::{Arc, atomic::{AtomicU32, Ordering}};
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::{Config, AuthConfig}},
    client::client::Connection,
    state_machine::login::{LoginCtx, start_plain, start_chap, run_login, LoginStates},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load config
    let cfg_path = resolve_config_path("./config.yaml")?;
    let cfg = Config::load_from_file(cfg_path)?;

    // Connect
    let conn = Connection::connect(cfg.clone()).await?; // Arc<Connection>

    // ISID and CID you control; ITT=0 for login flow
    let isid: [u8; 6] = [0, 2, 61, 0, 0, 14];
    let cid: u16 = 1;
    let itt: u32 = 0;

    // Build context and choose branch by auth
    let mut lctx = LoginCtx::new(Arc::clone(&conn), &cfg, isid, cid, itt);
    let start: LoginStates = match cfg.login.auth {
        AuthConfig::Chap(_) => start_chap(),
        AuthConfig::None    => start_plain(),
    };

    let st = run_login(start, &mut lctx).await?; // LoginStatus

    // Seed counters for SCSI traffic using login response
    let cmd_sn = AtomicU32::new(st.exp_cmd_sn);
    let exp_stat_sn = AtomicU32::new(st.stat_sn.wrapping_add(1));
    let itt_ctr = AtomicU32::new(1); // non-zero ITT for I/O

    // ... now you can run NOP/READ/WRITE state machines
    Ok(())
}
```

---

## Architecture overview

### Connection & PDU framing

`Connection` wraps a Tokio TCP stream and frames iSCSI PDUs by their 48‑byte BHS. It:

* writes PDUs via `ToBytes`
* reads headers + payload with a timeout
* coalesces multi‑segment payloads using `Continue`/`Final` bits
* completes a pending request by **Initiator Task Tag (ITT)** and delivers a fully reconstructed `PDUWithData<T>` to the caller

### Sequence & task numbers

* **ITT** (Initiator Task Tag): request correlation per command/flow
* **CmdSN** / **ExpStatSN**: maintained by caller; on responses we bump `ExpStatSN = stat_sn + 1`

Utility builders produce PDUs with correct fields; state machines update counters for you at the right moments.

---

## Login state machine

Two branches share a common context `LoginCtx` and output `LoginStatus`.

* **Plain**: single step — `Operational → FullFeature` + login keys
* **CHAP**: four steps

  1. `Security → Security` — advertise security keys (no `CHAP_A`)
  2. `Security → Security` — send `CHAP_A=5`
  3. `Security → Operational (Transit)` — compute `CHAP_R` from `CHAP_I`/`CHAP_C`, send `CHAP_N`/`CHAP_R`
  4. `Operational → FullFeature (Transit)` — send operational keys

APIs:

```rust
// Pick a branch and run until Done
pub fn start_plain() -> LoginStates;
pub fn start_chap()  -> LoginStates;
pub async fn run_login(state: LoginStates, ctx: &mut LoginCtx<'_>) -> anyhow::Result<LoginStatus>;
```

**CHAP details**

* Parses challenge text for `CHAP_I` and `CHAP_C` (accepts `0x…` or raw hex)
* Computes `CHAP_R = MD5( one-octet CHAP_I || secret || challenge )` as **uppercase hex with `0x` prefix**

---

## NOP state machine

Ping the target and verify `ExpStatSN` handling.

```rust
use iscsi_client_rs::state_machine::nop::{
    NopCtx, NopStates, Idle, run_nop
};

let lun = [0,1,0,0,0,0,0,0];
let ttt = iscsi_client_rs::models::nop::request::NopOutRequest::DEFAULT_TAG;
let mut nctx = NopCtx::new(conn.clone(), lun, &itt_ctr, &cmd_sn, &exp_stat_sn, ttt);

// one round trip
let _st = run_nop(NopStates::Idle(Idle), &mut nctx).await?;
```

---

## SCSI commands

### READ(10) state machine (Data‑In)

* `ReadStart` — sends `SCSI READ(10)` (16‑byte padded CDB) and records counters
* `ReadWait`  — drains **all** `ScsiDataIn` fragments, appends data, updates `ExpStatSN` on the fragment that carries `stat_sn`, and returns the assembled buffer

```rust
use iscsi_client_rs::scsi::{build_read10};
use iscsi_client_rs::state_machine::read::{
    ReadCtx, ReadStates, ReadStart, run_read
};

let mut cdb = [0u8; 16];
build_read10(&mut cdb, /*lba=*/0, /*blocks=*/8, /*flags=*/0, /*control=*/0);

let mut rctx = ReadCtx {
    conn: conn.clone(),
    lun: [0,1,0,0,0,0,0,0],
    itt: &itt_ctr,
    cmd_sn: &cmd_sn,
    exp_stat_sn: &exp_stat_sn,
    expected: 8 * 512, // bytes
    cdb,
};

let rr = run_read(ReadStates::Start(ReadStart), &mut rctx).await?;
println!("read {} bytes", rr.data.len());
```

### WRITE(10) state machine (Data‑Out)

Two paths:

* **ImmediateData** (supported): if negotiated `ImmediateData=Yes` and payload ≤ `FirstBurstLength`, data is embedded into the `ScsiCommandRequest` and sent in one go; we then wait for `ScsiCommandResponse` and validate `ResponseCode`/`Status`.
* **R2T** (WIP): if `ImmediateData=No` or payload is larger, the target may issue **R2T**. Full Data‑Out sequencing (respecting `MaxBurstLength` and `MaxRecvDataSegmentLength`) is on the roadmap. Currently returns an error: `R2T not implemented`.

```rust
use iscsi_client_rs::scsi::build_write10;
use iscsi_client_rs::state_machine::write::{
    WriteCtx, WriteStates, WriteStart, run_write
};

let mut cdb = [0u8; 16];
build_write10(&mut cdb, /*lba=*/0, /*blocks=*/8, /*flags=*/0, /*control=*/0);

let mut wctx = WriteCtx {
    conn: conn.clone(),
    lun: [0,1,0,0,0,0,0,0],
    itt: &itt_ctr,
    cmd_sn: &cmd_sn,
    exp_stat_sn: &exp_stat_sn,
    first_burst: 262_144,
    immediate_ok: true,
    cdb,
    data: vec![0u8; 4096],
};

let ws = run_write(WriteStates::Start(WriteStart), &mut wctx).await?;
println!("write ok: itt={} cmd_sn={} exp_stat_sn={}", ws.itt, ws.cmd_sn, ws.exp_stat_sn);
```

---

## Testing

Fixture‑driven tests validate parsing and key ordering without mocks.

**Current status (integration):**
Right now we test by running the real client against a real target in Docker (typically tgt) and executing the main entrypoint. This gives us end-to-end coverage over TCP and exercises login (Plain/CHAP), NOP, and SCSI READ/WRITE.

**Typical flow:**
	*1.	Start a local iSCSI target in Docker (e.g., tgt) with a simple LUN and, if desired, CHAP enabled.
	*2.	Run the client with your test config (plain or CHAP) and observe PDUs / traces.

**Run unit tests:**

```bash
cargo test --tests --no-fail-fast --verbose
```

**Run inegrational tests:**

```bash
docker run -d --name my-tgt \
    -p 3260:3260 \
    -e TGT_IQN=iqn.2025-08.example:disk0 \
    -e TGT_SIZE_MB=500 \
    -e TGT_CHAP_USER=testuser \
    -e TGT_CHAP_PASS=secretpass \
    iscsi-tgtd

cargo run
```

---

## CLI

An example CLI demonstrates discovery/login and simple I/O using the same library APIs. See `examples/` (if enabled in this version).

---

## Roadmap

**Protocol & features**
	* Header/Data digests (CRC32C) with optional NIC offload
	* Multi-connection sessions (MC/S), connection reinstatement, session recovery
	* Error Recovery Levels (ERL1/ERL2): SNACKs, data retransmit, CmdSN/StatSN windowing
	* Mutual CHAP (bi-directional auth), CHAP key normalization & strict parsing
	* Discovery: SendTargets (Text) and basic iSNS client
	* Task Management: ABORT TASK, LOGICAL UNIT RESET, CLEAR TASK SET, etc.
	* Common SCSI ops: REPORT LUNS, INQUIRY VPD, MODE SENSE/SELECT, UNMAP, WRITE SAME, COMPARE-AND-WRITE
	* Asynchronous Event Notification (AEN) / Unit Attention flow
	* IPv6, jumbo frames; optional TLS/TCP (where supported by targets)

**Performance**
	* Zero-copy buffers for PDU build/parse, fewer allocations
	* Pipelining / outstanding command windows, auto-tuning of MaxBurstLength, FirstBurstLength, ImmediateData
	* Scatter-gather for large Data-Out
	* Benchmarks suite (throughput, latency) with reproducible network profiles

**API & ergonomics**
	* Unified state_machine API for Login, NOP, READ/WRITE, TMFs (cancel/timeout/cancellation tokens)
	* Pluggable allocators/ITT strategies, wrap-around handling
	* Structured errors with retry hints; back-pressure & graceful shutdown

**Testing & CI**
	* Matrix with multiple targets (tgt, LIO/targetcli, SCST, FreeBSD ctld)
	* Deterministic packet capture & byte-for-byte fixtures for every login hop
	* Fuzzing (cargo-fuzz/proptest) for PDUs and text-key parsing
	* Long-haul stability tests (hours-long READ/WRITE with keepalives)

**Docs & examples**
	* End-to-end examples: plain login, CHAP, READ/WRITE, TMFs
	* Migration guide, troubleshooting (Auth failures, digests, ERL)
	* RFC alignment notes (7143/7144/SPC/SAM) and conformance checklist

---

## Contributing

Issues and PRs are welcome. Please run:

```bash
cargo fmt --all
cargo clippy --tests --examples --benches -- -D warnings
cargo test
```

---

## License

Licensed under either of

* Apache License, Version 2.0
* MIT license

at your option.

---

## Acknowledgments

Thanks to the iSCSI community and Linux `tgt` for a solid reference target to test against.
