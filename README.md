[![crates.io](https://img.shields.io/crates/v/iscsi-client-rs.svg)](https://crates.io/crates/iscsi-client-rs)
[![docs.rs](https://docs.rs/iscsi-client-rs/badge.svg)](https://docs.rs/iscsi-client-rs)
[![CI](https://github.com/your-org/iscsi-client-rs/workflows/CI/badge.svg)](https://github.com/Masorubka1/iscsi-client-rs/actions)
[![license](https://img.shields.io/crates/l/iscsi-client-rs.svg)](LICENSE)

# iscsi-client-rs

A pure‑Rust iSCSI initiator **library** (with example CLI) for interacting with iSCSI targets over TCP. Build/parse PDUs, perform login (plain or CHAP), and exchange SCSI commands asynchronously.

> ⚠️ **Status**: tested against Linux `tgt/targetcli` only. Other targets may behave differently. Use with care.

---

## Features

* iSCSI Login across **Security → Operational → Full‑Feature** phases
* **CHAP** (MD5) authentication (challenge parsing + response building)
* Plain login (no authentication)
* Async networking via **Tokio**
* High‑level state machines for:
  * **Login** (plain & CHAP)
  * **NOP** (Nop-Out / Nop-In)
  * **SCSI READ(10/16)** (Data-In)
  * **SCSI WRITE(10/16)** (Data-Out; ImmediateData path)
  * **SCSI READ CAPACITY(16)**
  * **SCSI TEST UNIT READY(6)**
  * **SCSI MODE SENSE(6/10)**
  * **SCSI REPORT LUNS(12)**
  * **SCSI REQUEST SENSE(6)**
  * **SCSI INQUIRY EVPD/VPD (6)**
  * **Logout**
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
pub async fn run_login(state: LoginStates, ctx: &mut LoginCtx<'_>) -> anyhow::Result<LoginStatus>;
```

**CHAP details**

* Parses challenge text for `CHAP_I` and `CHAP_C` (accepts `0x…` or raw hex)
* Computes `CHAP_R = MD5( one-octet CHAP_I || secret || challenge )` as **uppercase hex with `0x` prefix**

---

## NOP state machine

Ping the target and verify `ExpStatSN` handling.

```rust
let lun = [0,1,0,0,0,0,0,0];
let ttt = NopOutRequest::DEFAULT_TAG;
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

### WRITE(10) state machine (Data-Out)

Both paths are supported:

* **ImmediateData**: if `ImmediateData=Yes` **and** `data_len ≤ FirstBurstLength`, the payload is embedded in the `ScsiCommandRequest` (one PDU). We then wait for `ScsiCommandResponse` and validate `ResponseCode`/`Status`.

* **R2T (Ready-To-Transfer)**: if the payload can’t fit in ImmediateData (or the target requires R2T), we honor each **R2T** by sending one or more `Data-Out` PDUs with the provided **TTT** and **BufferOffset**. Segmentation respects the negotiated **MaxRecvDataSegmentLength (MRDSL)** and **MaxBurstLength**; the last PDU in a burst has **Final=1**. (Assumes `DataPDUInOrder=Yes` and `DataSequenceInOrder=Yes` today.)

```rust
let mut cdb = [0u8; 16];
build_write10(&mut cdb, /*lba=*/0, /*blocks=*/8, /*flags=*/0, /*control=*/0);

// The state machine will choose ImmediateData or R2T based on negotiation
// (ImmediateData, FirstBurstLength, MaxBurstLength, MRDSL).
let mut wctx = WriteCtx {
    conn: conn.clone(),
    lun: [0,1,0,0,0,0,0,0],
    itt: &itt_ctr,
    cmd_sn: &cmd_sn,
    exp_stat_sn: &exp_stat_sn,
    cdb,
    data: vec![0u8; 4096],
};

let ws = run_write(WriteStates::Start(WriteStart), &mut wctx).await?;
println!(
    "write ok: itt={} cmd_sn={} exp_stat_sn={}",
    ws.itt, ws.cmd_sn, ws.exp_stat_sn
);
```

> Notes:
>
> * If `ImmediateData=No` or the payload exceeds `FirstBurstLength`, the flow switches to R2T.
> * Each R2T defines the allowed window (offset/length); `Data-Out` PDUs are sliced to `min(MRDSL, remaining_in_burst)`.

---

# Testing via `just`

```bash
# List available libiscsi tests
just cu-list

# Bring up target + mapper and run a basic test (no CHAP)
just cu TEST_PATTERN='SCSI.Read16'

# Run the destructive CompareAndWrite suite
just cu TEST_PATTERN='ALL.CompareAndWrite.*' CU_ARGS='--dataloss'

# Run a test with CHAP enabled
just cu-chap TEST_PATTERN='SCSI.Read16' CU_ARGS=''

# Follow mapper logs
just mapper-logs

# Tear everything down
just mapper-down && just down
```

Tip: you can override addresses/ports and IQN via env vars used in your `justfile` (e.g., `MAPPER_ADDR`, `MAPPER_PORT`, `ISCSI_ADDR`, `ISCSI_PORT`, `TGT_IQN`, `TGT_LUN`).

---

## CLI

An example CLI demonstrates discovery/login and simple I/O using the same library APIs. See `examples/` (if enabled in this version).

---

# Roadmap

A high-level plan, trimmed for GitHub readability. We track delivery as **Now → Next → Later** with checkboxes.

## Now

* **Core protocol & plumbing**

  * [x] CRC32C digests (Header/Data; opt-in)
  * [ ] Unified state machine (Login, NOP, READ/WRITE)
  * [ ] Discovery: **SendTargets** (Text)
* **Reliability & ergonomics**

  * [x] Structured errors with retry hints
  * [ ] Timeouts & cancellation tokens
  * [ ] Back-pressure & graceful shutdown
* **Testing & CI**

  * [x] Multi-target matrix: **tgt**, **LIO/targetcli**, **SCST**
  * [x] Byte-exact fixtures for each login hop
  * [ ] Fuzzing (cargo-fuzz / proptest) for PDUs & text keys

## Next

* **Sessions & recovery**

  * [ ] Multi-connection sessions (MC/S)
  * [ ] Reinstatement & session recovery
  * [ ] ERL1/ERL2: SNACKs, retransmit, CmdSN/StatSN windowing
* **Security**

  * [ ] Mutual CHAP (bi-dir), strict key parsing/normalization
  * [ ] Optional TLS/TCP (when target supports it)
* **SCSI coverage**

  * [x] REPORT LUNS, INQUIRY VPD, MODE SENSE/SELECT
  * [ ] UNMAP, WRITE SAME, COMPARE-AND-WRITE
  * [ ] TMFs: ABORT TASK, LUN RESET, CLEAR TASK SET
  * [ ] AEN / Unit Attention flow
* **Performance**

  * [x] Zero-copy build/parse; fewer allocs
  * [ ] Pipelining & outstanding-cmd windows
  * [ ] Auto-tune: MaxBurstLength, FirstBurstLength
  * [ ] Scatter-gather for large Data-Out
  * [ ] Benchmarks (throughput/latency) with reproducible profiles

**How we track:** create issues with labels `epic`, `proto`, `perf`, `api`, `testing`, `docs`. Link them here under the matching section as they’re planned.


---

## Contributing

Issues and PRs are welcome. Please run:

```bash
cargo fmt --all
cargo clippy --tests --examples --benches -- -D warnings
cargo test
```

---

## Acknowledgments

Thanks to the iSCSI community and Linux `tgt` for a solid reference target to test against.
