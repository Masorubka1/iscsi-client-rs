[![crates.io](https://img.shields.io/crates/v/iscsi-client-rs.svg)](https://crates.io/crates/iscsi-client-rs)
[![docs.rs](https://docs.rs/iscsi-client-rs/badge.svg)](https://docs.rs/iscsi-client-rs)
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
* Support CancellationToken and Graceful shutdown
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

## ⚠️ IMPORTANT: Always use the **Pool**

All SCSI commands **must** be executed via the session **Pool**.

Why this matters:

* **Correct counters & ordering.** Pool allocates and wires `ITT`, `CmdSN`, `ExpStatSN` for each task and binds them to the right connection (CID) in a session (TSIH).
* **Channel lifecycle.** Pool creates and removes per‑ITT channels exactly once, avoiding stuck in‑flight requests.
* **Keep‑alive & unsolicited NOP‑In.** Pool auto‑replies and manages background plumbing; direct use can break this.
* **Graceful shutdown.** Pool can quiesce writers and drain in‑flight tasks cleanly.

> Do **not** call `ClientConnection::send_request` / `read_response*` directly in application code.
> Always wrap your state machine into `pool.execute_with(tsih, cid, |conn, itt, cmd_sn, exp_stat_sn| { … })`.

---

## Quick start (via Pool)

```rust
use anyhow::Result;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use iscsi_client_rs::{
    cfg::config::Config,
    client::pool_sessions::Pool,
};

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = Config::load_from_file("./config.yaml")?;
    let cancel = CancellationToken::new();

    // Create a Pool (session manager): owns connections and read loops.
    let pool: Arc<Pool> = Pool::new(cfg.clone(), cancel.clone()).await?;

    // Open a session (TSIH) + first connection (CID). Auth is taken from cfg.
    let isid: [u8; 6] = [0x0d, 0x70, 0xbc, 0x71, 0xa1, 0x22];
    let (tsih, cid) = pool.open_session_and_login(isid).await?;

    // From now on, always use pool.execute_with(tsih, cid, …) to run I/O.
    Ok(())
}
```

> If you build sessions by hand, ensure the connection is **bound**:
> `ClientConnection::bind_pool_session(pool_weak, tsih, cid)` before any I/O.
> This enables unsolicited NOP‑In auto‑replies and other internals.

---

## Examples (Pool‑first)

### NOP (keep‑alive)

```rust
use iscsi_client_rs::{
    models::nop::request::NopOutRequest,
    state_machine::nop_states::NopCtx,
};

let lun = 1u64 << 48;
pool.execute_with(tsih, cid, move |conn, itt, cmd_sn, exp_stat_sn| {
    NopCtx::new(
        conn,
        lun,
        itt,
        cmd_sn,
        exp_stat_sn,
        NopOutRequest::DEFAULT_TAG,
    )
})
.await?;
```

### READ(10)

```rust
use iscsi_client_rs::{
    control_block::read::build_read10,
    // adjust the path to your crate's ReadCtx
    state_machine::read_states::ReadCtx,
};

let lun = 1u64 << 48;
let blocks = 64u32;
let block_size = 4096u32;
let read_len = blocks * block_size;

let mut cdb = [0u8; 16];
build_read10(&mut cdb, /*lba=*/0, /*blocks=*/blocks, /*flags=*/0, /*control=*/0);

let read_outcome = pool.execute_with(tsih, cid, move |conn, itt, cmd_sn, exp_stat_sn| {
    ReadCtx::new(
        conn,
        lun,
        itt,
        cmd_sn,
        exp_stat_sn,
        read_len,
        cdb,
    )
})
.await?;

// println!("read {} bytes", read_outcome.data.len());
```

### WRITE(10) — R2T path

```rust
use iscsi_client_rs::{
    control_block::write::build_write10,
    // adjust the path to your crate's WriteCtx
    state_machine::write_states::WriteCtx,
};

let lun = 1u64 << 48;
let blocks = 64u32;
let block_size = 4096u32;
let bytes = (blocks * block_size) as usize;

let mut payload = vec![0u8; bytes];
// fill payload …

let mut cdb = [0u8; 16];
build_write10(&mut cdb, /*lba=*/0, /*blocks=*/blocks, /*flags=*/0, /*control=*/0);

pool.execute_with(tsih, cid, move |conn, itt, cmd_sn, exp_stat_sn| {
    WriteCtx::new(
        conn,
        lun,
        itt,
        cmd_sn,
        exp_stat_sn,
        cdb,
        payload,
    )
})
.await?;

// println!("write ok");
```

**Notes:**

* If `ImmediateData=Yes` **and** `len ≤ FirstBurstLength`, `WriteCtx` may send the payload in the initial `ScsiCommandRequest`. Otherwise it honors **R2T** windows and segments `Data‑Out` by `min(MRDSL, remaining_in_burst)`; the last PDU in a burst has `F=1`.
* `ReadyToTransfer` PDUs are **never** final; the Pool keeps the ITT open until the final `ScsiCommandResponse`.

---

## Anti‑pattern (don’t do this)

```rust
// ❌ Bypassing the Pool: sending requests and reading replies manually.
// This will desynchronize per‑ITT channels and leak in‑flight tasks.
let conn = /* … */;
conn.send_request(itt, pdu).await?;
let rsp = conn.read_response::<…>(itt).await?;
```

Always route through the Pool:

```rust
// ✅ Correct
pool.execute_with(tsih, cid, |conn, itt, cmd_sn, exp_stat_sn| {
    /* build your state machine here */
})
.await?;
```

---

## Concurrency pattern

Want to parallelize I/O? Launch several `execute_with` calls (different ITTs or LBAs). The Pool handles sequencing and counters.

```rust
use futures::future::try_join_all;

let tasks = (0..8).map(|k| {
    let pool = pool.clone();
    async move {
        pool.execute_with(tsih, cid, move |conn, itt, cmd_sn, exp_stat_sn| {
            /* e.g., ReadCtx::new(... different LBA/len per k ...) */
        })
        .await
    }
});

try_join_all(tasks).await?;
```

---

## Troubleshooting

* **Stuck ITTs (e.g., `left [ … ]`).** Ensure finality semantics are consistent in both the low‑level parser and `SendingData` impls:

  * **ScsiDataIn**: channel is final **only** when `F=1 && S=1` (status carried in Data‑In). If `S=0`, expect a separate `ScsiCommandResponse` and keep the channel open.
  * **ScsiCommandResponse**: always final.
  * **ReadyToTransfer (R2T)**: never final.
    These rules must match in *both* `parse::Pdu::get_final_bit()` and `ScsiDataIn`’s `SendingData::get_final_bit()`.

* **Unsolicited NOP‑In (TTT ≠ 0xffffffff) needs auto‑reply.** Make sure the connection is bound to the Pool (done automatically by `open_session_and_login`).

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

## CLI

An example CLI demonstrates discovery/login and simple I/O using the same library APIs. See `examples/` (if enabled in this version).

---

## Roadmap

A high‑level plan, tracked as **Now → Next → Later** with checkboxes. Pool‑first API is the baseline assumption.

### Now

* **Core protocol & plumbing**

  * [x] CRC32C digests (Header/Data; opt‑in)
  * [x] Unified state machines (Login, NOP, READ/WRITE)
  * [x] Opcode‑aware finality semantics (Data‑In: final iff **F=1 && S=1**; R2T: never final; ScsiCommandResponse: always final)
  * [x] **Pool‑first execution path** (per‑ITT channels; auto NOP‑In reply)
  * [ ] Discovery: **SendTargets** (Text)

* **Reliability & ergonomics**

  * [x] Structured errors with retry hints
  * [ ] Timeouts & cancellation tokens per I/O and login
  * [ ] Back‑pressure & graceful shutdown (quiesce writers, drain in‑flights)

* **Testing & CI**

  * [x] Multi‑target matrix: **tgt**, **LIO/targetcli**, **SCST**
  * [x] Byte‑exact fixtures for login/PDUs
  * [ ] Fuzzing (cargo‑fuzz / proptest) for PDUs & text keys

### Next

* **Sessions & recovery**
  * [x] Multi‑connection sessions (MC/S)
  * [ ] Reinstatement & session recovery
  * [ ] ERL1/ERL2: SNACKs, retransmit, CmdSN/StatSN windowing
* **Security**
  * [ ] Mutual CHAP (bi‑dir), strict key parsing/normalization
  * [ ] Optional TLS/TCP (when target supports it)
* **SCSI coverage**
  * [x] REPORT LUNS, INQUIRY VPD, MODE SENSE/SELECT
  * [ ] UNMAP, WRITE SAME, COMPARE‑AND‑WRITE
  * [ ] TMFs: ABORT TASK, LUN RESET, CLEAR TASK SET
  * [ ] AEN / Unit Attention flow
* **Performance**
  * [x] Zero‑copy build/parse; fewer allocs
  * [ ] Pipelining & outstanding‑cmd windows
  * [ ] Auto‑tune: MaxBurstLength, FirstBurstLength
  * [ ] Scatter‑gather for large Data‑Out
  * [ ] Benchmarks (throughput/latency) with reproducible profiles

**How we track:** create issues with labels `epic`, `proto`, `perf`, `api`, `testing`, `docs`. Link them here under the matching section.

## Contributing

We use **DCO** (Signed-off-by on each commit) and require a **CLA** (individual/entity) before the first PR.
This allows us to keep the project AGPL-only today and offer a commercial license later without recontacting contributors.

* See `CONTRIBUTING.md`, `CLA-INDIVIDUAL.md`, `CLA-ENTITY.md`.

Issues and PRs are welcome. Please run:

```bash
cargo fmt --all
cargo clippy --tests --benches -- -D warnings
cargo test
```

---

## License

AGPL-3.0-or-later. See [LICENSE-AGPL-3.0.md](./LICENSE-AGPL-3.0.md).

© 2012-2025 Andrei Maltsev

**Commercial licensing:** not available yet; if you need a proprietary license, contact [u7743837492@gmail.com](mailto:u7743837492@gmail.com) to be notified when dual licensing launches.
