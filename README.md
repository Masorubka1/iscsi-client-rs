[![crates.io](https://img.shields.io/crates/v/iscsi-client-rs.svg)](https://crates.io/crates/iscsi-client-rs)
[![docs.rs](https://docs.rs/iscsi-client-rs/badge.svg)](https://docs.rs/iscsi-client-rs)
[![license](https://img.shields.io/crates/l/iscsi-client-rs.svg)](./LICENSE-AGPL-3.0.md)

# iscsi-client-rs

Pure-Rust iSCSI initiator library for TCP targets. It builds/parses PDUs, performs login, and runs SCSI commands asynchronously.

> Status: tested in CI against `tgt`, `LIO/targetcli`, and `TrueNAS SCALE`.

## What is here

* Login: plain and CHAP
* Pool-based session/connection management
* State machines for login, NOP, READ, WRITE, TUR, MODE SENSE, REPORT LUNS, REQUEST SENSE, INQUIRY, logout
* CRC32C header/data digests
* Multi-connection sessions and connection recovery
* No C dependencies

## Important

All SCSI I/O must go through `Pool::execute_with_ctx(...)`.

Do not call `ClientConnection::send_request` or `read_response*` directly from application code. The pool owns:

* `ITT`, `CmdSN`, `ExpStatSN`
* per-ITT response channels
* unsolicited `NOP-In` auto-replies
* graceful shutdown and poisoned-connection recovery

## Quick Start

```rust
use anyhow::Result;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use iscsi_client_rs::{
    cfg::config::Config,
    client::{client::ClientConnection, pool_sessions::Pool},
    utils::generate_isid,
};

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = Config::load_from_file("./config.yaml")?;
    let cancel = CancellationToken::new();
    let pool = Arc::new(Pool::with_cancel(&cfg, cancel.clone()));
    pool.attach_self();

    let (isid, _) = generate_isid();
    let cid = 0u16;
    let conn = ClientConnection::connect(cfg.clone(), pool.cancel_token().child_token()).await?;
    let target_name: Arc<str> = Arc::from(cfg.login.identity.target_name.clone());
    let tsih = pool.login_and_insert(target_name, isid, cid, conn).await?;

    let _ = (tsih, cid);
    Ok(())
}
```

If you assemble sessions manually, bind the connection to the pool before I/O:
`ClientConnection::bind_pool_session(pool_weak, tsih, cid)`.

## Usage

```rust
use iscsi_client_rs::{
    models::nop::request::NopOutRequest,
    state_machine::nop_states::NopCtx,
};

let lun = 1u64 << 48;
pool.execute_with_ctx(tsih, cid, move |env| {
    NopCtx::from_execute_env(env, lun, NopOutRequest::DEFAULT_TAG)
})
.await?;
```

```rust
use iscsi_client_rs::{
    control_block::read::build_read10,
    state_machine::read_states::ReadCtx,
};

let lun = 1u64 << 48;
let blocks = 64u32;
let block_size = 4096u32;
let read_len = blocks * block_size;

let mut cdb = [0u8; 16];
build_read10(&mut cdb, 0, blocks, 0, 0);

let out = pool.execute_with_ctx(tsih, cid, move |env| {
    ReadCtx::from_execute_env(env, lun, read_len, cdb)
})
.await?;

let _data = out.data;
```

```rust
use iscsi_client_rs::{
    control_block::write::build_write10,
    state_machine::write_states::WriteCtx,
};

let lun = 1u64 << 48;
let blocks = 64u32;
let block_size = 4096u32;
let mut payload = vec![0u8; (blocks * block_size) as usize];

let mut cdb = [0u8; 16];
build_write10(&mut cdb, 0, blocks, 0, 0);

pool.execute_with_ctx(tsih, cid, move |env| {
    WriteCtx::from_execute_env(env, lun, cdb, payload)
})
.await?;
```

## Concurrency

Parallel I/O is just parallel `execute_with_ctx` calls. The pool wires sequence numbers and per-request routing.

```rust
use futures::future::try_join_all;

let jobs = (0..8).map(|_| {
    let pool = pool.clone();
    async move {
        pool.execute_with_ctx(tsih, cid, move |env| {
            /* build state machine */
        })
        .await
    }
});

try_join_all(jobs).await?;
```

## Troubleshooting

* Stuck ITTs usually mean broken finality rules. `ScsiDataIn` is final only when `F=1 && S=1`; `ScsiCommandResponse` is always final; `R2T` is never final.
* Unsolicited `NOP-In` requires a pool-bound connection.
* `WRITE` may use ImmediateData for small payloads and R2T windows for the rest.

## CI

* Unit tests
* Integration matrix for `tgt`, `LIO/targetcli`, and `TrueNAS SCALE`
* Integration test binary is built once and reused across target jobs

## Roadmap

Done:

* CRC32C digests
* Pool-first API
* SendTargets discovery
* REPORT LUNS, INQUIRY VPD, MODE SENSE
* MC/S and basic connection recovery

Next:

* ERL1/ERL2 and SNACKs
* Mutual CHAP
* TLS/TCP when target supports it
* UNMAP / WRITE SAME / TMFs
* Fuzzing and benchmarks

## Contributing

We use DCO and require a CLA before the first PR. See `CONTRIBUTING.md`, `legal/CLA-INDIVIDUAL.md`, and `legal/CLA-ENTITY.md`.

Before sending changes:

```bash
cargo fmt --all
cargo clippy --tests --benches -- -D warnings
cargo test
```

## License

AGPL-3.0-or-later. See [LICENSE-AGPL-3.0.md](./LICENSE-AGPL-3.0.md).

Commercial licensing is not available yet. For future proprietary licensing, contact [u7743837492@gmail.com](mailto:u7743837492@gmail.com).
