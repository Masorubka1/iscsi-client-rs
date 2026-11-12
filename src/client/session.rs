//! Session state, command execution, and connection recovery.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::{Arc, atomic::AtomicU32};

use anyhow::{Context, Result, bail, ensure};
use dashmap::{DashMap, mapref::entry::Entry};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    cfg::config::AuthConfig,
    client::client::ClientConnection,
    models::{
        data_fromat::{self, PduResponse},
        identifiers::{Cid, Isid, IttGen, Tsih},
        login::response::LoginResponse,
        nop::response::NopInResponse,
    },
    state_machine::{
        common::StateMachineCtx, login::common::LoginCtx, nop_states::NopCtx,
    },
};

/// Lets the pool remove an exhausted session without treating ordinary command
/// errors or a temporarily absent connection as session teardown.
#[derive(Debug, thiserror::Error)]
#[error("connection recovery attempts exhausted for TSIH={tsih}, CID={cid}")]
pub(super) struct RecoveryExhausted {
    tsih: Tsih,
    cid: Cid,
}

/// Per-connection state within an iSCSI session
///
/// Represents a single TCP connection within an iSCSI session. A session may
/// have multiple connections (Multi-Connection per Session - MC/S) for
/// increased throughput.
#[derive(Debug)]
pub struct Connection {
    /// Connection ID - unique identifier for this connection within the session
    /// Identifier of this connection within its session.
    pub cid: Cid,
    /// Reference to the underlying client connection handling TCP communication
    pub conn: Arc<ClientConnection>,
    /// Next Expected StatSN (ACK). Bumped when we accept a reply from target.
    /// Used to track the sequence of status responses from the target.
    pub exp_stat_sn: Arc<AtomicU32>,
}

/// Per-session state identified by ISID+TSIH combination
///
/// Represents an iSCSI session which is a logical connection between an
/// initiator and target. A session may have multiple TCP connections
/// (Multi-Connection per Session - MC/S) for increased performance and
/// redundancy.
#[derive(Debug)]
pub struct Session {
    /// Target Session Identifying Handle - assigned by target during login
    /// Handle assigned by the target to this session.
    pub tsih: Tsih,
    /// Initiator Session ID - 6 bytes identifying the session from initiator
    /// side
    /// Identifier selected by the initiator for this session.
    pub isid: Isid,
    /// Name of the target this session is connected to
    pub target_name: Arc<str>,
    /// Map of connection ID to connection objects within this session
    pub conns: DashMap<Cid, Arc<Connection>>,

    /// CmdSN generator for numbered commands (incremented on every
    /// non-immediate command). Ensures proper command ordering.
    pub(super) cmd_sn: Arc<AtomicU32>,
    /// ITT (Initiator Task Tag) generator - unique within a session.
    /// Used to match requests with responses.
    pub(super) itt_gen: Arc<IttGen>,
    pub(super) cancel: CancellationToken,
    pub(super) max_connection_recovery_attempts: usize,
}

/// Injected session/connection state used to build a state-machine context.
#[derive(Clone)]
pub struct ExecuteEnv {
    pub conn: Arc<ClientConnection>,
    pub itt_gen: Arc<IttGen>,
    pub cmd_sn: Arc<AtomicU32>,
    pub exp_stat_sn: Arc<AtomicU32>,
}

impl Session {
    pub(super) fn insert_connection(
        self: &Arc<Self>,
        cid: Cid,
        conn: Arc<ClientConnection>,
        stat_sn: u32,
    ) -> Result<()> {
        match self.conns.entry(cid) {
            Entry::Occupied(_) => bail!("CID={cid} already exists in TSIH={}", self.tsih),
            Entry::Vacant(entry) => {
                conn.bind_session(Arc::downgrade(self), cid);
                entry.insert(Arc::new(Connection {
                    cid,
                    conn,
                    exp_stat_sn: Arc::new(AtomicU32::new(stat_sn.wrapping_add(1))),
                }));
            },
        }
        Ok(())
    }

    /// Executes a command on a connection, recovering it within the configured
    /// retry limit.
    pub async fn execute_with_ctx<Ctx, Res, Build>(
        self: &Arc<Self>,
        cid: Cid,
        build: Build,
    ) -> Result<Res>
    where
        Build: Fn(ExecuteEnv) -> Ctx,
        Ctx: StateMachineCtx<Ctx, Res>,
    {
        #[cfg(feature = "profiling-puffin")]
        profiling::function_scope!();
        let tsih = self.tsih;
        for attempt in 0..=self.max_connection_recovery_attempts {
            let conn = self
                .conns
                .get(&cid)
                .with_context(|| format!("CID={cid} not found in TSIH={tsih}"))?
                .clone();

            if conn.conn.is_poisoned() {
                warn!(
                    "TSIH={}, CID={} is poisoned before execute attempt {}",
                    tsih,
                    cid,
                    attempt + 1,
                );
            } else {
                let mut ctx = build(ExecuteEnv {
                    conn: conn.conn.clone(),
                    itt_gen: self.itt_gen.clone(),
                    cmd_sn: self.cmd_sn.clone(),
                    exp_stat_sn: conn.exp_stat_sn.clone(),
                });
                match ctx.execute(&conn.conn.stop_writes).await {
                    Ok(res) => return Ok(res),
                    Err(error) if conn.conn.is_poisoned() => {
                        warn!(
                            "TSIH={}, CID={} poisoned during execute attempt {}: {}",
                            tsih,
                            cid,
                            attempt + 1,
                            error
                        );
                    },
                    Err(error) => return Err(error),
                }
            }

            if attempt == self.max_connection_recovery_attempts {
                self.conns.remove(&cid);
                return Err(RecoveryExhausted { tsih, cid }.into());
            }

            match self.recover_connection(cid, conn.clone()).await {
                Ok(()) => {
                    debug!(
                        "recovered TSIH={}, CID={} after poisoned connection",
                        tsih, cid
                    );
                },
                Err(error) => {
                    warn!(
                        "failed to recover TSIH={}, CID={} on attempt {}: {}",
                        tsih,
                        cid,
                        attempt + 1,
                        error
                    );
                },
            }
        }

        Err(RecoveryExhausted { tsih, cid }.into())
    }

    async fn recover_connection(
        self: &Arc<Self>,
        cid: Cid,
        expected: Arc<Connection>,
    ) -> Result<()> {
        #[cfg(feature = "profiling-puffin")]
        profiling::function_scope!();
        let tsih = self.tsih;

        if let Some(current) = self.conns.get(&cid).map(|entry| entry.clone())
            && !Arc::ptr_eq(&current, &expected)
            && !current.conn.is_poisoned()
        {
            return Ok(());
        }

        let isid = self.isid;
        let cfg = expected.conn.cfg.clone();
        let mut removed = None;

        if let Some(current) = self.conns.get(&cid).map(|entry| entry.clone()) {
            if Arc::ptr_eq(&current, &expected) || current.conn.is_poisoned() {
                removed = self.conns.remove(&cid).map(|(_, conn)| conn);
            } else {
                return Ok(());
            }
        }

        let child = self.cancel.child_token();
        let recovery = async {
            let conn = ClientConnection::connect(cfg, child).await?;
            let response =
                login_connection(conn.clone(), isid, tsih, cid, &self.cancel).await?;
            let hdr = response.header_view()?;
            ensure!(
                hdr.tsih.get() == tsih.get(),
                "TSIH changed during connection recovery"
            );
            self.insert_connection(cid, conn, hdr.stat_sn.get())?;
            Ok(())
        }
        .await;

        if recovery.is_err()
            && let Some(previous) = removed
            && self.conns.get(&cid).is_none()
        {
            self.conns.insert(cid, previous);
        }

        recovery
    }

    pub(crate) async fn execute_nop_reply(
        &self,
        cid: Cid,
        pdu: data_fromat::PduResponse<NopInResponse>,
    ) -> Result<()> {
        #[cfg(feature = "profiling-puffin")]
        profiling::function_scope!();
        let tsih = self.tsih;
        let conn = self
            .conns
            .get(&cid)
            .with_context(|| format!("CID={cid} not found in TSIH={tsih}"))?
            .clone();

        let mut ctx = NopCtx::for_reply(
            conn.conn.clone(),
            &self.itt_gen,
            self.cmd_sn.clone(),
            conn.exp_stat_sn.clone(),
            pdu,
        )?;
        ctx.execute(&conn.conn.stop_writes).await?;
        Ok(())
    }
}

pub(super) async fn login_connection(
    conn: Arc<ClientConnection>,
    isid: Isid,
    tsih: Tsih,
    cid: Cid,
    cancel: &CancellationToken,
) -> Result<PduResponse<LoginResponse>> {
    let mut ctx = LoginCtx::new(conn.clone(), isid, cid, tsih);
    match &conn.cfg.login.auth {
        AuthConfig::Chap(_) => ctx.set_chap_login(),
        AuthConfig::None => ctx.set_plain_login(),
    }
    ctx.execute(cancel).await.context("login failed")
}
