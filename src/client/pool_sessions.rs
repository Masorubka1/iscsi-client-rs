// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{
    sync::{Arc, Weak, atomic::AtomicU32},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use dashmap::DashMap;
use once_cell::sync::OnceCell;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::{
    cfg::config::{AuthConfig, Config},
    client::client::ClientConnection,
    models::logout::common::LogoutReason,
    state_machine::{
        common::StateMachineCtx, login::common::LoginCtx, logout_states::LogoutCtx,
    },
    utils::generate_isid,
};

/// Per-connection state within an iSCSI session
///
/// Represents a single TCP connection within an iSCSI session. A session may
/// have multiple connections (Multi-Connection per Session - MC/S) for
/// increased throughput.
#[derive(Debug)]
pub struct Connection {
    /// Connection ID - unique identifier for this connection within the session
    pub cid: u16,
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
    pub tsih: u16,
    /// Initiator Session ID - 6 bytes identifying the session from initiator
    /// side
    pub isid: [u8; 6],
    /// Name of the target this session is connected to
    pub target_name: Arc<str>,
    /// Map of connection ID to connection objects within this session
    pub conns: DashMap<u16, Arc<Connection>>,

    /// CmdSN generator for numbered commands (incremented on every
    /// non-immediate command). Ensures proper command ordering.
    cmd_sn: Arc<AtomicU32>,
    /// ITT (Initiator Task Tag) generator - unique within a session.
    /// Used to match requests with responses.
    itt_gen: Arc<AtomicU32>,
}

/// Pool of iSCSI sessions and connections
///
/// Manages multiple iSCSI sessions and their associated connections. Provides
/// centralized management, resource limits, and graceful shutdown capabilities.
/// Acts as the main orchestrator for all iSCSI communication.
pub struct Pool {
    /// Map of TSIH to session objects - all active sessions
    pub sessions: DashMap<u16, Arc<Session>>,
    /// Maximum number of sessions allowed in this pool
    max_sessions: u32,
    /// Maximum number of connections per session
    max_connections: u16,
    /// Weak self-reference to avoid circular dependencies
    self_weak: OnceCell<Weak<Pool>>,

    /// Root cancellation token for the entire pool.
    /// Child tokens are passed to connections so we can abort all I/O on full
    /// shutdown.
    cancel: CancellationToken,
}

impl Pool {
    /// Create a pool with its own root cancellation token.
    pub fn new(cfg: &Config) -> Self {
        Self {
            sessions: DashMap::with_capacity(
                cfg.extra_data.connections.max_sessions as usize,
            ),
            max_sessions: cfg.extra_data.connections.max_sessions,
            max_connections: cfg.extra_data.connections.max_connections,
            self_weak: OnceCell::new(),
            cancel: CancellationToken::new(),
        }
    }

    /// Optionally construct with an external root cancellation token.
    pub fn with_cancel(cfg: &Config, cancel: CancellationToken) -> Self {
        Self {
            sessions: DashMap::with_capacity(
                cfg.extra_data.connections.max_sessions as usize,
            ),
            max_sessions: cfg.extra_data.connections.max_sessions,
            max_connections: cfg.extra_data.connections.max_connections,
            self_weak: OnceCell::new(),
            cancel,
        }
    }

    /// Expose the root token (e.g., if callers want to create siblings).
    #[inline]
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Must be called once after creating Arc<Pool>.
    pub fn attach_self(self: &Arc<Self>) {
        let _ = self.self_weak.set(Arc::downgrade(self));
    }

    /// Login all sessions sequentially.
    pub async fn login_sessions_from_cfg(&self, cfg: &Config) -> Result<Vec<u16>> {
        ensure!(self.max_sessions > 0, "max_sessions must be > 0");

        let target_name: Arc<str> = Arc::from(cfg.login.security.target_name.clone());
        let mut tsihs = Vec::with_capacity(self.max_sessions as usize);

        for _ in 0..self.max_sessions {
            let child = self.cancel.child_token();
            let conn = ClientConnection::connect(cfg.clone(), child).await?;
            let (isid, _) = generate_isid();

            let tsih = self
                .login_and_insert(target_name.clone(), isid, 0u16, conn)
                .await?;

            tsihs.push(tsih);
        }

        Ok(tsihs)
    }

    /// Login via a single TCP connection.
    /// If TSIH is unknown (new session), target will assign a non-zero TSIH.
    pub async fn login_and_insert(
        &self,
        target_name: Arc<str>,
        isid: [u8; 6],
        cid: u16,
        conn: Arc<ClientConnection>,
    ) -> Result<u16> {
        self.login_one_and_insert_impl(
            target_name,
            isid,
            /* tsih_hint */ 0,
            cid,
            conn,
        )
        .await
    }

    /// Add one more TCP connection into an existing session (known TSIH).
    pub async fn add_connection_to_session(
        &self,
        tsih: u16,
        cid: u16,
        conn: Arc<ClientConnection>,
    ) -> Result<()> {
        // Read immutable bits upfront (don't hold DashMap guards across await)
        let (target_name, isid) = {
            let sess = self
                .sessions
                .get(&tsih)
                .ok_or_else(|| anyhow::anyhow!("unknown TSIH={tsih}"))?;
            (sess.target_name.clone(), sess.isid)
        };
        let _ = self
            .login_one_and_insert_impl(target_name, isid, tsih, cid, conn)
            .await?;
        Ok(())
    }

    async fn login_one_and_insert_impl(
        &self,
        target_name: Arc<str>,
        isid: [u8; 6],
        tsih_hint: u16,
        cid: u16,
        conn: Arc<ClientConnection>,
    ) -> Result<u16> {
        let mut l = LoginCtx::new(conn.clone(), isid, cid, tsih_hint);
        match &conn.cfg.login.auth {
            AuthConfig::Chap(_) => l.set_chap_login(),
            AuthConfig::None => l.set_plain_login(),
        }

        let login_pdu = l.execute(&self.cancel).await.context("login failed")?;
        let hdr = login_pdu.header_view()?;

        let tsih = hdr.tsih.get();
        ensure!(tsih != 0, "TSIH=0 in final Login Response");

        let sess = self
            .sessions
            .entry(tsih)
            .or_insert_with(|| {
                Arc::new(Session {
                    tsih,
                    isid,
                    target_name: target_name.clone(),
                    conns: DashMap::with_capacity(self.max_connections as usize),
                    cmd_sn: Arc::new(AtomicU32::new(hdr.exp_cmd_sn.get())),
                    itt_gen: Arc::new(AtomicU32::new(
                        hdr.initiator_task_tag.get().wrapping_add(1),
                    )),
                })
            })
            .clone();

        let inserted = sess.conns.insert(
            cid,
            Arc::new(Connection {
                cid,
                conn: conn.clone(),
                exp_stat_sn: Arc::new(AtomicU32::new(hdr.stat_sn.get().wrapping_add(1))),
            }),
        );
        ensure!(
            inserted.is_none(),
            "CID={cid} already exists in TSIH={tsih}"
        );

        if let Some(w) = self.self_weak.get().cloned() {
            conn.bind_pool_session(w, tsih, cid);
        } else {
            warn!(
                "Pool::attach_self() was not called; unsolicited NOP auto-reply will be \
                 disabled"
            );
        }

        Ok(tsih)
    }

    /// Logout a single TCP connection (CID). Removes the entry on success.
    async fn logout_connection(
        &self,
        tsih: u16,
        cid: u16,
        reason: LogoutReason,
    ) -> Result<()> {
        let sess = self
            .sessions
            .get(&tsih)
            .with_context(|| format!("unknown TSIH={tsih}"))?
            .clone();
        let conn = sess
            .conns
            .get(&cid)
            .with_context(|| format!("CID={cid} not found in TSIH={tsih}"))?
            .clone();

        let mut lo = LogoutCtx::new(
            conn.conn.clone(),
            sess.itt_gen.clone(),
            sess.cmd_sn.clone(),
            conn.exp_stat_sn.clone(),
            cid,
            reason.clone(),
        );
        lo.execute(&conn.conn.stop_writes)
            .await
            .context("logout (CloseConnection) failed")?;

        // Local cleanup
        if reason != LogoutReason::RemoveConnectionForRecovery {
            sess.conns.remove(&cid);
            if sess.conns.is_empty() {
                self.sessions.remove(&tsih);
            }
        }
        Ok(())
    }

    /// Logout the entire session by TSIH and purge local state.
    pub async fn logout_session(&self, tsih: u16) -> Result<()> {
        let sess = self
            .sessions
            .get(&tsih)
            .with_context(|| format!("unknown TSIH={tsih}"))?
            .clone();

        if let Some(cid0) = sess.conns.iter().map(|e| *e.key()).min() {
            let conn = sess
                .conns
                .get(&cid0)
                .expect("CID just collected must exist")
                .clone();

            let mut lo = LogoutCtx::new(
                conn.conn.clone(),
                sess.itt_gen.clone(),
                sess.cmd_sn.clone(),
                conn.exp_stat_sn.clone(),
                cid0,
                LogoutReason::CloseSession,
            );
            lo.execute(&conn.conn.stop_writes)
                .await
                .context("logout (CloseSession) failed")?;
        }

        if let Some((_, s)) = self.sessions.remove(&tsih) {
            // Drain connections to drop their Arcs eagerly (optional)
            for cid in s.conns.iter().map(|kv| *kv.key()).collect::<Vec<_>>() {
                let _ = s.conns.remove(&cid);
            }
        }
        Ok(())
    }

    /// Unified logout handler by reason.
    /// - CloseSession: ignores `cid` (you may pass None), sends Logout on any
    ///   active connection and removes the entire session from the pool
    ///   locally.
    /// - CloseConnection: requires `cid`, removes only that connection; if no
    ///   connections are left, removes the session as well.
    /// - RemoveConnectionForRecovery: requires `cid`, removes only that
    ///   connection; keeps the session even if it temporarily has 0 connections
    ///   (used for recovery).
    pub async fn logout(
        &self,
        tsih: u16,
        reason: LogoutReason,
        cid: Option<u16>,
    ) -> Result<()> {
        match reason {
            LogoutReason::CloseSession => self.logout_session(tsih).await,
            LogoutReason::CloseConnection | LogoutReason::RemoveConnectionForRecovery => {
                self.logout_connection(tsih, cid.context("failed to get cid")?, reason)
                    .await
            },
        }
    }

    /// Gracefully shut down the entire pool:
    /// 1) Quiesce writes on all connections (no new PDUs).
    /// 2) Wait for in-flight requests to drain (bounded by
    ///    `max_wait_per_conn`).
    /// 3) Send exactly one Logout(CloseSession) per session.
    /// 4) Half-close the write side (TCP FIN) on all connections.
    /// 5) Cancel the root token to stop remaining I/O.
    pub async fn shutdown_gracefully(&self, max_wait_per_conn: Duration) -> Result<()> {
        let all_connections: Vec<Arc<Connection>> = self
            .sessions
            .iter()
            .flat_map(|s| {
                s.conns
                    .iter()
                    .map(|c| c.value().clone())
                    .collect::<Vec<_>>()
            })
            .collect();

        debug!("notify state machines to stop writing ti socket");
        for c in &all_connections {
            if let Err(e) = c.conn.graceful_quiesce(max_wait_per_conn).await {
                warn!("drain failed on TSIH={}?, CID={}: {}", c.cid, c.cid, e);
            }
        }

        debug!("call logout session for 1 connectionf of all sessions");
        let tsihs = self.sessions.iter().map(|e| *e.key()).collect::<Vec<_>>();
        for tsih in tsihs {
            if let Err(e) = self.logout_session(tsih).await {
                warn!(
                    "logout_session(TSIH={}) failed during shutdown: {}",
                    tsih, e
                );
            }
        }

        debug!("close socket to target on connection");
        for c in &all_connections {
            if let Err(e) = c.conn.half_close_writes().await {
                warn!("half_close_writes failed on CID={}: {}", c.cid, e);
            }
        }

        debug!("Set cancel enable");
        self.cancel.cancel();
        info!("Pool graceful shutdown completed.");
        Ok(())
    }

    /// Build a state-machine context for (TSIH, CID), inject counters and run
    /// it.
    ///
    /// Usage:
    /// pool.execute_with(tsih, cid, |conn, itt, cmd_sn, exp_stat_sn| {
    ///     NopCtx::new(conn, lun, itt, cmd_sn, exp_stat_sn, ttt)
    /// }).await?;
    pub async fn execute_with<Ctx, Res, Build>(
        &self,
        tsih: u16,
        cid: u16,
        build: Build,
    ) -> Result<Res>
    where
        Build: for<'a> FnOnce(
            Arc<ClientConnection>,
            Arc<AtomicU32>, // ITT
            Arc<AtomicU32>, // CmdSN
            Arc<AtomicU32>, // ExpStatSN
        ) -> Ctx,
        Ctx: StateMachineCtx<Ctx, Res>,
    {
        let sess = self
            .sessions
            .get(&tsih)
            .with_context(|| format!("unknown TSIH={tsih}"))?
            .clone();
        let conn = sess
            .conns
            .get(&cid)
            .with_context(|| format!("CID={cid} not found in TSIH={tsih}"))?
            .clone();

        let mut ctx = build(
            conn.conn.clone(),
            sess.itt_gen.clone(),
            sess.cmd_sn.clone(),
            conn.exp_stat_sn.clone(),
        );
        ctx.execute(&conn.conn.stop_writes).await
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        // Keep Drop short and non-blocking. We don't spawn long tasks here:
        // the runtime may already be shutting down and spawned tasks might never run.
        for sess in self.sessions.iter() {
            for c in sess.conns.iter() {
                c.value().conn.stop_writes.cancel();
            }
        }
        // Abort remaining I/O at the nearest await.
        self.cancel.cancel();
    }
}
