// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::{Arc, Weak, atomic::AtomicU32};

use anyhow::{Context, Result, ensure};
use dashmap::DashMap;
use once_cell::sync::OnceCell;

use crate::{
    cfg::config::{AuthConfig, Config},
    client::client::ClientConnection,
    models::logout::common::LogoutReason,
    state_machine::{
        common::StateMachineCtx, login::common::LoginCtx, logout_states::LogoutCtx,
    },
    utils::generate_isid,
};

/// Per-connection state
#[derive(Debug)]
pub struct Connection {
    pub cid: u16,
    pub conn: Arc<ClientConnection>,
    /// Next Expected StatSN (ACK). Bumped when we accept a reply from target.
    pub exp_stat_sn: Arc<AtomicU32>,
}

/// Per-session state (ISID+TSIH). A session may have multiple TCP connections
/// (MC/S).
#[derive(Debug)]
pub struct Session {
    pub tsih: u16,
    pub isid: [u8; 6],
    pub target_name: Arc<str>,
    pub conns: DashMap<u16, Arc<Connection>>,

    /// CmdSN generator for numbered commands (incremented on every
    /// non-immediate command).
    cmd_sn: Arc<AtomicU32>,
    /// ITT generator (unique within a session).
    itt_gen: Arc<AtomicU32>,
}

pub struct Pool {
    pub sessions: DashMap<u16, Arc<Session>>,
    max_sessions: u32,
    self_weak: OnceCell<Weak<Pool>>,
}

impl Pool {
    pub fn new(cfg: &Config) -> Self {
        Self {
            sessions: DashMap::with_capacity(
                cfg.extra_data.connections.max_connections as usize,
            ),
            max_sessions: cfg.extra_data.connections.max_sessions,
            self_weak: OnceCell::new(),
        }
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
            let conn = ClientConnection::connect(cfg.clone()).await?;
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

    /// Logout a single TCP connection (CID). Removes the entry on success.
    pub async fn logout_connection(&self, tsih: u16, cid: u16) -> Result<()> {
        // Clone Arc handles for await
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

        // Protocol Logout (CloseConnection)
        let mut lo = LogoutCtx::new(
            conn.conn.clone(),
            sess.itt_gen.clone(),
            sess.cmd_sn.clone(),
            conn.exp_stat_sn.clone(),
            cid,
            LogoutReason::CloseConnection,
        );
        lo.execute()
            .await
            .context("logout (CloseConnection) failed")?;

        // Local cleanup
        sess.conns.remove(&cid);
        if sess.conns.is_empty() {
            self.sessions.remove(&tsih);
        }
        Ok(())
    }

    /// Logout the entire session by TSIH and purge local state.
    pub async fn logout_session(&self, tsih: u16) -> Result<()> {
        let sess = self
            .sessions
            .get(&tsih)
            .context(format!("unknown TSIH={tsih}"))?
            .clone();

        // Use any connection to send CloseSession (if present)
        if let Some(first) = sess.conns.iter().next() {
            let cid = *first.key();
            let conn = first.value().clone();

            let mut lo = LogoutCtx::new(
                conn.conn.clone(),
                sess.itt_gen.clone(),
                sess.cmd_sn.clone(),
                conn.exp_stat_sn.clone(),
                cid,
                LogoutReason::CloseSession,
            );
            lo.execute().await.context("logout (CloseSession) failed")?;
        }

        // Local cleanup (idempotent)
        if let Some((_, s)) = self.sessions.remove(&tsih) {
            for cid in s.conns.iter().map(|kv| *kv.key()).collect::<Vec<_>>() {
                s.conns.remove(&cid);
            }
        }
        Ok(())
    }

    /// Logout all sessions sequentially.
    pub async fn logout_all(&self) -> Result<()> {
        for tsih in self.sessions.iter().map(|e| *e.key()).collect::<Vec<_>>() {
            self.logout_session(tsih).await?;
        }
        Ok(())
    }

    // --- internals ---

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

        let login_pdu = l.execute().await.context("login failed")?;
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
                    conns: DashMap::new(),
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
            tracing::warn!(
                "Pool::attach_self() was not called; unsolicited NOP auto-reply will be \
                 disabled"
            );
        }

        Ok(tsih)
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
        ctx.execute().await
    }
}
