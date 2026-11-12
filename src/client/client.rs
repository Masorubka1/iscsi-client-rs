// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

mod read;
mod write;

use std::{
    sync::{Arc, Weak},
    time::Duration,
};

use anyhow::{Result, anyhow, bail};
use once_cell::sync::OnceCell;
use tokio::{
    select,
    time::{Instant, sleep},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    cfg::config::Config,
    client::{
        common::is_timeout_error, connection_state::ConnectionState,
        pending_requests::PendingRequests, session::Session, transport::Transport,
    },
    models::{
        identifiers::{Cid, Lun},
        nop::request::NopOutRequest,
    },
    state_machine::nop_states::NopCtx,
};

/// Identifies the owning session for keepalives and unsolicited NOP-In
/// auto-replies without keeping the session alive.
#[derive(Debug, Clone)]
struct SessionRef {
    /// Weak reference to the owning session to avoid circular references
    session: Weak<Session>,
    /// Connection ID within the session
    cid: Cid,
}

/// Represents a single iSCSI connection over a TCP stream.
///
/// Routes responses to pending requests and manages connection lifecycle.
/// Socket I/O and PDU framing are delegated to the transport.
#[derive(Debug)]
pub struct ClientConnection {
    /// Socket I/O and complete-PDU framing.
    transport: Transport,
    /// Configuration parameters for this connection
    pub(crate) cfg: Config,
    /// Routes responses from the read loop to the request that owns the ITT.
    pending: PendingRequests,

    /// Reference to the session this connection belongs to
    session_ref: OnceCell<SessionRef>,

    /// Global "kill now" token: if cancelled, both read and write paths abort
    /// immediately.
    cancel: CancellationToken,
    /// "Soft stop" gate for writes: when cancelled, new writes are rejected,
    /// but the read loop keeps draining in-flight responses.
    pub(crate) stop_writes: CancellationToken,
    state: ConnectionState,
}

impl ClientConnection {
    /// Establishes a new TCP connection to the given address.
    pub async fn connect(cfg: Config, cancel: CancellationToken) -> Result<Arc<Self>> {
        #[cfg(feature = "profiling-puffin")]
        profiling::function_scope!();
        let transport = Transport::connect(&cfg, cancel.clone()).await?;
        let pending = PendingRequests::new(cfg.runtime.response_queue_capacity);
        let conn = Arc::new(Self {
            transport,
            cfg,
            pending,
            session_ref: OnceCell::new(),
            cancel,
            stop_writes: CancellationToken::new(),
            state: ConnectionState::default(),
        });

        let reader = Arc::clone(&conn);
        tokio::spawn(async move {
            #[cfg(feature = "profiling-puffin")]
            profiling::register_thread!("iscsi-client-rs::read-loop");
            if let Err(e) = Arc::clone(&reader).read_loop().await {
                if is_timeout_error(&e) {
                    reader.poison(format!("read loop timeout: {e}"));
                } else {
                    reader.poison(format!("read loop exited: {e}"));
                }
                warn!("read loop exited: {e}");
            }
        });

        Ok(conn)
    }

    pub(crate) fn bind_session(&self, session: Weak<Session>, cid: Cid) {
        let _ = self.session_ref.set(SessionRef { session, cid });
    }

    #[inline]
    pub(super) fn ensure_active(&self) -> Result<()> {
        if self.is_poisoned() {
            bail!("connection poisoned");
        }
        if self.cancel.is_cancelled() {
            bail!("cancelled");
        }
        Ok(())
    }

    #[inline]
    pub(super) fn ensure_writable(&self) -> Result<()> {
        self.ensure_active()?;
        if self.stop_writes.is_cancelled() {
            bail!("writes are quiesced");
        }
        Ok(())
    }

    /// Forbid new writes (no FIN). The reader continues to receive and deliver
    /// all in-flight responses into per-ITT channels.
    fn quiesce_writes(&self) {
        self.stop_writes.cancel();
    }

    /// Wait until all in-flight requests have received their FINAL PDUs
    /// and have been delivered to per-ITT channels. Does not tear down TCP.
    /// Can be interrupted by the global `cancel` token.
    async fn wait_inflight_drained(&self, max_wait: Duration) -> Result<()> {
        let deadline = Instant::now() + max_wait;

        debug!("in-flight ITTs: {:?}", self.pending.inflight_tags());
        loop {
            if self.pending.is_drained() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!(
                    "drain timeout: still {} in-flight",
                    self.pending.inflight_count()
                );
            }
            select! {
                _ = self.cancel.cancelled() => return Err(anyhow!("cancelled")),
                _ = sleep(Duration::from_millis(100)) => {},
            }
        }
    }

    /// Convenience: forbid new writes and wait for the input side to drain.
    /// No FIN is sent; use `half_close_writes()` if you also want a write-side
    /// FIN.
    pub async fn graceful_quiesce(&self, max_wait: Duration) -> Result<()> {
        self.quiesce_writes();
        self.wait_inflight_drained(max_wait).await
    }

    /// Hard stop: cancel both read and write paths immediately.
    /// Prefer `graceful_quiesce()` + `half_close_writes()` for graceful
    /// shutdowns.
    pub fn kill_now(&self) {
        self.cancel.cancel();
    }

    pub fn is_poisoned(&self) -> bool {
        self.state.is_poisoned()
    }

    pub(crate) fn poison(&self, reason: impl Into<String>) {
        let reason = reason.into();
        let first_poison = self.state.mark_poisoned();
        self.stop_writes.cancel();
        self.cancel.cancel();
        self.pending.abort_all();

        if first_poison {
            warn!("connection poisoned: {reason}");
        }
    }

    /// Sends a keepalive through the owning session, including its recovery
    /// policy.
    pub async fn send_keepalive(self: &Arc<Self>, lun: Lun) -> Result<()> {
        let sr = self
            .session_ref
            .get()
            .ok_or_else(|| anyhow!("connection is not bound to a pool/session"))?;
        let session = sr
            .session
            .upgrade()
            .ok_or_else(|| anyhow!("session has been dropped"))?;
        let ttt = NopOutRequest::DEFAULT_TAG;

        session
            .execute_with_ctx(sr.cid, move |env| NopCtx::from_execute_env(env, lun, ttt))
            .await?;
        Ok(())
    }

    /// Compatibility entry point for callers using the original pool-based
    /// name.
    pub async fn send_keepalive_via_pool_lun(self: &Arc<Self>, lun: Lun) -> Result<()> {
        self.send_keepalive(lun).await
    }
}
