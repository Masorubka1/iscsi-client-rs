// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

mod read;
mod write;

use std::{
    sync::{
        Arc, Mutex as StdMutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Result, anyhow, bail};
use once_cell::sync::OnceCell;
use tokio::{
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    select,
    sync::Mutex,
    time::{Instant, sleep},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    cfg::config::Config,
    client::{
        common::{io_with_timeout, is_timeout_error},
        pending_requests::PendingRequests,
        pool_sessions::Pool,
    },
    models::nop::request::NopOutRequest,
    state_machine::nop_states::NopCtx,
};

/// A weak reference to a session in the pool, used for unsolicited NOP-In
/// auto-replies.
///
/// Contains a weak reference to the session pool and identifies a specific
/// session and connection within that pool.
#[derive(Debug, Clone)]
struct SessionRef {
    /// Weak reference to the session pool to avoid circular references
    pool: Weak<Pool>,
    /// Target Session Identifying Handle
    tsih: u16,
    /// Connection ID within the session
    cid: u16,
}

/// Represents a single iSCSI connection over a TCP stream.
///
/// This struct manages sending requests (PDUs) and receiving responses, and is
/// responsible for framing PDUs based on the information in their headers. It
/// handles the low-level TCP communication with proper framing according to the
/// iSCSI protocol.
#[derive(Debug)]
pub struct ClientConnection {
    /// TCP read half protected by mutex for concurrent access
    pub reader: Mutex<OwnedReadHalf>,
    /// TCP write half protected by mutex for concurrent access
    pub writer: Mutex<OwnedWriteHalf>,
    /// Configuration parameters for this connection
    pub cfg: Config,
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
    poisoned: AtomicBool,
    poison_reason: StdMutex<Option<String>>,
}

impl ClientConnection {
    /// Establishes a new TCP connection to the given address.
    pub async fn connect(cfg: Config, cancel: CancellationToken) -> Result<Arc<Self>> {
        let stream = io_with_timeout(
            "connect",
            TcpStream::connect(&cfg.login.transport.target_address),
            cfg.runtime.timeout_connection,
            &cancel,
        )
        .await?;
        stream.set_nodelay(true)?;

        let (r, w) = stream.into_split();

        let conn = Self::from_split_no_reader(r, w, cfg, cancel);

        let reader = Arc::clone(&conn);
        tokio::spawn(async move {
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

    pub fn bind_pool_session(&self, pool: Weak<Pool>, tsih: u16, cid: u16) {
        let _ = self.session_ref.set(SessionRef { pool, tsih, cid });
    }

    #[inline]
    pub fn cancel_now(&self) {
        self.cancel.cancel();
    }

    pub fn from_split_no_reader(
        r: OwnedReadHalf,
        w: OwnedWriteHalf,
        cfg: Config,
        cancel: CancellationToken,
    ) -> Arc<Self> {
        Arc::new(Self {
            reader: Mutex::new(r),
            writer: Mutex::new(w),
            cfg,
            pending: PendingRequests::default(),
            session_ref: OnceCell::new(),
            cancel,
            stop_writes: CancellationToken::new(),
            poisoned: AtomicBool::new(false),
            poison_reason: StdMutex::new(None),
        })
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
        self.cancel_now();
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::SeqCst)
    }

    pub fn poison_reason(&self) -> Option<String> {
        self.poison_reason
            .lock()
            .ok()
            .and_then(|reason| reason.clone())
    }

    pub fn poison(&self, reason: impl Into<String>) {
        let reason = reason.into();
        let first_poison = !self.poisoned.swap(true, Ordering::SeqCst);
        if let Ok(mut slot) = self.poison_reason.lock()
            && slot.is_none()
        {
            *slot = Some(reason.clone());
        }
        self.stop_writes.cancel();
        self.cancel.cancel();
        self.pending.abort_all();

        if first_poison {
            warn!("connection poisoned: {reason}");
        }
    }

    pub fn ensure_healthy(&self) -> Result<()> {
        if self.is_poisoned() {
            bail!(
                "connection poisoned{}",
                self.poison_reason()
                    .map(|reason| format!(": {reason}"))
                    .unwrap_or_default()
            );
        }
        Ok(())
    }

    pub async fn send_keepalive_via_pool_lun(self: &Arc<Self>, lun: u64) -> Result<()> {
        let sr = self
            .session_ref
            .get()
            .ok_or_else(|| anyhow!("connection is not bound to a pool/session"))?;
        let pool = sr
            .pool
            .upgrade()
            .ok_or_else(|| anyhow!("pool has been dropped"))?;

        pool.execute_with(sr.tsih, sr.cid, move |conn, itt, cmd_sn, exp_stat_sn| {
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
        Ok(())
    }

    pub async fn send_keepalive_via_pool(self: &Arc<Self>) -> Result<()> {
        self.send_keepalive_via_pool_lun(1u64 << 48).await
    }
}
