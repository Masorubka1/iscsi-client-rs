// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Result, anyhow};
use dashmap::DashMap;
use tokio::sync::mpsc;

use crate::{client::common::RawPdu, models::identifiers::Itt};

#[derive(Debug)]
pub(super) struct PendingRequests {
    senders: DashMap<Itt, mpsc::Sender<RawPdu>>,
    receivers: DashMap<Itt, mpsc::Receiver<RawPdu>>,
    response_queue_capacity: usize,
}

impl PendingRequests {
    pub(super) fn new(response_queue_capacity: usize) -> Self {
        debug_assert!(response_queue_capacity > 0);
        Self {
            senders: DashMap::new(),
            receivers: DashMap::new(),
            response_queue_capacity,
        }
    }

    pub(super) fn register(&self, itt: Itt) {
        if self.senders.contains_key(&itt) {
            return;
        }

        let (tx, rx) = mpsc::channel(self.response_queue_capacity);
        self.senders.insert(itt, tx);
        self.receivers.insert(itt, rx);
    }

    pub(super) fn remove(&self, itt: Itt) {
        self.senders.remove(&itt);
        self.receivers.remove(&itt);
    }

    pub(super) fn take_receiver(&self, itt: Itt) -> Result<mpsc::Receiver<RawPdu>> {
        self.receivers
            .remove(&itt)
            .map(|(_, receiver)| receiver)
            .ok_or_else(|| anyhow!("no pending request with itt={itt}"))
    }

    pub(super) fn restore_receiver(&self, itt: Itt, receiver: mpsc::Receiver<RawPdu>) {
        self.receivers.insert(itt, receiver);
    }

    pub(super) async fn deliver(
        &self,
        itt: Itt,
        pdu: RawPdu,
        is_final: bool,
    ) -> Result<()> {
        let sender = self
            .senders
            .get(&itt)
            .map(|entry| entry.clone())
            .ok_or_else(|| anyhow!("no pending sender channel for itt={itt}"))?;

        sender
            .send(pdu)
            .await
            .map_err(|_| anyhow!("response receiver dropped for itt={itt}"))?;

        if is_final {
            self.senders.remove(&itt);
        }

        Ok(())
    }

    pub(super) fn is_drained(&self) -> bool {
        self.senders.is_empty()
    }

    pub(super) fn inflight_count(&self) -> usize {
        self.senders.len()
    }

    pub(super) fn inflight_tags(&self) -> Vec<Itt> {
        let mut tags = self
            .senders
            .iter()
            .map(|entry| *entry.key())
            .collect::<Vec<_>>();
        tags.sort_unstable();
        tags
    }

    pub(super) fn abort_all(&self) {
        self.senders.clear();
        self.receivers.clear();
    }
}
