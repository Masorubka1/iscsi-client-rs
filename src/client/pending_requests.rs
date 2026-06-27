// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Result, anyhow};
use dashmap::DashMap;
use tokio::sync::mpsc;

use crate::{client::common::RawPdu, models::common::InitiatorTaskTag};

const RESPONSE_QUEUE_CAPACITY: usize = 32;

#[derive(Debug, Default)]
pub(super) struct PendingRequests {
    senders: DashMap<InitiatorTaskTag, mpsc::Sender<RawPdu>>,
    receivers: DashMap<InitiatorTaskTag, mpsc::Receiver<RawPdu>>,
}

impl PendingRequests {
    pub(super) fn register(&self, itt: InitiatorTaskTag) {
        if self.senders.contains_key(&itt) {
            return;
        }

        let (tx, rx) = mpsc::channel(RESPONSE_QUEUE_CAPACITY);
        self.senders.insert(itt, tx);
        self.receivers.insert(itt, rx);
    }

    pub(super) fn remove(&self, itt: InitiatorTaskTag) {
        self.senders.remove(&itt);
        self.receivers.remove(&itt);
    }

    pub(super) fn take_receiver(
        &self,
        itt: InitiatorTaskTag,
    ) -> Result<mpsc::Receiver<RawPdu>> {
        self.receivers
            .remove(&itt)
            .map(|(_, receiver)| receiver)
            .ok_or_else(|| anyhow!("no pending request with itt={itt}"))
    }

    pub(super) fn restore_receiver(
        &self,
        itt: InitiatorTaskTag,
        receiver: mpsc::Receiver<RawPdu>,
    ) {
        self.receivers.insert(itt, receiver);
    }

    pub(super) async fn deliver(
        &self,
        itt: InitiatorTaskTag,
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

    pub(super) fn inflight_tags(&self) -> Vec<InitiatorTaskTag> {
        let mut tags = self
            .senders
            .iter()
            .map(|entry| *entry.key())
            .collect::<Vec<_>>();
        tags.sort_unstable_by_key(|tag| tag.get());
        tags
    }
}
