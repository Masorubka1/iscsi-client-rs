// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use loom::{sync::Arc, thread};

use crate::connection_state::ConnectionState;

#[test]
fn concurrent_poison_has_exactly_one_first_caller() {
    loom::model(|| {
        let state = Arc::new(ConnectionState::default());
        assert!(!state.is_poisoned());
        let workers = (0..3)
            .map(|_| {
                let state = state.clone();
                thread::spawn(move || {
                    let first = state.mark_poisoned();
                    assert!(state.is_poisoned());
                    first
                })
            })
            .collect::<Vec<_>>();
        let first_callers = workers
            .into_iter()
            .map(|worker| worker.join().expect("poison thread panicked"))
            .filter(|first| *first)
            .count();
        assert_eq!(first_callers, 1);
        assert!(state.is_poisoned());
        assert!(!state.mark_poisoned());
    });
}

#[test]
fn observed_poison_never_reverts_to_active() {
    loom::model(|| {
        let state = Arc::new(ConnectionState::default());
        let writer = state.clone();
        let worker = thread::spawn(move || writer.mark_poisoned());
        let before = state.is_poisoned();
        thread::yield_now();
        let after = state.is_poisoned();
        assert!(!before || after);
        assert!(worker.join().expect("poison thread panicked"));
        assert!(state.is_poisoned());
    });
}
