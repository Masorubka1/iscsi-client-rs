// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use iscsi_client_rs::models::identifiers::{Itt, IttGen};
use loom::{sync::Arc, thread};

fn check_allocations(start: u32, expected: [u32; 4], next: u32) {
    loom::model(move || {
        let generator = Arc::new(IttGen::new(Itt::new(start).expect("valid start")));
        let workers = (0..2)
            .map(|_| {
                let generator = generator.clone();
                thread::spawn(move || {
                    [generator.fetch_inc().get(), generator.fetch_inc().get()]
                })
            })
            .collect::<Vec<_>>();
        let mut actual = workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("allocation thread panicked"))
            .collect::<Vec<_>>();
        actual.sort_unstable();
        let mut expected = expected;
        expected.sort_unstable();
        assert_eq!(actual, expected, "tags must not be lost or allocated twice");
        assert!(!actual.contains(&Itt::RESERVED));
        assert_eq!(generator.load().get(), next);
    });
}

#[test]
fn concurrent_allocations_are_unique() {
    check_allocations(0, [0, 1, 2, 3], 4);
}

#[test]
fn concurrent_allocations_skip_reserved_tag_at_wraparound() {
    check_allocations(u32::MAX - 2, [u32::MAX - 2, u32::MAX - 1, 0, 1], 2);
}

#[test]
fn concurrent_load_observes_a_valid_generator_state() {
    loom::model(|| {
        let generator =
            Arc::new(IttGen::new(Itt::new(u32::MAX - 1).expect("valid start")));
        let writer = generator.clone();
        let worker = thread::spawn(move || writer.fetch_inc());
        let observed = generator.load().get();
        assert!(observed == u32::MAX - 1 || observed == 0);
        assert_eq!(
            worker.join().expect("allocation thread panicked").get(),
            u32::MAX - 1
        );
        assert_eq!(generator.load().get(), 0);
    });
}
