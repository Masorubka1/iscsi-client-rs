//! This module defines common traits and enums for the state machine.
//! It provides the core building blocks for defining and executing state
//! machines.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::future::Future;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

/// Represents the outcome of a state transition.
pub enum Transition<S, R> {
    /// Move to the next state.
    Next(S, R),
    /// Remain in the current state.
    Stay(R),
    /// The state machine has completed.
    Done(R),
}

/// A trait for defining a state machine.
pub trait StateMachine<Ctx, Resp>: Sized {
    /// The future returned by the `step` method.
    type StepResult<'a>: Future<Output = Resp> + Send + 'a
    where
        Self: 'a,
        Resp: 'a,
        Ctx: 'a;

    /// Executes a single step of the state machine.
    fn step<'a>(&'a self, ctx: &'a mut Ctx) -> Self::StepResult<'a>;
}

/// A trait for executing a state machine.
pub trait StateMachineCtx<Ctx, Out = ()>: Sized {
    /// Executes the state machine to completion.
    fn execute(
        &mut self,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<Out>>;
}
