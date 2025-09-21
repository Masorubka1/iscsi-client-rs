// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::Result;
use tokio_util::sync::CancellationToken;

pub enum Transition<S, R> {
    Next(S, R),
    Stay(R),
    Done(R),
}

pub trait StateMachine<Ctx, Resp>: Sized {
    type StepResult<'a>: Future<Output = Resp> + Send + 'a
    where
        Self: 'a,
        Resp: 'a,
        Ctx: 'a;

    fn step<'a>(&'a self, ctx: &'a mut Ctx) -> Self::StepResult<'a>;
}

pub trait StateMachineCtx<Ctx, Out = ()>: Sized {
    fn execute(
        &mut self,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<Out>>;
}
