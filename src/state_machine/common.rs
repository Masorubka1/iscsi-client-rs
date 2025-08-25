// SPDX-License-Identifier: AGPL-3.0-or-later GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

pub enum Transition<S, R> {
    Next(S, R),
    Stay(R),
    Done(R),
}

pub trait StateMachine<Ctx, RespCtx>: Sized {
    type StepResult<'a>: Future<Output = RespCtx> + Send + 'a
    where
        Self: 'a,
        RespCtx: 'a,
        Ctx: 'a;

    fn step<'a>(&'a mut self, ctx: &'a mut Ctx) -> Self::StepResult<'a>;
}
