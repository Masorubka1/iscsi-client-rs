
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
