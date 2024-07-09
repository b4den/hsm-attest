use crate::{Machine, State, STATE_VARIANTS};
use num_enum::FromPrimitive;

pub fn build_unboxed_handlers() -> Vec<Vec<Func<fn(&mut Machine) -> Option<State>>>> {
    #[allow(non_upper_case_globals)]
    const table_size: usize = STATE_VARIANTS;
    let mut fn_table: Vec<Vec<Func<_>>> = Vec::new();
    for _ in 0..table_size {
        let funcs: Vec<_> = (0..table_size)
            .into_iter()
            .map(|_| Func::<fn(&mut Machine) -> Option<State>>::Unit(()))
            .collect();
        fn_table.push(funcs);
    }

    fn_table
}


pub trait Callable {
    fn apply(&self, ctx: &mut Machine) -> Option<State>;
}

impl<F> Callable for F
where
    F: Fn(&mut Machine) -> Option<State> + ?Sized,
{
    fn apply(&self, ctx: &mut Machine) -> Option<State> {
        (self)(ctx)
    }
}

impl Callable for () {
    fn apply(&self, _ctx: &mut Machine) -> Option<State> {
        None
    }
}

impl<T> Callable for Func<T>
where
    T: Fn(&mut Machine) -> Option<State>,
{
    fn apply(&self, ctx: &mut Machine) -> Option<State> {
        match self {
            Func::Unit(u) => u.apply(ctx),
            Func::Fun(f) => f.apply(ctx),
        }
    }
}

#[derive(Copy, Clone)]
pub enum Func<T: Fn(&mut Machine) -> Option<State>> {
    Unit(()),
    Fun(T),
}

impl std::fmt::Debug for Func<fn(&mut Machine) -> Option<State>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Func::*;
        match self {
            Unit(_) => write!(f, "{}", "unit"),
            Fun(_) => write!(f, "{}", "func"),
        }
    }
}

pub trait FuncState {
    fn to(&self, s: State) -> FuncMap;
}

pub struct FuncMap(pub Vec<State>, pub State);

impl State {
    pub fn any() -> Vec<State> {
        (0..STATE_VARIANTS)
            .map(|s| State::from_primitive(s as _))
            .collect()
    }
}

impl FuncState for State {
    fn to(&self, s: State) -> FuncMap {
        FuncMap(vec![*self], s)
    }
}

impl<T> FuncState for T
where T: IntoIterator<Item = State> + Clone + ?Sized,
{
    fn to(&self, s: State) -> FuncMap {
        FuncMap(self.clone().into_iter().collect(), s)
    }
}
