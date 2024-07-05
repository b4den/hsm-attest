use std::rc::Rc;

use crate::{Machine, State, STATE_VARIANTS};
use num_enum::FromPrimitive;

pub fn build_unboxed_handlers() -> Vec<Vec<Func<fn(&mut Machine) -> Option<State>>>> {
    const table_size: usize = STATE_VARIANTS;
    let mut fn_table: Vec<Vec<Func<_>>> = Vec::new();
    for _ in 0..table_size {
        let funcs: Vec<_> = (0..table_size)
            .into_iter()
            .map(|_| Func::<fn(&mut Machine) -> Option<State>>::Unit(()))
            .collect();
        fn_table.push(funcs);
    }

    build_mappings(&mut fn_table);
    fn_table
}

fn build_mappings(fn_table: &mut Vec<Vec<Func<fn(&mut Machine) -> Option<State>>>>) {
    fn_table[State::Initial as usize][State::SKIP8 as usize] = Func::FuncBoxed(Rc::new(|m| {
        println!("[initial] -> [skip8]!");
        m.counter+=1;
        if m.counter >= 8 {
            m.counter = 0;
            return Some((m.state as u8 + 2).into());
        }
        println!("counter is {}", m.counter);
        None
    }));
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
            Func::FuncPtr(f) => f.apply(ctx),
            Func::FuncBoxed(bf) => bf.apply(ctx),
        }
    }
}

#[derive(Clone)]
pub enum Func<T: Fn(&mut Machine) -> Option<State>> {
    Unit(()),
    Fun(T),
    FuncPtr(fn(&mut Machine) -> Option<State>),
    FuncBoxed(Rc<dyn Fn(&mut Machine) -> Option<State>>),
}

impl<T> Func<T>
where
    T: Fn(&mut Machine) -> Option<State>,
{
    pub fn boxed(input: impl Fn(&mut Machine) -> Option<State> + 'static) -> Func<T> {
        Func::FuncBoxed(Rc::new(input))
    }
}

impl std::fmt::Debug for Func<fn(&mut Machine) -> Option<State>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Func::*;
        match self {
            Unit(_) => write!(f, "{}", "unit"),
            Fun(_) => write!(f, "{}", "func"),
            FuncPtr(_) => write!(f, "{}", "func_pointer"),
            FuncBoxed(_) => write!(f, "{}", "func_boxed"),
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
