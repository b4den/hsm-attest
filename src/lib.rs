#[macro_use]
pub mod macros;
pub mod error;
pub mod function;

use function::{build_unboxed_handlers, Callable, Func, FuncMap};
use num_enum::FromPrimitive;

pub type FuncResult = Vec<Vec<Func<fn(&mut Machine) -> Option<State>>>>;

#[derive(Debug)]
pub struct Machine {
    state: State,
    prev: State,
    byte: u8,
    stack: Vec<u8>,
    state_machine: Vec<u8>,
    func_table: FuncResult,
    counter: u32,
    pub be_int: u32,
}

impl Machine {
    pub fn new() -> Self {
        Self {
            state: State::from_primitive(1),
            prev: State::Initial,
            stack: Vec::new(),
            state_machine: make_state(),
            func_table: build_unboxed_handlers(),
            counter: 0,
            byte: 0,
            be_int: 0,
        }
    }

    pub fn run_buf(&mut self, buff: &[u8]) {
        for c in buff {
            self.parse(*c);
        }
    }
    pub fn parse(&mut self, c: u8) {
        let current_state = self.state;
        self.byte = c;
        //println!("current state is {:?}", self.state);
        let proposed_state = self.state_machine[current_state as usize * 256 + c as usize];
        let new_state = self
            .run_funcs(current_state, proposed_state.into())
            .unwrap_or_else(|| {
                println!("run funcs false for {:?} to {:?}", current_state, State::from_primitive(proposed_state));
                current_state
            });
        //println!("newstate is {new_state:?}");
        self.state = new_state.into();
        self.prev = current_state;
    }

    pub fn run_funcs(&mut self, current: State, new: State) -> Option<State> {
        let res = self.func_table[current as usize].clone();
        let func = res[new as usize].clone();
        let res = func.apply(self);
        res
    }

}

impl Machine {
    pub fn map_func(&mut self, mapper: FuncMap, func: Func<fn(&mut Machine) -> Option<State>>) {
        let FuncMap(from_iter, to) = mapper;
        for from in from_iter {
            self.func_table[from as usize][to as usize] = func.clone();
        }
    }

    pub fn current_byte(&self) -> u8 {
        self.byte
    }

    pub fn stack_mut(&mut self) -> &mut Vec<u8> {
        &mut self.stack
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn next_state(&self) -> State {
        State::from_primitive(self.state as u8 + 1)
    }

    pub fn previous(&self) -> State {
        self.prev
    }

    // only come through set state to ensure we've got an accurate representation of previous
    pub fn set_state(&mut self, new_state: State) {
        self.prev = self.state.clone();
        self.state = new_state;
    }

    pub fn reset_count(&mut self) {
        self.counter = 0;
        self.be_int = 0;
    }

    pub fn current_count(&self) -> u32 {
        self.counter
    }

    pub fn inc_count(&mut self) -> u32 {
        self.counter += 1;
        self.counter
    }
}

enum_builder! (
    pub enum State {
        Initial = 0,
        SKIP8,
        TOTALSIZE4,
        BUFSIZE4,
    }
);
const STATE_VARIANTS: usize = State::attr_count();

// potentially we could have another machine that tracks the count for each state and increments
// where appropriate.
fn make_state() -> Vec<u8> {
    let mut sm = vec![0u8; 256 * STATE_VARIANTS];
    for enum_state in 0..State::attr_count() {
        let state = State::from_primitive(enum_state as _);
        for c in 0usize..=255 {
            sm[state as usize * 256 + c] = enum_state as _;
        }
    }
    sm
}
