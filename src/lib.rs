#[macro_use]
pub mod macros;
pub mod error;
pub mod function;
pub mod tlv_mapping;

use function::{build_unboxed_handlers, Callable, Func, FuncMap};
use num_enum::FromPrimitive;

pub type FuncResult = Vec<Vec<Func<fn(&mut Machine) -> Option<State>>>>;
const SIG_SIZE:usize = 256;

#[derive(Debug)]
pub struct Machine {
    stack: Vec<u8>,
    state_stack: Vec<State>,
    state_machine: Vec<u8>,
    func_table: FuncResult,
    state: State,
    prev: State,
    counter: u32,
    pub be_int: u32,
    byte: u8,
    index: usize,
    pub total_size: u32,
    pub buff_size: u32,
    pub attr_offset: u32,
    pub firstkey_offset: u32,
    pub secondkey_offset: u32,
    pub attrs_processed: u32,
    pub attr_count: u32,
    mode: Mode,
    pub tlv_type: u32,
    pub tlv_len: u32,
    pub signature_len: usize,
    pub key_mode: KeyMode,
}

impl Machine {
    pub fn new() -> Self {
        Self {
            state: State::from_primitive(1),
            prev: State::Initial,
            stack: Vec::new(),
            state_stack: Vec::new(),
            state_machine: make_state(),
            func_table: build_unboxed_handlers(),
            counter: 0,
            byte: 0,
            be_int: 0,
            index: 0,
            total_size: 0,
            buff_size: 0,
            attr_offset: 0,
            firstkey_offset: 0,
            secondkey_offset: 0,
            attrs_processed: 0,
            attr_count: 0,
            mode: Mode::default(),
            tlv_type: 0,
            tlv_len: 0,
            signature_len: 256,
            key_mode: KeyMode::default(),
        }
    }

    pub fn new_with_signature_len(len: usize) -> Self {
        let mut machine = Self::new();
        machine.set_signature_len(len);
        machine
    }

    pub fn run_buf(&mut self, buff: &[u8]) {
        for c in buff {
            self.parse(*c);
        }
    }
    pub fn parse(&mut self, c: u8) {
        let current_state = self.state;
        self.byte = c;

        let proposed_state = self.state_machine[current_state as usize * 256 + c as usize];
        let new_state = self
            .run_funcs(current_state, proposed_state.into())
            .unwrap_or_else(|| current_state);

        // if we've manually overidden the state then reset the counters
        if proposed_state != new_state as _ {
            self.reset_count();
        };

        self.state = new_state.into();
        self.prev = current_state;
        self.index += 1;
    }

    pub fn run_funcs(&mut self, current: State, new_state: State) -> Option<State> {
        let func = self.func_table[current as usize][new_state as usize];
        let res = func.apply(self);
        res
    }
}

impl Machine {
    pub fn map_func(&mut self, mapper: FuncMap, func: Func<fn(&mut Machine) -> Option<State>>) {
        let FuncMap(from_iter, to) = mapper;
        for from in from_iter {
            self.func_table[from as usize][to as usize] = func;
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

    pub fn set_total_size(&mut self, size: u32) {
        self.total_size = size;
    }

    pub fn set_buf_size(&mut self, size: u32) {
        self.buff_size = size;
    }

    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    pub fn get_mode(&self) -> Mode {
        self.mode
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

    pub fn get_index(&self) -> usize {
        self.index
    }

    pub fn push_state(&mut self, state: State) {
        self.state_stack.push(state);
    }

    pub fn pop_state(&mut self) -> Option<State> {
        self.state_stack.pop()
    }

    pub fn set_signature_len(&mut self, len: usize) {
        self.signature_len = len;
    }

    pub fn get_keymode(&self) -> KeyMode {
        self.key_mode
    }

    pub fn set_keymode(&mut self, keymode: KeyMode) {
        self.key_mode = keymode;
    }
}

enum_builder! (
    pub enum State {
        Initial = 0,
        SKIP8,
        TOTALSIZE4,
        BUFSIZE4,
        SkipToOffset,
        SkipU16_2,
        OffsetPubkey16,
        OffsetPrivkey16,
        Skip4,
        AttrLen,
        SkipAttr4,
        TLVType,
        TLVLen,
        TLVValue,
        SecondaryKey,
        Signature,
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

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub enum Mode {
    Symmetric,
    #[default]
    Asymetric,
}

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub enum KeyMode {
    #[default]
    Primary,
    Secondary,
}
