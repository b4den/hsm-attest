use hsmattest::error::{self, ParseError};
use hsmattest::function::{FuncState, Func};
use hsmattest::{Machine, State};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use num_enum::FromPrimitive;

const BUF_SIZE: u16 = u16::MAX;
fn main() {
    match run_parse() {
        Ok(_) => println!("Done"),
        Err(e) => println!("Error while parsing = '{}'", e),
    };
}

fn run_parse() -> Result<(), error::ParseError> {
    let mut machine = Machine::new();
    register_functions(&mut machine);

    let fname = std::env::args().skip(1).next().ok_or(ParseError::InvalidArg(0))?;
    println!("File to read = {}", fname);
    let file = File::open(Path::new(&fname))?;

    let mut reader = BufReader::with_capacity(BUF_SIZE as _, file);
    loop {
        let length = {
            let buffer = reader.fill_buf()?;
            machine.run_buf(buffer);
            buffer.len()
        };

        if length == 0 {
            break;
        }
        reader.consume(length);
    };

    Ok(())
}

/* Here is where the state machine logic is defined.
 * Notes
 * 1. Shifting between states via map_func returns will reset the counters.
 * 2. All integer values in the TLV are in big-endian, therefore we must bit-shift these as they
 *    appear in network byte order.
 * 3. In the case where we don't have a full byte buffer payload, we attempt to store each byte on
 *    the stack and dispatch on the next state transition. This allows for a full asynchronous
 *    state machine model, even in the case where reads are returning 1 byte at a time.
 * */
fn register_functions(machine: &mut Machine) {
    machine.map_func(State::SKIP8.to(State::SKIP8), Func::Fun(|m| {
        if m.inc_count() == 1 << 3 {
            m.reset_count();
            return Some(m.next_state());
        }
        None
    }));

    machine.map_func(State::BUFSIZE4.to(State::BUFSIZE4), Func::Fun(|m| {
        m.be_int = m.be_int << 8 | m.current_byte() as u32;

        if m.inc_count() == 1 << 2 {
            println!("buf size {}", m.be_int);
            m.set_buf_size(m.be_int);
            return Some(m.next_state());
        }
        None
    }));

    machine.map_func(State::TOTALSIZE4.to(State::TOTALSIZE4), Func::Fun(|m| {
        m.be_int = m.be_int << 8 | m.current_byte() as u32;

        if m.inc_count() == 1 << 2 {
            println!("BE INT {}", m.be_int);
            m.set_total_size(m.be_int);
            return Some(m.next_state())
        }
        None
    }));

    machine.map_func(State::SkipToOffset.to(State::SkipToOffset), Func::Fun(|m| {
        // set the attribute offset if it isn't already
        let mask = (!((m.attr_offset == 0) as i32) + 1) as u32;
        m.attr_offset = (mask & (m.total_size - (m.buff_size + 256))) | (!mask & m.attr_offset);

        // now check if the current index is at our offset
        if m.attr_offset as usize == m.get_index() {
            println!("got index at {}. current byte {}", m.get_index(), m.current_byte());
            // move to the next state, skipping an additional three bytes
            return Some(m.next_state());
        }
        None
    }));

    machine.map_func(State::SkipU16_2.to(State::SkipU16_2), Func::Fun(|m| {
        println!("Skip 16! current byte = {}", m.current_byte());
        if m.inc_count() == 3 {
            return Some(m.next_state());
        }
        None
    }));

    machine.map_func(State::OffsetPubkey16.to(State::OffsetPubkey16), Func::Fun(|m| {
        m.firstkey_offset = m.firstkey_offset << 8 | m.current_byte() as u32;
        let mask = (!((m.inc_count() == 2) as i32) + 1) as u32;
        let st = (mask & m.next_state() as u32) | (!mask & m.state() as u32);
        Some(State::from_primitive(st as _))
    }));

    machine.map_func(State::OffsetPrivkey16.to(State::OffsetPrivkey16), Func::Fun(|m| {
        m.secondkey_offset = m.secondkey_offset << 8 | m.current_byte() as u32;
        let mask = (!((m.inc_count() == 2) as i32) + 1) as u32;
        let st = (mask & m.next_state() as u32) | (!mask & m.state() as u32);
        Some(State::from_primitive(st as _))
    }));

    machine.map_func(State::Skip4.to(State::Skip4), Func::Fun(|m| {
        println!("skip4");
        let mask = (!((m.inc_count() == 1 << 2) as i32) + 1) as u32;
        Some(State::from_primitive(
                ( (mask & m.next_state() as u32) | (!mask & m.state() as u32) ) as u8
        ))

    }));
    machine.map_func(State::FirstAttrs.to(State::FirstAttrs), Func::Fun(|m| {
        println!("firstattrs! {}", m.current_byte());
        println!("firstattrs! privkey offset {}", m.secondkey_offset);
        None
    }));

}
