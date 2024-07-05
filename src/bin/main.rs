use hsmattest::error::{self, ParseError};
use hsmattest::function::{FuncState, Func};
use hsmattest::{Machine, State};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

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

fn register_functions(machine: &mut Machine) {
    machine.map_func(State::SKIP8.to(State::SKIP8), Func::Fun(|m| {
        if m.inc_count() & 0x00000008 != 0 {
            m.reset_count();
            return Some(m.next_state());
        }
        None
    }));

    machine.map_func(State::BUFSIZE4.to(State::BUFSIZE4), Func::Fun(|m| {
        if m.inc_count() & 0x00000004 != 0 {
            m.reset_count();
            return Some(m.next_state());
        }
        None
    }));

    machine.map_func(State::TOTALSIZE4.to(State::TOTALSIZE4), Func::Fun(|m| {
        println!("WOW");
        println!("total size! count = {}", m.current_count());
        println!("m anded = {}", m.current_count() ^ 0x00000004);
        println!("current byte in total = {}", m.current_byte());
        m.be_int = m.be_int << 8 | m.current_byte() as u32;
        if m.inc_count() == 4 {
            println!("BE INT {}", m.be_int);
            m.reset_count();
            return Some(m.next_state())
        }
        None
    }));
}
