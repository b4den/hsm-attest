use hsmattest::error::{self, ParseError};
use hsmattest::state_transitions::register_functions;
use hsmattest::Machine;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

const BUF_SIZE: u32 = 1 << 16;
fn main() {
    match run_parse() {
        Ok(_) => println!("Done"),
        Err(e) => println!("Error while parsing = '{}'", e),
    };
}

fn run_parse() -> Result<(), error::ParseError> {
    let mut machine = Machine::new().with_writer();
    register_functions(&mut machine);

    let fname = std::env::args().skip(1).next().ok_or(ParseError::InvalidArg(0))?;
    println!("Reading file = {}", fname);
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
    //if let Some(writer) = machine.to_json_bytes() {
    //    println!("{}", String::from_utf8(writer).unwrap());
    //}

    Ok(())
}
