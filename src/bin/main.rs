use hsmattest::error::{self, ParseError};
use hsmattest::function::{FuncState, Func};
use hsmattest::tlv_mapping::TLVMapping;
use hsmattest::{Machine, Mode, State};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use num_enum::FromPrimitive;

const BUF_SIZE: u32 = 1 << 16;
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
            m.set_buf_size(m.be_int);
            return Some(m.next_state());
        }
        None
    }));

    machine.map_func(State::TOTALSIZE4.to(State::TOTALSIZE4), Func::Fun(|m| {
        m.be_int = m.be_int << 8 | m.current_byte() as u32;

        if m.inc_count() == 1 << 2 {
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
        if mask == 0xFFFFFFFF {
            if m.secondkey_offset == 0 {
                m.set_mode(Mode::Symmetric);
                m.push_state(State::Signature);
            } else {
                m.push_state(State::Signature);
                m.push_state(State::SecondaryKey);
            };
        }
        let st = (mask & m.next_state() as u32) | (!mask & m.state() as u32);
        Some(State::from_primitive(st as _))
    }));

    // this operation will also check on the last iteration whether secondkey_offset is greater
    // than 0.
    // If it is, then we have private key attestation to handle for assymetric keys
    // If its not, then we have a symmetric key to parse, moving directly to signature at the end.
    machine.map_func(State::Skip4.to(State::Skip4), Func::Fun(|m| {
        println!("skip4");
        let mask = (!((m.inc_count() == 1 << 2) as i32) + 1) as u32;

        Some(State::from_primitive(
                ( (mask & m.next_state() as u32) | (!mask & m.state() as u32) ) as u8
        ))
    }));

    machine.map_func(vec![State::AttrLen, State::SecondaryKey].to(State::AttrLen), Func::Fun(|m| {
        // take four bytes here, and assign to our attr count.
        // then skip another four and start parsing.
        m.attr_count = m.attr_count << 8 | m.current_byte() as u32;

        // check if counter is four bytes.
        //let mask = (!((m.inc_count() == 4) as i32) + 1) as u32;
        let mask = (((m.inc_count() as i32 ^ 4) - 1) >> 31) as u32;

        let st = (mask & m.next_state() as u32) | (!mask & m.state() as u32);
        Some(State::from_primitive(st as _))
    }));

    machine.map_func(State::SkipAttr4.to(State::SkipAttr4), Func::Fun(|m| {
        let mask = (((m.inc_count() as i32 ^ 4) - 1) >> 31) as u32;

        if mask == 0xFFFFFFFF {
            (0..m.attr_count - 1).into_iter().for_each(|_| m.push_state(State::TLVType));
            println!("Mode is {:?}", m.get_mode());
        };

        Some(State::from_primitive(
                ( (mask & m.next_state() as u32) | (!mask & m.state() as u32) ) as u8
        ))
    }));

    machine.map_func(State::TLVType.to(State::TLVType), Func::Fun(|m| {
        let mask = (((m.inc_count() as i32 ^ 4) - 1) >> 31) as u32;
        m.tlv_type = m.tlv_type << 8 | m.current_byte() as u32;
        Some(State::from_primitive(
                ( (mask & m.next_state() as u32) | (!mask & m.state() as u32) ) as u8
        ))
    }));

    machine.map_func(State::TLVLen.to(State::TLVLen), Func::Fun(|m| {
        let mask = (((m.inc_count() as i32 ^ 4) - 1) >> 31) as u32;
        m.tlv_len = m.tlv_len << 8 | m.current_byte() as u32;

        Some(State::from_primitive(
                ( (mask & m.next_state() as u32) | (!mask & m.state() as u32) ) as u8
        ))
    }));

    machine.map_func(State::TLVValue.to(State::TLVValue), Func::Fun(|m| {

        let mask = (((m.inc_count() as i32 ^ m.tlv_len as i32) - 1) >> 31) as u32;
        let current_byte = m.current_byte();
        m.stack_mut().push(current_byte);

        if mask == 0xFFFFFFFF {
            let byte_vals = m.stack_mut().drain(..).collect::<Vec<_>>();
            println!("Type = {:04x}  Len = {}, Value = {:?} {:?}",
                m.tlv_type,
                m.tlv_len,
                String::from_utf8_lossy(&byte_vals[..]),
                TLVMapping::from_int(m.tlv_type).encode(&byte_vals[..], m.tlv_len),
            );
            // if we have integer values these are bizzarely represented in little endian, so we
            // should swap these without a temporary.
            // so the value at the "end" of the array is 65k, where 1 is set
            //
            // position end - 1 is 16 ^ 3 = 4096
            // position end - 2 is 16 ^ 2 = 256
            // position end - 3 is 16 ^ 1 = 16
            // so [0, 0, 12, 0] ends up
            // 0 << 0
            // 12 << 8
            // 0 << 16
            // 0 << 24
            // and [1, 0, 1] ends up [0, 1, 0, 1]
            // 1 << 0 -------------------------^
            // 0 << 8
            // 1 << 16
            // 0 << 24
            // and 00000c ends up 00 00 0c 00, where the LSB is always padded

            m.attrs_processed += 1;
            m.tlv_type = 0;
            m.tlv_len = 0;
            let retval = m.pop_state();
            retval
        } else {
            None
        }
        // tlv should look at the type field and length field and then determine the value
        // at this point, we should probably have a trait that can handle parsing these.
        //
        // once the tlv_len field is equal to the tlv_value_count, we should pop the state.
        // the popped state will either:
        // 1. give us back another round of TLV parsing
        // 2. move us to the next key-type and TLV parsing
        // 3. move us to the signature phase.

    }));

    machine.map_func(State::SecondaryKey.to(State::SecondaryKey), Func::Fun(|m| {
        // recall there's a 32byte header where we 'start' counting offset.
        // 16 bytes for the signature delta,
        // skip 3, then go to attr len
        let mask = (((m.inc_count() as i32 ^ 4) - 1) >> 31) as u32;
        if mask == 0xFFFFFFFF {
            m.attr_count = 0;
            Some(State::AttrLen)
        } else {
            None
        }
    }));

    machine.map_func(State::Signature.to(State::Signature), Func::Fun(|m| {
        println!("in signature! {}", m.current_byte());
        None
    }));

}
