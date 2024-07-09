use crate::{Machine, State, Mode, KeyMode};
use crate::function::{FuncState, Func};
use crate::tlv_mapping::{Bytes, EncodeTLV, TLVMapping};
use num_enum::FromPrimitive;


/* Here is where the state machine logic is defined.
 * Notes
 * 1. Shifting between states via map_func returns will reset the counters.
 * 2. All integer values in the TLV are in big-endian, therefore we must bit-shift these as they
 *    appear in network byte order.
 * 3. In the case where we don't have a full byte buffer payload, we attempt to store each byte on
 *    the stack and dispatch on the next state transition. This allows for a full asynchronous
 *    state machine model, even in the case where reads are returning 1 byte at a time.
 * */
pub fn register_functions(machine: &mut Machine) {
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
        m.attr_offset = (mask & (m.total_size - (m.buff_size + m.signature_len as u32))) | (!mask & m.attr_offset);

        // now check if the current index is at our offset
        if m.attr_offset as usize == m.get_index() {
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

    // this operation will also check on the last iteration whether secondkey_offset is greater
    // than 0.
    // If it is, then we have private key attestation to handle for assymetric keys
    // If its not, then we have a symmetric key to parse, moving directly to signature at the end.
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

    machine.map_func(State::Skip4.to(State::Skip4), Func::Fun(|m| {
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
            println!("------------KEYMODE: {:?} -------------", m.get_keymode());
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
            let tlv = TLVMapping::from_int(m.tlv_type);
            println!("Type = {:04x}  {} Len = {},  {:?}", // Value = {:?}",
                m.tlv_type,
                tlv,
                m.tlv_len,
                //String::from_utf8_lossy(&byte_vals[..]),
                tlv.encode(&byte_vals[..], m.tlv_len).to_str(),
            );

            m.attrs_processed += 1;
            m.tlv_type = 0;
            m.tlv_len = 0;
            let retval = m.pop_state();
            retval
        } else {
            None
        }
    }));

    machine.map_func(State::SecondaryKey.to(State::SecondaryKey), Func::Fun(|m| {
        // recall there's a 32byte header where we 'start' counting offset.
        // 16 bytes for the signature delta,
        // skip 3, then go to attr len
        let mask = (((m.inc_count() as i32 ^ 4) - 1) >> 31) as u32;
        if mask == 0xFFFFFFFF {
            m.attr_count = 0;
            m.set_keymode(KeyMode::Secondary);
            Some(State::AttrLen)
        } else {
            None
        }
    }));

    machine.map_func(State::Signature.to(State::Signature), Func::Fun(|m| {
        let current_byte = m.current_byte();
        m.stack_mut().push(current_byte);
        let mask = (((m.inc_count() as i32 ^ m.signature_len as i32) -1) >> 31) as u32;

        if mask == 0xFFFFFFFF {
            let byte_stack = m.stack_mut().drain(..);
            let byte_stack = byte_stack.as_ref();
            println!("Attestation Signature \n{}", Bytes::encode(byte_stack, byte_stack.len() as _)?.to_str());
        }
        None
    }));
}
