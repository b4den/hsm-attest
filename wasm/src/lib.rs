use std::ffi::{c_char, CString};
use hsmattest::{state_transitions, Machine};

macro_rules! println {
    ($($tt:tt)*) => {
        $crate::log(format!($($tt)*))
    }
}

#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern fn multi() -> (u32, u32) {
    (101, 102)
}

#[no_mangle]
pub unsafe fn parse(byte_buffer_ptr: *mut u8, byte_buffer_len: u32, kv_ptr: *mut u8, kv_len: u32) -> *mut u8 {
    // write some arbitrary values into kv_ptr.
    let mut data = Vec::from_raw_parts(kv_ptr, kv_len as usize, kv_len as usize);
    data.as_mut_slice()[..].copy_from_slice(b"hilo");

    let mut machine  = Machine::new();
    state_transitions::register_functions(&mut machine);

    let byte_buff = Vec::from_raw_parts(byte_buffer_ptr, byte_buffer_len as usize, byte_buffer_len as usize);
    for item in byte_buff {
        println!("in item! ");
        machine.parse(item);
    }
    data[3] = 100;
    log("In parse!".into());

    data.as_mut_ptr()
}

#[no_mangle]
pub fn alloc(len: usize) -> *mut u8 {
    // create a new mutable buffer with capacity `len`
    let mut buf = Vec::with_capacity(len);
    // take a mutable pointer to the buffer
    let ptr = buf.as_mut_ptr();
    // take ownership of the memory block and
    // ensure that its destructor is not
    // called when the object goes out of scope
    // at the end of the function
    std::mem::forget(buf);
    // return the pointer so the runtime
    // can write data at this offset
    return ptr;
}

#[no_mangle]
pub unsafe fn dealloc(ptr: *mut u8, size: usize) {
    let data = Vec::from_raw_parts(ptr, size, size);
    std::mem::drop(data)
}

#[no_mangle]
pub unsafe fn array_sum(ptr: *mut u8, len: usize) -> u8 {
    // create a Vec<u8> from the pointer to the
    // linear memory and the length
    let mut data = Vec::from_raw_parts(ptr, len, len);
    data[0] = 53;
    // actually compute the sum and return it
    data.iter().sum()
}

#[no_mangle]
pub extern fn the_answer() -> u32 {
    let m  = Machine::new();
    println!("got the answer!");
    0
}

extern "C" {
    fn consoleLog(p: *mut c_char);
}

fn log(s: String) {
    let c_string = CString::new(s).unwrap();
    let p: *mut c_char = c_string.into_raw();

    unsafe {
        consoleLog(p);
    }
}

#[no_mangle]
fn dealloc_cstring(p: *mut c_char) {
    let _ = unsafe {
        CString::from_raw(p)
    };
}
