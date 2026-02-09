mod charlie_cypher;
mod protocol;
mod utils;

use core::slice;

#[no_mangle]
pub unsafe extern "C" fn charlie_cypher(data: *mut u8, len: usize) {
    if data.is_null() {
        return;
    }

    let slice = unsafe { slice::from_raw_parts_mut(data, len) };
    charlie_cypher::cypher(slice);
}

#[no_mangle]
pub unsafe extern "C" fn charlie_decypher(data: *mut u8, len: usize) {
    if data.is_null() {
        return;
    }

    let slice = unsafe { slice::from_raw_parts_mut(data, len) };
    let _ = protocol::iotc_record::parse(slice, None);
}
