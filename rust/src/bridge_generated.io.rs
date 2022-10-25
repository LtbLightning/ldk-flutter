use super::*;
// Section: wire functions

#[no_mangle]
pub extern "C" fn wire_connect_peer(
    port_: i64,
    pub_key_str: *mut wire_uint_8_list,
    peer_add_str: *mut wire_uint_8_list,
) {
    wire_connect_peer_impl(port_, pub_key_str, peer_add_str)
}

#[no_mangle]
pub extern "C" fn wire_list_peers(port_: i64) {
    wire_list_peers_impl(port_)
}

#[no_mangle]
pub extern "C" fn wire_get_node_info(port_: i64) {
    wire_get_node_info_impl(port_)
}

#[no_mangle]
pub extern "C" fn wire_open_channel(
    port_: i64,
    pub_key_str: *mut wire_uint_8_list,
    peer_add_str: *mut wire_uint_8_list,
    amount: u64,
    is_public: bool,
) {
    wire_open_channel_impl(port_, pub_key_str, peer_add_str, amount, is_public)
}

#[no_mangle]
pub extern "C" fn wire_list_channels(port_: i64) {
    wire_list_channels_impl(port_)
}

#[no_mangle]
pub extern "C" fn wire_close_channel(
    port_: i64,
    channel_id_str: *mut wire_uint_8_list,
    peer_pubkey_str: *mut wire_uint_8_list,
) {
    wire_close_channel_impl(port_, channel_id_str, peer_pubkey_str)
}

#[no_mangle]
pub extern "C" fn wire_force_close_channel(
    port_: i64,
    channel_id_str: *mut wire_uint_8_list,
    peer_pubkey_str: *mut wire_uint_8_list,
) {
    wire_force_close_channel_impl(port_, channel_id_str, peer_pubkey_str)
}

#[no_mangle]
pub extern "C" fn wire_start_ldk(
    port_: i64,
    username: *mut wire_uint_8_list,
    password: *mut wire_uint_8_list,
    host: *mut wire_uint_8_list,
    node_network: i32,
    path: *mut wire_uint_8_list,
    port: u16,
) {
    wire_start_ldk_impl(port_, username, password, host, node_network, path, port)
}

// Section: allocate functions

#[no_mangle]
pub extern "C" fn new_uint_8_list_0(len: i32) -> *mut wire_uint_8_list {
    let ans = wire_uint_8_list {
        ptr: support::new_leak_vec_ptr(Default::default(), len),
        len,
    };
    support::new_leak_box_ptr(ans)
}

// Section: impl Wire2Api

impl Wire2Api<String> for *mut wire_uint_8_list {
    fn wire2api(self) -> String {
        let vec: Vec<u8> = self.wire2api();
        String::from_utf8_lossy(&vec).into_owned()
    }
}

impl Wire2Api<Vec<u8>> for *mut wire_uint_8_list {
    fn wire2api(self) -> Vec<u8> {
        unsafe {
            let wrap = support::box_from_leak_ptr(self);
            support::vec_from_leak_ptr(wrap.ptr, wrap.len)
        }
    }
}
// Section: wire structs

#[repr(C)]
#[derive(Clone)]
pub struct wire_uint_8_list {
    ptr: *mut u8,
    len: i32,
}

// Section: impl NewWithNullPtr

pub trait NewWithNullPtr {
    fn new_with_null_ptr() -> Self;
}

impl<T> NewWithNullPtr for *mut T {
    fn new_with_null_ptr() -> Self {
        std::ptr::null_mut()
    }
}

// Section: sync execution mode utility

#[no_mangle]
pub extern "C" fn free_WireSyncReturnStruct(val: support::WireSyncReturnStruct) {
    unsafe {
        let _ = support::vec_from_leak_ptr(val.ptr, val.len);
    }
}
