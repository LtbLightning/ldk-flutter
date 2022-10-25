use super::*;
// Section: wire functions

#[wasm_bindgen]
pub fn wire_get_node_info(port_: MessagePort) {
    wire_get_node_info_impl(port_)
}

#[wasm_bindgen]
pub fn wire_open_channel(
    port_: MessagePort,
    pub_key_str: String,
    peer_add_str: String,
    amount: u64,
    is_public: bool,
) {
    wire_open_channel_impl(port_, pub_key_str, peer_add_str, amount, is_public)
}

#[wasm_bindgen]
pub fn wire_list_channels(port_: MessagePort) {
    wire_list_channels_impl(port_)
}

#[wasm_bindgen]
pub fn wire_list_peers(port_: MessagePort) {
    wire_list_peers_impl(port_)
}

#[wasm_bindgen]
pub fn wire_close_channel(port_: MessagePort, channel_id_str: String, peer_pubkey_str: String) {
    wire_close_channel_impl(port_, channel_id_str, peer_pubkey_str)
}

#[wasm_bindgen]
pub fn wire_force_close_channel(
    port_: MessagePort,
    channel_id_str: String,
    peer_pubkey_str: String,
) {
    wire_force_close_channel_impl(port_, channel_id_str, peer_pubkey_str)
}

#[wasm_bindgen]
pub fn wire_start_ldk(
    port_: MessagePort,
    username: String,
    password: String,
    host: String,
    node_network: i32,
    path: String,
    port: u16,
) {
    wire_start_ldk_impl(port_, username, password, host, node_network, path, port)
}

// Section: allocate functions

// Section: impl Wire2Api

impl Wire2Api<String> for String {
    fn wire2api(self) -> String {
        self
    }
}

impl Wire2Api<Vec<u8>> for Box<[u8]> {
    fn wire2api(self) -> Vec<u8> {
        self.into_vec()
    }
}
// Section: impl Wire2Api for JsValue

impl Wire2Api<String> for JsValue {
    fn wire2api(self) -> String {
        self.as_string().expect("non-UTF-8 string, or not a string")
    }
}
impl Wire2Api<bool> for JsValue {
    fn wire2api(self) -> bool {
        self.is_truthy()
    }
}
impl Wire2Api<i32> for JsValue {
    fn wire2api(self) -> i32 {
        self.unchecked_into_f64() as _
    }
}
impl Wire2Api<Network> for JsValue {
    fn wire2api(self) -> Network {
        (self.unchecked_into_f64() as i32).wire2api()
    }
}
impl Wire2Api<u16> for JsValue {
    fn wire2api(self) -> u16 {
        self.unchecked_into_f64() as _
    }
}
impl Wire2Api<u64> for JsValue {
    fn wire2api(self) -> u64 {
        ::std::convert::TryInto::try_into(self.dyn_into::<js_sys::BigInt>().unwrap()).unwrap()
    }
}
impl Wire2Api<u8> for JsValue {
    fn wire2api(self) -> u8 {
        self.unchecked_into_f64() as _
    }
}
impl Wire2Api<Vec<u8>> for JsValue {
    fn wire2api(self) -> Vec<u8> {
        self.unchecked_into::<js_sys::Uint8Array>().to_vec().into()
    }
}
