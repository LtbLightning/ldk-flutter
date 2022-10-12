use std::ffi::CString;
use crate::ffi;
use allo_isolate::Isolate;
use lazy_static::lazy_static;
use std::io;
use std::os::raw;
use tokio::runtime::{Builder, Runtime};
// Create runtime for tokio in the static scope
lazy_static! {
    static ref RUNTIME: io::Result<Runtime> = Builder::new_multi_thread()
        .enable_all()
        .worker_threads(3)
        .thread_name("ldkrrust")
        .thread_stack_size(8 * 1024 * 1024)
        .build();
}
// Simple Macro to help getting the value of the runtime.
macro_rules! runtime {
    () => {
        match RUNTIME.as_ref() {
            Ok(rt) => rt,
            Err(_) => {
                return 0;
            }
        }
    };
}
macro_rules! error {
    ($result:expr) => {
        error!($result, 0);
    };
    ($result:expr, $error:expr) => {
        match $result {
            Ok(value) => value,
            Err(e) => {
                ffi_helpers::update_last_error(e);
                return $error;
            }
        }
    };
}

macro_rules! cstr {
    ($ptr:expr) => {
        cstr!($ptr, 0)
    };
    ($ptr:expr, $error:expr) => {{
        ffi_helpers::null_pointer_check!($ptr);
        error!(unsafe { CStr::from_ptr($ptr).to_str() }, $error)
    }};
}

fn last_error_length() -> i32 {
    ffi_helpers::error_handling::last_error_length()
}
pub fn check_rpc_init() -> bool {
    ffi::check_rpc_init()
}
pub fn get_node_id()->String{
    ffi::get_node_id()
}
#[tokio::main(flavor = "current_thread")]
pub async fn ldk_load_or_init(username: String,
                 password: String,
                 host: String,
                 network: String,
                 path: String,
                 port: u16,) -> anyhow::Result<String> {
    let result = ffi::ldk_init(host, port, username, password, network, path).await;
    Ok(result)
}

pub fn load_client(
    username: String,
    password: String,
    host: String,
    isolate_port: u16,
    network: String,
    path: String,
    port: u16,
) -> u32
{
    // get a ref to the runtime
    let rt = runtime!();
    rt.block_on(async {
        // load the page and get the result back
        let result = ffi::ldk_init(host, port, username, password, network, path).await;
        // make a ref to an isolate using it's port
        let isolate = Isolate::new(isolate_port as i64);
        // and sent it the `Rust's` result
        // no need to convert anything :)
        isolate.post(result);
    });
    1
}
