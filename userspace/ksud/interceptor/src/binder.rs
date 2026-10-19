use libc::{c_int, c_void};

pub type TransactFn = unsafe extern "C" fn(
    binder: *mut c_void,
    code: u32,
    data: *mut c_void,
    reply: *mut c_void,
    flags: u32,
) -> c_int;

pub fn resolve_transact() -> Option<TransactFn> {
    unsafe {
        let handle = libc::dlopen(
            b"libbinder_ndk.so\0".as_ptr() as *const libc::c_char,
            libc::RTLD_NOW,
        );
        if handle.is_null() {
            return None;
        }
        let sym = libc::dlsym(handle, b"AIBinder_transact\0".as_ptr() as *const libc::c_char);
        if sym.is_null() {
            return None;
        }
        Some(std::mem::transmute::<*mut c_void, TransactFn>(sym))
    }
}
