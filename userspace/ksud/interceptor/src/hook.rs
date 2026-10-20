use std::ffi::c_void;
use crate::binder::{resolve_transact, TransactFn};

static mut ORIGINAL_TRANSACT: *mut c_void = std::ptr::null_mut();

unsafe extern "C" fn transact_hook(
    binder: *mut c_void,
    code: u32,
    data: *mut c_void,
    reply: *mut c_void,
    flags: u32,
) -> libc::c_int {
    // 【修复】绝对不要在 Hook 内部打同步日志
    // crate::log::write(&format!("attest: transact code={code:#x}"));

    let orig_fn: TransactFn = unsafe { std::mem::transmute(ORIGINAL_TRANSACT) };
    unsafe { orig_fn(binder, code, data, reply, flags) }
}

pub fn install() {
    let Some(target_fn) = resolve_transact() else {
        return;
    };

    let target_ptr = target_fn as *mut c_void;
    let replacement_ptr = transact_hook as *mut c_void;
    let mut original_ptr: *mut c_void = std::ptr::null_mut();

    unsafe {
        cydia_substrate_rs::A64HookFunction(target_ptr, replacement_ptr, &mut original_ptr);
        ORIGINAL_TRANSACT = original_ptr;
    }

    // 只在安装完成时打一次日志，此时还没进入高并发的 Binder 处理逻辑
    if original_ptr.is_null() {
        crate::log::write("attest: A64HookFunction failed, original pointer is null");
    } else {
        crate::log::write("attest: AIBinder_transact hook installed (cydia-substrate)");
    }
}
