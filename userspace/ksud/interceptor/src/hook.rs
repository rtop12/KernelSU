use std::ffi::c_void;
use std::sync::OnceLock;

use crate::binder::{resolve_transact, TransactFn};

// 保存原始函数的指针，用于后续调用
static mut ORIGINAL_TRANSACT: *mut c_void = std::ptr::null_mut();

unsafe extern "C" fn transact_hook(
    binder: *mut c_void,
    code: u32,
    data: *mut c_void,
    reply: *mut c_void,
    flags: u32,
) -> libc::c_int {
    // Phase 1: 打印所有 Binder transaction 的 code
    crate::log::write(&format!("attest: transact code={code:#x}"));

    // 调用原始函数
    let orig: TransactFn = std::mem::transmute(ORIGINAL_TRANSACT);
    if let Some(orig) = orig {
        unsafe { orig(binder, code, data, reply, flags) }
    } else {
        -1 // 如果原始函数指针无效，返回错误
    }
}

pub fn install() {
    let Some(target) = resolve_transact() else {
        crate::log::write("attest: failed to resolve AIBinder_transact");
        return;
    };

    let target_ptr = target as *mut c_void;
    let replacement_ptr = transact_hook as *mut c_void;
    let mut original_ptr: *mut c_void = std::ptr::null_mut();

    // 使用 cydia-substrate-rs 的 AArch64 专用 Hook API
    unsafe {
        cydia_substrate_rs::A64HookFunction(target_ptr, replacement_ptr, &mut original_ptr);
        ORIGINAL_TRANSACT = original_ptr;
    }

    if ORIGINAL_TRANSACT.is_null() {
        crate::log::write("attest: A64HookFunction failed, original pointer is null");
    } else {
        crate::log::write("attest: AIBinder_transact hook installed (cydia-substrate)");
    }
}
