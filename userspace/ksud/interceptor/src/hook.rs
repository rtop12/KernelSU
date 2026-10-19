use std::sync::OnceLock;

use crate::binder::{resolve_transact, TransactFn};

static ORIG: OnceLock<TransactFn> = OnceLock::new();

unsafe extern "C" fn transact_hook(
    binder: *mut libc::c_void,
    code: u32,
    data: *mut libc::c_void,
    reply: *mut libc::c_void,
    flags: u32,
) -> libc::c_int {
    let Some(orig) = ORIG.get() else {
        return -1;
    };

    // Phase 1: log only. Phase 2 will parse/rewrite `reply` here.
    if matches!(code, 0x4b4d_4545 | 0x4b4d_4546) {
        // placeholder codes; real KeyMint codes will be confirmed from logs
        crate::log::write(&format!("attest: transact code={code:#x}"));
    }

    orig(binder, code, data, reply, flags)
}

pub fn install() {
    let Some(orig) = resolve_transact() else {
        crate::log::write("attest: failed to resolve AIBinder_transact");
        return;
    };
    let _ = ORIG.set(orig);

    // Use retour inline hook. `initialize` may fail on some kernels; log and continue.
    unsafe {
        let target: unsafe extern "C" fn(*mut libc::c_void, u32, *mut libc::c_void, *mut libc::c_void, u32) -> libc::c_int =
            std::mem::transmute(orig);
        static_detour! {
            static TRANSACT: unsafe extern "C" fn(*mut libc::c_void, u32, *mut libc::c_void, *mut libc::c_void, u32) -> libc::c_int;
        }
        if let Err(e) = TRANSACT.initialize(target, transact_hook) {
            crate::log::write(&format!("attest: detour initialize failed: {e:?}"));
            return;
        }
        if let Err(e) = TRANSACT.enable() {
            crate::log::write(&format!("attest: detour enable failed: {e:?}"));
            return;
        }
    }
    crate::log::write("attest: AIBinder_transact hook installed");
}
