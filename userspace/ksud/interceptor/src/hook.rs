use retour::static_detour;

use crate::binder::resolve_transact;

// `static_detour!` must be expanded at module scope, not inside a function.
retour::static_detour! {
    static TRANSACT: unsafe extern "C" fn(
        *mut libc::c_void, u32, *mut libc::c_void, *mut libc::c_void, u32
    ) -> libc::c_int;
}

unsafe extern "C" fn transact_hook(
    binder: *mut libc::c_void,
    code: u32,
    data: *mut libc::c_void,
    reply: *mut libc::c_void,
    flags: u32,
) -> libc::c_int {
    // Phase 1: log *every* transact code. We need the full set to identify
    // KeyMint's generateKey / getKeyEntry codes before writing the Phase 2
    // parcel parser. Filtering by guessed codes loses data we cannot recover.
    crate::log::write(&format!("attest: transact code={code:#x}"));

    // `TRANSACT.call` invokes the saved original. Calling `orig()` directly
    // would recurse into the detour itself.
    unsafe { TRANSACT.call(binder, code, data, reply, flags) }
}

pub fn install() {
    let Some(orig) = resolve_transact() else {
        crate::log::write("attest: failed to resolve AIBinder_transact");
        return;
    };

    unsafe {
        if let Err(e) = TRANSACT.initialize(orig, transact_hook) {
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
