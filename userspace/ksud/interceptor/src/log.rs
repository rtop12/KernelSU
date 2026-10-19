extern "C" {
    fn __android_log_write(prio: i32, tag: *const i8, text: *const i8) -> i32;
}

pub fn write(msg: &str) {
    let Ok(c_str) = std::ffi::CString::new(msg) else {
        return;
    };
    let tag = b"KSU_ATTEST\0";
    unsafe {
        __android_log_write(
            4, /* ANDROID_LOG_INFO */
            tag.as_ptr() as *const i8,
            c_str.as_ptr() as *const i8,
        );
    }
}
