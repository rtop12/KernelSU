#![allow(clippy::missing_safety_doc)]

mod binder;
mod hook;
mod log;

#[used]
#[link_section = ".init_array"]
static INIT: extern "C" fn() = init;

extern "C" fn init() {
    // 确认 so 加载
    crate::log::write("attest: libinterceptor.so loaded successfully!");
    
    // 暂时注释掉 Hook，看看是不是它导致了崩溃
    //hook::install(); 
}
