#![allow(clippy::missing_safety_doc)]

mod binder;
mod hook;
mod log;

#[used]
#[link_section = ".init_array"]
static INIT: extern "C" fn() = init;

extern "C" fn init() {
    hook::install();
}
