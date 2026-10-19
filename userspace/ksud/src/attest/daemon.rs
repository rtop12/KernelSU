use anyhow::{Context, Result};
use log::{info, warn};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::{defs, utils};

pub fn spawn() -> Result<()> {
    if utils::create_daemon(true)? {
        let exe = std::env::current_exe()?;
        let mut cmd = std::process::Command::new(exe);
        cmd.arg("attestd").current_dir("/");
        match cmd.spawn() {
            Ok(_) => unsafe { libc::_exit(0) },
            Err(e) => {
                log::error!("attest: failed to spawn attestd: {e:#}");
                return Err(e.into());
            }
        }
    }
    Ok(())
}

pub fn run_daemon() -> Result<()> {
    crate::attest::install_interceptor_lib()?;

    let _ = std::fs::remove_file(defs::ATTEST_SOCKET_PATH);
    let listener = UnixListener::bind(defs::ATTEST_SOCKET_PATH)
        .with_context(|| format!("bind {}", defs::ATTEST_SOCKET_PATH))?;
    info!("attestd: listening on {}", defs::ATTEST_SOCKET_PATH);

    let running = Arc::new(AtomicBool::new(true));
    {
        let running = running.clone();
        std::thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                if let Err(e) = ensure_keystore2_injected() {
                    warn!("attestd: ensure_keystore2_injected: {e:#}");
                }
                std::thread::sleep(Duration::from_secs(5));
            }
        });
    }

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                if let Err(e) = handle_interceptor(s) {
                    warn!("attestd: handle_interceptor: {e:#}");
                }
            }
            Err(e) => warn!("attestd: accept: {e}"),
        }
    }
    running.store(false, Ordering::Relaxed);
    Ok(())
}

fn ensure_keystore2_injected() -> Result<()> {
    let Some(pid) = crate::attest::injector::find_pid_by_comm("keystore2") else {
        return Ok(());
    };
    if crate::attest::injector::is_already_injected(pid, "libinterceptor.so") {
        return Ok(());
    }
    info!("attestd: injecting interceptor into keystore2 (pid={pid})");
    crate::attest::injector::inject(pid, defs::ATTEST_LIB_PATH)
}

fn handle_interceptor(mut stream: std::os::unix::net::UnixStream) -> Result<()> {
    use std::io::{BufRead, BufReader, Write};
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.trim() == "HELLO" {
        stream.write_all(b"OK\n")?;
    }
    Ok(())
}
