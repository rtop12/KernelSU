pub mod config;
pub mod daemon;
pub mod injector;
pub mod x509;

use anyhow::{Context, Result};
use log::info;
use std::path::Path;

use crate::defs;
use crate::feature_id::FeatureId;
use crate::utils::ensure_binary;

pub fn ensure_started() -> Result<()> {
    if !is_enabled() {
        info!("attest: feature disabled, skip");
        return Ok(());
    }
    config::ensure_default_configs()?;
    install_interceptor_lib()?;
    daemon::spawn()?;
    Ok(())
}

fn is_enabled() -> bool {
    crate::ksucalls::get_feature(FeatureId::AttestSpoof as u32)
        .map(|s| s.supported && s.value != 0)
        .unwrap_or(false)
}

pub fn install_interceptor_lib() -> Result<()> {
    let target_path = crate::defs::ATTEST_LIB_PATH;

    // 如果手机里已经有这个文件了，直接跳过释放逻辑（方便手动 push 测试）
    if std::path::Path::new(target_path).exists() {
        return Ok(());
    }

    let data = crate::assets::get_asset_data("libinterceptor.so").context(
        "libinterceptor.so is not embedded; build the interceptor crate and copy it to ksud/bin/aarch64/",
    )?;
    ensure_binary(defs::ATTEST_LIB_PATH, &data, false)?;
    Ok(())
}

// --- CLI helpers ---------------------------------------------------------
// These are called from `cli.rs` under `Commands::Attest { .. }`.

pub fn cli_status() -> Result<()> {
    let enabled = is_enabled();
    let pid = injector::find_pid_by_comm("keystore2");
    let injected = pid.is_some_and(|p| injector::is_already_injected(p, "libinterceptor.so"));
    let cfg = config::load()?;

    println!("feature enabled: {enabled}");
    println!("keystore2 pid:  {pid:?}");
    println!(
        "interceptor:    {}",
        if injected { "injected" } else { "not injected" }
    );
    println!("targets:        {} entries", cfg.targets.len());
    println!("keyboxes:       {} entries", cfg.keyboxes.len());
    Ok(())
}

pub fn cli_list_targets() -> Result<()> {
    let cfg = config::load()?;
    if cfg.targets.is_empty() {
        println!("(empty)");
        return Ok(());
    }
    for t in cfg.targets {
        println!("{:<50} {:?}", t.package, t.mode);
    }
    Ok(())
}

pub fn cli_set_targets(packages: &[String]) -> Result<()> {
    config::ensure_default_configs()?;
    std::fs::write(defs::ATTEST_TARGET_PATH, packages.join("\n"))?;
    cli_reload()
}

pub fn cli_show_patch() -> Result<()> {
    let cfg = config::load()?;
    println!("system: {:?}", cfg.patch.system);
    println!("vendor: {:?}", cfg.patch.vendor);
    println!("boot:   {:?}", cfg.patch.boot);
    Ok(())
}

pub fn cli_set_patch(value: &str) -> Result<()> {
    config::ensure_default_configs()?;
    std::fs::write(defs::ATTEST_SECURITY_PATCH_PATH, value)?;
    cli_reload()
}

pub fn cli_reload() -> Result<()> {
    // Phase 1: touch a marker file; Phase 2 will replace this with a
    // broadcast message over `defs::ATTEST_SOCKET_PATH`.
    let marker = Path::new(defs::ATTEST_DIR).join(".reload");
    std::fs::write(marker, b"")?;
    println!("reload requested");
    Ok(())
}

pub fn cli_verify() -> Result<()> {
    // Phase 1: parse_keybox() returns an empty Vec, so this only confirms
    // the file exists and the XML is structurally acceptable.
    let keyboxes = config::parse_keybox(Path::new(defs::ATTEST_KEYBOX_PATH))?;
    if keyboxes.is_empty() {
        println!("keybox: (empty, or parser not yet implemented)");
    } else {
        println!("keybox: {} entries", keyboxes.len());
    }
    Ok(())
}

pub fn cli_inject(pid: i32) -> Result<()> {
    println!("Manually injecting into pid: {}", pid);

    // 动态下发 SELinux 规则，允许 keystore 和 keystore2 读取并执行我们的文件
    let sepolicy = "allow keystore ksu_file file { read open map execute getattr }; allow keystore2 ksu_file file { read open map execute getattr };";
    println!("Applying sepolicy: {}", sepolicy);

    // 调用 ksud 自身的 sepolicy 功能
    let exe = std::env::current_exe()
        .unwrap_or_else(|_| std::path::PathBuf::from("/data/adb/kitsune/kitsune"));
    let _ = std::process::Command::new(exe)
        .args(["sepolicy", "patch", sepolicy])
        .status();

    // 执行注入
    injector::inject(pid, defs::ATTEST_LIB_PATH)?;
    println!("Injection command sent successfully!");
    Ok(())
}
