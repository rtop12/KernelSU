use crate::module::{ScriptWait, handle_updated_modules, prune_modules};
use crate::utils::is_safe_mode;
use crate::{
    assets, defs, ksucalls, metamodule, restorecon,
    utils::{self},
};
use anyhow::{Context, Result};
use log::{error, info, warn};
use std::{path::Path, time::Instant};

pub fn on_post_fs_data() -> Result<()> {
    if let Err(e) = ksucalls::ensure_uapi_version_matched() {
        error!("{e:#}, skip on_post_fs_data");
        return Ok(());
    }

    ksucalls::report_post_fs_data();

    utils::umask(0);

    // Clear all temporary module configs early
    if let Err(e) = crate::module_config::clear_all_temp_configs() {
        warn!("clear temp configs failed: {e}");
    }

    if let Some(alias) = std::fs::read_to_string(defs::SU_ALIAS_PATH).ok() {
        let alias = alias.trim();
        if !alias.is_empty() {
            if let Err(e) = ksucalls::set_su_path(alias) {
                warn!("Failed to restore su alias via ioctl: {e}");
            } else {
                info!("Restored su alias to: {alias}");
            }
        }
    }

    let _ = catch_bootlog("logcat", &["logcat", "-b", "all"]);
    let _ = catch_bootlog("dmesg", &["dmesg", "-w", "-r"]);

    if utils::has_magisk() {
        warn!("Magisk detected, skip post-fs-data!");
        return Ok(());
    }

    let safe_mode = crate::utils::is_safe_mode();
    let wait = ScriptWait::Until(Instant::now() + defs::BOOT_STAGE_TIMEOUT);

    if safe_mode {
        warn!("safe mode, skip common post-fs-data.d scripts");
    } else {
        if let Err(e) = crate::module::exec_common_scripts("post-fs-data.d", wait) {
            warn!("exec common post-fs-data scripts failed: {e}");
        }
    }

    let module_dir = defs::MODULE_DIR;

    assets::ensure_binaries(true).with_context(|| "Failed to extract bin assets")?;

    if safe_mode {
        warn!("safe mode, skip post-fs-data scripts and disable all modules!");
        if let Err(e) = crate::module::disable_all_modules() {
            warn!("disable all modules failed: {e}");
        }
        return Ok(());
    }

    if let Err(e) = handle_updated_modules() {
        warn!("handle updated modules failed: {e}");
    }

    if let Err(e) = prune_modules() {
        warn!("prune modules failed: {e}");
    }

    // [新增] 部署内置的 Zygisk-Next
    if let Err(e) = deploy_builtin_zygisk() {
        warn!("Failed to deploy built-in Zygisk-Next: {e}");
    }

    if let Err(e) = crate::module::regenerate_preinit_rc() {
        warn!("regenerate preinit rc failed: {e}");
    }

    if let Err(e) = restorecon::restorecon() {
        warn!("restorecon failed: {e}");
    }

    if crate::module::load_sepolicy_rule().is_err() {
        warn!("load sepolicy.rule failed");
    }

    if let Err(e) = crate::profile::apply_sepolies() {
        warn!("apply root profile sepolicy failed: {e}");
    }

    crate::feature::init_forced_features();

    if is_safe_mode() {
        warn!("safe mode, skip load feature config");
    } else if let Err(e) = crate::feature::init_features() {
        warn!("init features failed: {e}");
    }

    if let Err(e) = metamodule::exec_stage_script("post-fs-data", wait) {
        warn!("exec metamodule post-fs-data script failed: {e}");
    }

    if let Err(e) = crate::module::exec_stage_script("post-fs-data", wait) {
        warn!("exec post-fs-data scripts failed: {e}");
    }

    if let Err(e) = crate::module::load_system_prop() {
        warn!("load system.prop failed: {e}");
    }

    if let Err(e) = metamodule::exec_mount_script(module_dir) {
        warn!("execute metamodule mount failed: {e}");
    }

    run_stage("post-mount", wait);

    std::env::set_current_dir("/").with_context(|| "failed to chdir to /")?;

    Ok(())
}

fn deploy_builtin_zygisk() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let module_dir = "/data/adb/modules/zygisksu";
    let module_path = Path::new(module_dir);

    if module_path.join("disable").exists() || module_path.join("remove").exists() {
        info!("Built-in Zygisk-Next is disabled or marked for removal, skipping deployment.");
        return Ok(());
    }

    let module_prop_path = module_path.join("module.prop");
    if module_prop_path.exists() {
        if let Ok(prop) = std::fs::read_to_string(&module_prop_path) {
            if !prop.contains("Built-in") {
                info!("Third-party zygisksu module detected, skipping built-in deployment.");
                return Ok(());
            }
        }
    }

    if !module_path.exists() {
        utils::ensure_dir_exists(module_dir)?;
    }

    let module_prop = "id=zygisksu\nname=Zygisk-Next (Built-in)\nversion=v1.0\nversionCode=100\nauthor=rtop12\n";
    std::fs::write(&module_prop_path, module_prop)?;

    let zygiskd_data = assets::get_zygiskd()?;
    let zygiskd_path = module_path.join("zygiskd");
    std::fs::write(&zygiskd_path, &zygiskd_data)?;
    std::fs::set_permissions(&zygiskd_path, std::fs::Permissions::from_mode(0o755))?;

    let zygisk_lib_data = assets::get_zygisk_lib()?;
    let zygisk_lib_path = module_path.join("zygisk");
    std::fs::write(&zygisk_lib_path, &zygisk_lib_data)?;
    std::fs::set_permissions(&zygisk_lib_path, std::fs::Permissions::from_mode(0o644))?;

    // 新增：写入启动脚本，确保 zygiskd 被拉起
    let post_fs_data_path = module_path.join("post-fs-data.sh");
    let post_fs_data_content = r#"#!/system/bin/sh
MODDIR=${0%/*}
# 启动 zygiskd 并放到后台
$MODDIR/zygiskd &
"#;
    std::fs::write(&post_fs_data_path, post_fs_data_content)?;
    std::fs::set_permissions(&post_fs_data_path, std::fs::Permissions::from_mode(0o755))?;

    let _ = restorecon::lsetfilecon(&zygiskd_path, restorecon::KSU_CON);
    let _ = restorecon::lsetfilecon(&zygisk_lib_path, restorecon::KSU_CON);
    let _ = restorecon::lsetfilecon(&post_fs_data_path, restorecon::KSU_CON);

    info!("Built-in Zygisk-Next deployed successfully to {module_dir}");
    Ok(())
}

pub fn run_stage(stage: &str, wait: ScriptWait) {
    utils::umask(0);

    if utils::has_magisk() {
        warn!("Magisk detected, skip {stage}");
        return;
    }

    if crate::utils::is_safe_mode() {
        warn!("safe mode, skip {stage} scripts");
        return;
    }

    if let Err(e) = crate::module::exec_common_scripts(&format!("{stage}.d"), wait) {
        warn!("Failed to exec common {stage} scripts: {e}");
    }

    if let Err(e) = metamodule::exec_stage_script(stage, wait) {
        warn!("Failed to exec metamodule {stage} script: {e}");
    }

    if let Err(e) = crate::module::exec_stage_script(stage, wait) {
        warn!("Failed to exec {stage} scripts: {e}");
    }
}

pub fn on_services() {
    if let Err(e) = ksucalls::ensure_uapi_version_matched() {
        error!("{e:#}, skip on_services");
        return;
    }

    match ksucalls::report_services() {
        Ok(true) => {}
        Ok(false) => {
            info!("services already started, skipping");
            return;
        }
        Err(e) => {
            error!("Failed to report services: {e:#}");
            return;
        }
    }

    info!("on_services triggered!");
    run_stage("service", ScriptWait::NoWait);
}

pub fn on_boot_completed() {
    if let Err(e) = ksucalls::ensure_uapi_version_matched() {
        error!("{e:#}, skip on_boot_completed");
        return;
    }

    ksucalls::report_boot_complete();
    info!("on_boot_completed triggered!");

    run_stage("boot-completed", ScriptWait::NoWait);
}

fn catch_bootlog(logname: &str, command: &[&str]) -> Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;

    let logdir = Path::new(defs::LOG_DIR);
    utils::ensure_dir_exists(logdir)?;
    let bootlog = logdir.join(format!("{logname}.log"));
    let oldbootlog = logdir.join(format!("{logname}.old.log"));

    if bootlog.exists() {
        std::fs::rename(&bootlog, oldbootlog)?;
    }

    let bootlog = std::fs::File::create(bootlog)?;

    let mut args = vec!["-s", "9", defs::BOOTLOG_TIMEOUT];
    args.extend_from_slice(command);
    let result = unsafe {
        std::process::Command::new("timeout")
            .process_group(0)
            .pre_exec(|| {
                utils::switch_cgroups();
                Ok(())
            })
            .args(args)
            .stdout(Stdio::from(bootlog))
            .spawn()
    };

    if let Err(e) = result {
        warn!("Failed to start logcat: {e:#}");
    }

    Ok(())
}
