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
            let sysfs_path = "/sys/module/kernelsu/parameters/custom_su_path";
            if let Err(e) = std::fs::write(sysfs_path, alias) {
                warn!("Failed to restore su alias to sysfs: {e}");
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
        // we should still ensure module directory exists in safe mode
        // because we may need to operate the module dir in safe mode
        warn!("safe mode, skip common post-fs-data.d scripts");
    } else {
        // Then exec common post-fs-data scripts
        if let Err(e) = crate::module::exec_common_scripts("post-fs-data.d", wait) {
            warn!("exec common post-fs-data scripts failed: {e}");
        }
    }

    let module_dir = defs::MODULE_DIR;

    assets::ensure_binaries(true).with_context(|| "Failed to extract bin assets")?;

    // if we are in safe mode, we should disable all modules
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

    // Refresh /metadata/watchdog/ksu/modules.rc so the next boot's kernel hook sees the
    // current module set. Acts as a safety net when state was changed outside
    // of ksud's normal mutation commands.
    if let Err(e) = crate::module::regenerate_preinit_rc() {
        warn!("regenerate preinit rc failed: {e}");
    }

    if let Err(e) = restorecon::restorecon() {
        warn!("restorecon failed: {e}");
    }

    // load sepolicy.rule
    if crate::module::load_sepolicy_rule().is_err() {
        warn!("load sepolicy.rule failed");
    }

    if let Err(e) = crate::profile::apply_sepolies() {
        warn!("apply root profile sepolicy failed: {e}");
    }

    crate::feature::init_forced_features();

    // load feature config
    if is_safe_mode() {
        warn!("safe mode, skip load feature config");
    } else if let Err(e) = crate::feature::init_features() {
        warn!("init features failed: {e}");
    }

    // execute metamodule post-fs-data script first (priority)
    if let Err(e) = metamodule::exec_stage_script("post-fs-data", wait) {
        warn!("exec metamodule post-fs-data script failed: {e}");
    }

    // exec modules post-fs-data scripts
    if let Err(e) = crate::module::exec_stage_script("post-fs-data", wait) {
        warn!("exec post-fs-data scripts failed: {e}");
    }

    // load system.prop
    if let Err(e) = crate::module::load_system_prop() {
        warn!("load system.prop failed: {e}");
    }

    // execute metamodule mount script
    if let Err(e) = metamodule::exec_mount_script(module_dir) {
        warn!("execute metamodule mount failed: {e}");
    }

    run_stage("post-mount", wait);

    std::env::set_current_dir("/").with_context(|| "failed to chdir to /")?;

    Ok(())
}

/// 部署内置的 Zygisk-Next 模块到 /data/adb/modules/zygisksu
fn deploy_builtin_zygisk() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let module_dir = "/data/adb/modules/zygisksu";
    let module_path = Path::new(module_dir);

    // 1. 尊重用户的操作：如果被禁用了或标记了卸载，则不再强行部署
    if module_path.join("disable").exists() || module_path.join("remove").exists() {
        info!("Built-in Zygisk-Next is disabled or marked for removal, skipping deployment.");
        return Ok(());
    }

    // 2. 如果存在非内置的模块（用户手动安装的），不覆盖
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

    // 3. 写入 module.prop（必须带有 "Built-in" 标识以供后续判断）
    let module_prop = "id=zygisksu\nname=Zygisk-Next (Built-in)\nversion=v1.0\nversionCode=100\nauthor=rtop12\n";
    std::fs::write(&module_prop_path, module_prop)?;

    // 4. 释放 zygiskd 并赋予执行权限
    let zygiskd_data = assets::get_zygiskd()?;
    let zygiskd_path = module_path.join("zygiskd");
    std::fs::write(&zygiskd_path, &zygiskd_data)?;
    std::fs::set_permissions(&zygiskd_path, std::fs::Permissions::from_mode(0o755))?;

    // 5. 释放 zygisk 核心库
    let zygisk_lib_data = assets::get_zygisk_lib()?;
    let zygisk_lib_path = module_path.join("zygisk");
    std::fs::write(&zygisk_lib_path, &zygisk_lib_data)?;
    std::fs::set_permissions(&zygisk_lib_path, std::fs::Permissions::from_mode(0o644))?;

    // 6. 修复 SELinux 上下文，防止执行被拒绝
    let _ = restorecon::lsetfilecon(&zygiskd_path, restorecon::KSU_CON);
    let _ = restorecon::lsetfilecon(&zygisk_lib_path, restorecon::KSU_CON);

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

    // execute metamodule stage script first (priority)
    if let Err(e) = metamodule::exec_stage_script(stage, wait) {
        warn!("Failed to exec metamodule {stage} script: {e}");
    }

    // execute regular modules stage scripts
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
    // timeout -s 9 30s logcat > boot.log
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
