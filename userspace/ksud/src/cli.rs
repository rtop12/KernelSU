use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;

use android_logger::Config;
use log::{LevelFilter, error, info};

use crate::boot_patch::{BootPatchArgs, BootRestoreArgs};
use crate::lkm_image::BootPatchV2Args;
use crate::module::regenerate_preinit_rc;
use crate::{
    apk_sign, assets, debug, defs, init_event, ksu_uapi, ksucalls, module, module_config, sulog,
    utils,
};

/// KernelSU userspace cli
#[derive(Parser, Debug)]
#[command(author, version = defs::FULL_VERSION, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    Module { #[command(subcommand)] command: Module },
    PostFsData,
    Services,
    #[command(hide = true)]
    Sulogd,
    BootCompleted,
    LateLoad {
        #[arg(long, default_missing_value = "5555", num_args = 0..=1)]
        magica: Option<u16>,
        #[arg(long)]
        allow_shell: bool,
        #[arg(long)]
        post_magica: bool,
        #[arg(long)]
        kmi: Option<String>,
        #[arg(long, default_value_t = String::from(defs::DEFAULT_PACKAGE_NAME))]
        package_name: String,
    },
    SoftReboot,
    Insmod {
        module: PathBuf,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        params: Vec<String>,
    },
    Install {
        #[arg(long, default_value = None)]
        libadbroot: Option<PathBuf>,
        #[arg(long, default_value = None)]
        data_path: Option<PathBuf>,
    },
    Unload,
    Uninstall {
        #[arg(long, default_value_t = String::from(defs::DEFAULT_PACKAGE_NAME))]
        package_name: String,
    },
    Sepolicy { #[command(subcommand)] command: Sepolicy },
    Profile { #[command(subcommand)] command: Profile },
    Feature { #[command(subcommand)] command: Feature },
    BootPatch(BootPatchArgs),
    BootRestore(BootRestoreArgs),
    BootPatchV2(BootPatchV2Args),
    BootInfo { #[command(subcommand)] command: BootInfo },
    Debug { #[command(subcommand)] command: Debug },
    Kernel { #[command(subcommand)] command: Kernel },
    #[command(disable_help_flag = true)]
    Resetprop {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<String>,
    },
    Initrc { #[command(subcommand)] command: Initrc },
    SetSuAlias { path: String },
}

#[derive(clap::Subcommand, Debug)]
enum BootInfo {
    CurrentKmi,
    SupportedKmis,
    IsAbDevice,
    DefaultPartition,
    AvailablePartitions,
    SlotSuffix { #[arg(short = 'u', long, default_value = "false")] ota: bool },
}

#[derive(clap::Subcommand, Debug)]
enum Debug {
    SetManager { #[arg(default_value_t = String::from(defs::DEFAULT_PACKAGE_NAME))] apk: String },
    GetSign { apk: String },
    Su { #[arg(short, long, default_value = "false")] global_mnt: bool },
    Version,
    Test,
    ExtractBinary { name: String, path: PathBuf },
    Mark { #[command(subcommand)] command: MarkCommand },
    Sulogd,
    Info,
    Package,
}

#[derive(clap::Subcommand, Debug)]
enum MarkCommand {
    Get { #[arg(default_value = "0")] pid: i32 },
    Mark { #[arg(default_value = "0")] pid: i32 },
    Unmark { #[arg(default_value = "0")] pid: i32 },
    Refresh,
}

#[derive(clap::Subcommand, Debug)]
enum Sepolicy {
    Patch { sepolicy: String },
    Apply { file: String },
    Check { sepolicy: String },
}

#[derive(clap::Subcommand, Debug)]
enum Module {
    Install { zip: String },
    UndoUninstall { id: String },
    Uninstall { id: String },
    Enable { id: String },
    Disable { id: String },
    Action { id: String },
    List,
    Config {
        #[arg(long)]
        internal: Option<String>,
        #[command(subcommand)]
        command: ModuleConfigCmd,
    },
}

#[derive(clap::Subcommand, Debug)]
enum ModuleConfigCmd {
    Get { key: String },
    Set {
        key: String,
        value: Option<String>,
        #[arg(long)]
        stdin: bool,
        #[arg(short, long)]
        temp: bool,
    },
    List,
    Delete { key: String, #[arg(short, long)] temp: bool },
    Clear { #[arg(short, long)] temp: bool },
}

#[derive(clap::Subcommand, Debug)]
enum Profile {
    GetSepolicy { package: String },
    SetSepolicy { package: String, policy: String },
    GetTemplate { id: String },
    SetTemplate { id: String, template: String },
    DeleteTemplate { id: String },
    ListTemplates,
}

#[derive(clap::Subcommand, Debug)]
enum Feature {
    Get { id: String, #[arg(long, default_value_t = false)] config: bool },
    Set { id: String, value: u64 },
    List,
    Check { id: String },
    Load,
    Save,
}

#[derive(clap::Subcommand, Debug)]
enum Kernel {
    NukeExt4Sysfs { mnt: String },
    Umount { #[command(subcommand)] command: UmountOp },
    NotifyModuleMounted,
}

#[derive(clap::Subcommand, Debug)]
enum UmountOp {
    Add { mnt: String, #[arg(short, long, default_value = "0")] flags: u32 },
    Del { mnt: String },
    Wipe,
}

#[derive(clap::Subcommand, Debug)]
enum Initrc {
    Refresh,
}

pub fn run() -> Result<()> {
    android_logger::init_once(
        Config::default()
            .with_max_level(crate::debug_select!(LevelFilter::Trace, LevelFilter::Info))
            .with_tag("KernelSU"),
    );

    ksucalls::setup_sigsys_handler();

    let arg0 = std::env::args().next().unwrap_or_default();
    let mut is_root_request = arg0 == "su" || arg0.ends_with("/su");

    if !is_root_request {
        if let Some(alias) = std::fs::read_to_string(defs::SU_ALIAS_PATH).ok() {
            let alias = alias.trim();
            if !alias.is_empty() {
                if let Some(file_name) = std::path::Path::new(alias).file_name() {
                    if let Some(file_name_str) = file_name.to_str() {
                        if arg0 == file_name_str || arg0.ends_with(&format!("/{}", file_name_str)) {
                            is_root_request = true;
                        }
                    }
                }
            }
        }
    }

    if is_root_request {
        return crate::su::root_shell();
    }

    if arg0.ends_with("resetprop") {
        let all_args: Vec<String> = std::env::args().collect();
        crate::resetprop::resetprop_main(&all_args)
    }

    let cli = Args::parse();

    log::info!("command: {:?}", cli.command);

    let result = match cli.command {
        Commands::PostFsData => init_event::on_post_fs_data(),
        Commands::BootCompleted => {
            init_event::on_boot_completed();
            Ok(())
        }
        Commands::SoftReboot => crate::soft_reboot::soft_reboot(),
        Commands::Insmod { module, params } => debug::insmod(&module, &params),
        
        Commands::SetSuAlias { path } => {
            let default_path = "/system/bin/su";
            
            if path.is_empty() || path == default_path {
                let _ = std::fs::remove_file(defs::SU_ALIAS_PATH);
                match ksucalls::set_su_path(default_path) {
                    Ok(_) => println!("Reset su alias to default: {}", default_path),
                    Err(e) => println!("Failed to write kernel: {e}"),
                }
            } else {
                match ksucalls::set_su_path(&path) {
                    Ok(_) => {
                        let _ = std::fs::write(defs::SU_ALIAS_PATH, &path);
                        println!("Set su alias to: {}", path);
                    }
                    Err(e) => {
                        println!("Failed to write kernel: {e}");
                        anyhow::bail!("Failed to set su alias via ioctl");
                    }
                }
            }
            Ok(())
        }

        Commands::Module { command } => {
            utils::switch_mnt_ns(1)?;
            match command {
                Module::Install { zip } => module::install_module(&zip),
                Module::UndoUninstall { id } => module::undo_uninstall_module(&id),
                Module::Uninstall { id } => module::uninstall_module(&id),
                Module::Enable { id } => module::enable_module(&id),
                Module::Disable { id } => module::disable_module(&id),
                Module::Action { id } => module::run_action(&id),
                Module::List => module::list_modules(),
                Module::Config { internal, command } => {
                    let module_id = match internal {
                        Some(internal_name) => format!("internal.{internal_name}"),
                        None => std::env::var("KSU_MODULE").map_err(|_| {
                            anyhow::anyhow!(
                                "This command must be run in the context of a module or passed --internal <name>"
                            )
                        })?,
                    };
                    crate::module::validate_module_id(&module_id)?;

                    match command {
                        ModuleConfigCmd::Get { key } => {
                            let config = module_config::merge_configs(&module_id)?;
                            match config.get(&key) {
                                Some(value) => {
                                    println!("{value}");
                                    Ok(())
                                }
                                None => anyhow::bail!("Key '{key}' not found"),
                            }
                        }
                        ModuleConfigCmd::Set {
                            key, value, stdin, temp,
                        } => {
                            module_config::validate_config_key(&key)?;
                            let value_str = match value {
                                Some(v) if !stdin => v,
                                _ => {
                                    use std::io::Read;
                                    let mut buffer = String::new();
                                    std::io::stdin().read_to_string(&mut buffer).context("Failed to read from stdin")?;
                                    buffer
                                }
                            };
                            module_config::validate_config_value(&value_str)?;
                            let config_type = if temp { module_config::ConfigType::Temp } else { module_config::ConfigType::Persist };
                            module_config::set_config_value(&module_id, &key, &value_str, config_type)
                        }
                        ModuleConfigCmd::List => {
                            let config = module_config::merge_configs(&module_id)?;
                            if config.is_empty() {
                                println!("No config entries found");
                            } else {
                                for (key, value) in config {
                                    println!("{key}={value}");
                                }
                            }
                            Ok(())
                        }
                        ModuleConfigCmd::Delete { key, temp } => {
                            let config_type = if temp { module_config::ConfigType::Temp } else { module_config::ConfigType::Persist };
                            module_config::delete_config_value(&module_id, &key, config_type)
                        }
                        ModuleConfigCmd::Clear { temp } => {
                            let config_type = if temp { module_config::ConfigType::Temp } else { module_config::ConfigType::Persist };
                            module_config::clear_config(&module_id, config_type)
                        }
                    }
                }
            }
        }
        Commands::Install { libadbroot, data_path } => utils::install(libadbroot, data_path),
        Commands::Unload => crate::unload::unload(),
        Commands::Uninstall { package_name } => utils::uninstall(&package_name),
        Commands::Sepolicy { command } => match command {
            Sepolicy::Patch { sepolicy } => crate::sepolicy::live_patch(&sepolicy),
            Sepolicy::Apply { file } => crate::sepolicy::apply_file(file),
            Sepolicy::Check { sepolicy } => crate::sepolicy::check_rule(&sepolicy),
        },
        Commands::LateLoad { magica, allow_shell, post_magica, kmi, package_name } => {
            if let Some(port) = magica {
                return crate::magica::run(port, &package_name, allow_shell).map_err(|e| {
                    error!("Error running magica: {e}");
                    e
                });
            }
            let result = crate::late_load::run(&package_name, kmi, allow_shell);
            if post_magica {
                info!("Restoring adb properties (post-magica cleanup)...");
                if let Err(e) = crate::magica::disable_adb_root() {
                    error!("disable adb root failed: {e}");
                }
            }
            result
        }
        Commands::Services => {
            if ksucalls::get_version() <= 0 {
                info!("KernelSU not available, exiting services");
                std::process::exit(0);
            }
            init_event::on_services();
            Ok(())
        }
        Commands::Sulogd => sulog::run_sulogd(),
        Commands::Profile { command } => match command {
            Profile::GetSepolicy { package } => crate::profile::get_sepolicy(package),
            Profile::SetSepolicy { package, policy } => crate::profile::set_sepolicy(package, policy),
            Profile::GetTemplate { id } => crate::profile::get_template(id),
            Profile::SetTemplate { id, template } => crate::profile::set_template(id, template),
            Profile::DeleteTemplate { id } => crate::profile::delete_template(id),
            Profile::ListTemplates => crate::profile::list_templates(),
        },
        Commands::Feature { command } => match command {
            Feature::Get { id, config } => {
                if config { crate::feature::get_feature_config(&id) } else { crate::feature::get_feature(&id) }
            }
            Feature::Set { id, value } => crate::feature::set_feature(&id, value),
            Feature::List => { crate::feature::list_features(); Ok(()) }
            Feature::Check { id } => crate::feature::check_feature(&id),
            Feature::Load => crate::feature::load_config_and_apply(),
            Feature::Save => crate::feature::save_config(),
        },
        Commands::Debug { command } => match command {
            Debug::SetManager { apk } => debug::set_manager(&apk),
            Debug::GetSign { apk } => {
                let sign = apk_sign::get_apk_signature(&apk)?;
                println!("size: {:#x}, hash: {}", sign.0, sign.1);
                Ok(())
            }
            Debug::Version => { println!("Kernel Version: {}", ksucalls::get_version()); Ok(()) }
            Debug::Su { global_mnt } => crate::su::grant_root(global_mnt),
            Debug::Test => assets::ensure_binaries(false),
            Debug::ExtractBinary { name, path } => {
                let data = assets::get_asset_data(&name)?;
                utils::ensure_binary(&path, &data, false)
            }
            Debug::Mark { command } => match command {
                MarkCommand::Get { pid } => debug::mark_get(pid),
                MarkCommand::Mark { pid } => debug::mark_set(pid),
                MarkCommand::Unmark { pid } => debug::mark_unset(pid),
                MarkCommand::Refresh => debug::mark_refresh(),
            },
            Debug::Sulogd => sulog::ensure_sulogd_running(),
            Debug::Info => {
                let info = ksucalls::get_info();
                println!("version: {}", info.version);
                println!("flags: 0x{:x}", info.flags);
                println!("uapi_version: {}", info.uapi_version);
                println!("features: 0x{:x}", info.features);
                println!("lkm: {}", ksucalls::is_lkm());
                println!("bundled: {}", (info.flags & ksu_uapi::KSU_GET_INFO_FLAG_BUNDLED) != 0);
                println!("late_load: {}", ksucalls::is_late_load());
                println!("runtime_mode: {}", ksucalls::runtime_mode());
                println!("pr_build: {}", (info.flags & ksu_uapi::KSU_GET_INFO_FLAG_PR_BUILD) != 0);
                Ok(())
            }
            Debug::Package => { println!("{}", defs::DEFAULT_PACKAGE_NAME); Ok(()) }
        },
        Commands::BootPatch(boot_patch) => crate::boot_patch::patch(boot_patch),
        Commands::BootInfo { command } => match command {
            BootInfo::CurrentKmi => { println!("{}", crate::boot_patch::get_current_kmi()?); return Ok(()); }
            BootInfo::SupportedKmis => {
                for kmi in &crate::assets::list_supported_kmi() { println!("{kmi}"); }
                return Ok(());
            }
            BootInfo::IsAbDevice => {
                let val = crate::utils::getprop("ro.build.ab_update").unwrap_or_else(|| String::from("false"));
                println!("{}", if val.trim().to_lowercase() == "true" { "true" } else { "false" });
                return Ok(());
            }
            BootInfo::DefaultPartition => {
                let kmi = crate::boot_patch::get_current_kmi().unwrap_or_else(|_| String::new());
                println!("{}", crate::boot_patch::choose_boot_partition(&kmi, false, &None));
                return Ok(());
            }
            BootInfo::SlotSuffix { ota } => { println!("{}", crate::boot_patch::get_slot_suffix(ota)); return Ok(()); }
            BootInfo::AvailablePartitions => {
                for p in &crate::boot_patch::list_available_partitions() { println!("{p}"); }
                return Ok(());
            }
        },
        Commands::BootRestore(boot_restore) => crate::boot_patch::restore(boot_restore),
        Commands::BootPatchV2(patch) => crate::lkm_image::patch_boot(&patch),
        Commands::Resetprop { args } => {
            let mut full_args = vec!["resetprop".to_string()];
            full_args.extend(args);
            crate::resetprop::resetprop_main(&full_args)
        }
        Commands::Kernel { command } => match command {
            Kernel::NukeExt4Sysfs { mnt } => ksucalls::nuke_ext4_sysfs(&mnt),
            Kernel::Umount { command } => match command {
                UmountOp::Add { mnt, flags } => ksucalls::umount_list_add(&mnt, flags),
                UmountOp::Del { mnt } => ksucalls::umount_list_del(&mnt),
                UmountOp::Wipe => ksucalls::umount_list_wipe(),
            },
            Kernel::NotifyModuleMounted => { ksucalls::report_module_mounted(); Ok(()) }
        },
        Commands::Initrc { command } => match command {
            Initrc::Refresh => regenerate_preinit_rc(),
        },
    };

    if let Err(e) = &result {
        log::error!("Error: {e:?}");
    }
    result
}
