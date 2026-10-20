use anyhow::Result;
use rust_embed::RustEmbed;

#[cfg(target_os = "android")]
mod android {
    use crate::assets::Asset;
    use crate::defs::BINARY_DIR;
    use crate::utils::ensure_binary;
    use const_format::concatcp;

    pub const RESETPROP_PATH: &str = concatcp!(BINARY_DIR, "resetprop");
    pub const BUSYBOX_PATH: &str = concatcp!(BINARY_DIR, "busybox");
    pub const BOOTCTL_PATH: &str = concatcp!(BINARY_DIR, "bootctl");

    pub fn ensure_binaries(ignore_if_exist: bool) -> anyhow::Result<()> {
        for file in Asset::iter() {
            // 1. 过滤掉不需要释放到 BINARY_DIR 的文件
            if file == "ksuinit" 
                || file == "waitsys" 
                || file.ends_with(".ko")
                || file == "zygiskd"  // 排除 zygiskd
                || file == "zygisk"   // 排除 zygisk 库
            {
                continue;
            }
            let asset =
                Asset::get(&file).ok_or_else(|| anyhow::anyhow!("asset not found: {file}"))?;
            ensure_binary(format!("{BINARY_DIR}{file}"), &asset.data, ignore_if_exist)?;
        }

        let resetprop_link = RESETPROP_PATH;
        let _ = std::fs::remove_file(resetprop_link);
        
        std::os::unix::fs::symlink("/data/adb/kitsune/kitsune", resetprop_link)?;

        Ok(())
    }

    // 2. 为 Zygisk-Next 添加专用的获取接口
    pub fn get_zygiskd() -> Result<std::borrow::Cow<'static, [u8]>> {
        crate::assets::get_asset_data("zygiskd")
    }

    pub fn get_zygisk_lib() -> Result<std::borrow::Cow<'static, [u8]>> {
        crate::assets::get_asset_data("zygisk")
    }
}

#[cfg(target_os = "android")]
pub use android::*;

#[cfg(all(target_arch = "aarch64", target_os = "android"))]
#[derive(RustEmbed)]
#[folder = "bin/aarch64"]
struct Asset;

#[cfg(not(target_os = "android"))]
#[derive(RustEmbed)]
#[folder = "bin"]
struct Asset;

#[allow(unused)]
pub fn get_asset_data(name: &str) -> Result<std::borrow::Cow<'static, [u8]>> {
    let asset = Asset::get(name).ok_or_else(|| anyhow::anyhow!("asset not found: {name}"))?;
    Ok(asset.data)
}

pub fn get_asset(name: &str) -> Result<Box<dyn AsRef<[u8]>>> {
    let asset = Asset::get(name).ok_or_else(|| anyhow::anyhow!("asset not found: {name}"))?;
    Ok(Box::new(asset.data))
}

pub fn list_supported_kmi() -> std::vec::Vec<std::string::String> {
    let mut list = Vec::new();
    for file in Asset::iter() {
        if let Some(kmi) = file.strip_suffix("_kernelsu.ko") {
            list.push(kmi.to_string());
        }
    }
    list
}
