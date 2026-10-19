pub mod config;
pub mod daemon;
pub mod injector;
pub mod x509;

use anyhow::{Context, Result};
use log::{info, warn};

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
    let data = crate::assets::get_asset_data("libinterceptor.so")
        .context("libinterceptor.so is not embedded; build the interceptor crate and copy it to ksud/bin/aarch64/")?;
    ensure_binary(crate::defs::ATTEST_LIB_PATH, &data, false)?;
    Ok(())
}
