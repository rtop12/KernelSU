use anyhow::Result;
use std::path::Path;

use crate::defs;
use crate::utils::ensure_dir_exists;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestMode {
    Auto,
    LeafHack,
    Generate,
}

#[derive(Debug, Clone)]
pub struct TargetRule {
    pub package: String,
    pub mode: AttestMode,
}

#[derive(Debug, Clone, Default)]
pub struct SecurityPatch {
    pub system: Option<String>,
    pub vendor: Option<String>,
    pub boot: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Keybox {
    pub algorithm: String,
    pub private_key_pem: String,
    pub certificate_chain_pem: Vec<String>,
}

pub struct AttestConfig {
    pub targets: Vec<TargetRule>,
    pub patch: SecurityPatch,
    pub keyboxes: Vec<Keybox>,
}

pub fn ensure_default_configs() -> Result<()> {
    ensure_dir_exists(defs::ATTEST_DIR)?;
    ensure_dir_exists(defs::ATTEST_KEY_DB_DIR)?;

    if !Path::new(defs::ATTEST_TARGET_PATH).exists() {
        std::fs::write(
            defs::ATTEST_TARGET_PATH,
            "# One package name per line.\n\
             # Suffix '?' forces leaf-hack mode, '!' forces generation mode.\n\
             #\n\
             # Example:\n\
             # com.google.android.gms\n\
             # com.example.app?\n\
             # com.example.other!\n",
        )?;
    }

    if !Path::new(defs::ATTEST_SECURITY_PATCH_PATH).exists() {
        std::fs::write(
            defs::ATTEST_SECURITY_PATCH_PATH,
            "# Security patch level override.\n\
             # Simple form: a single date applies to system/vendor/boot.\n\
             # 2024-11-01\n\
             #\n\
             # Advanced form:\n\
             # system=2024-11-01\n\
             # vendor=no\n\
             # boot=no\n",
        )?;
    }

    Ok(())
}

pub fn parse_target_txt(content: &str) -> Vec<TargetRule> {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|line| {
            let (package, mode) = if let Some(p) = line.strip_suffix('!') {
                (p, AttestMode::Generate)
            } else if let Some(p) = line.strip_suffix('?') {
                (p, AttestMode::LeafHack)
            } else {
                (line, AttestMode::Auto)
            };
            if package.is_empty() {
                None
            } else {
                Some(TargetRule {
                    package: package.to_string(),
                    mode,
                })
            }
        })
        .collect()
}

pub fn parse_security_patch(content: &str) -> SecurityPatch {
    let mut patch = SecurityPatch::default();

    let body: String = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    if body.is_empty() {
        return patch;
    }

    if !body.contains('=') {
        let v = body.trim().to_string();
        patch.system = Some(v.clone());
        patch.vendor = Some(v.clone());
        patch.boot = Some(v);
        return patch;
    }

    for line in body.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        if v.eq_ignore_ascii_case("no") {
            continue;
        }
        match k {
            "system" | "all" => patch.system = Some(v.to_string()),
            "vendor" => patch.vendor = Some(v.to_string()),
            "boot" => patch.boot = Some(v.to_string()),
            _ => {}
        }
    }
    patch
}

pub fn parse_keybox(_path: &Path) -> Result<Vec<Keybox>> {
    // Phase 2: parse <AndroidAttestation><Keybox><Key algorithm="...">
    Ok(Vec::new())
}

pub fn load() -> Result<AttestConfig> {
    let targets = std::fs::read_to_string(defs::ATTEST_TARGET_PATH)
        .map(|s| parse_target_txt(&s))
        .unwrap_or_default();
    let patch = std::fs::read_to_string(defs::ATTEST_SECURITY_PATCH_PATH)
        .map(|s| parse_security_patch(&s))
        .unwrap_or_default();
    let keyboxes = parse_keybox(Path::new(defs::ATTEST_KEYBOX_PATH)).unwrap_or_default();
    Ok(AttestConfig {
        targets,
        patch,
        keyboxes,
    })
}
