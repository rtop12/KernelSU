use anyhow::{bail, Context, Result};
use libc::{c_int, c_void};

const PTRACE_PEEKDATA: c_int = 2;
const PTRACE_POKEDATA: c_int = 5;
const PTRACE_ATTACH: c_int = 16;
const PTRACE_DETACH: c_int = 17;
const PTRACE_CONT: c_int = 7;

// 新增 GETREGSET / SETREGSET
const PTRACE_GETREGSET: c_int = 0x4204;
const PTRACE_SETREGSET: c_int = 0x4205;
const NT_PRSTATUS: u64 = 1;

const RTLD_NOW: u64 = 2;
const NR_MMAP: u64 = 222; // aarch64
const PROT_READ_WRITE: u64 = 3;
const MAP_PRIVATE_ANON: u64 = 0x22;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserRegs {
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}

#[repr(C)]
struct IoVec {
    iov_base: *mut c_void,
    iov_len: usize,
}

fn ptrace_call(req: c_int, pid: i32, addr: u64, data: u64) -> libc::c_long {
    unsafe { libc::ptrace(req, pid, addr as *mut c_void, data as *mut c_void) }
}

fn get_regs(pid: i32, regs: &mut UserRegs) -> Result<()> {
    let mut iov = IoVec {
        iov_base: regs as *mut _ as *mut c_void,
        iov_len: std::mem::size_of::<UserRegs>(),
    };
    if ptrace_call(PTRACE_GETREGSET, pid, NT_PRSTATUS, &mut iov as *mut _ as u64) < 0 {
        bail!("PTRACE_GETREGSET: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

fn set_regs(pid: i32, regs: &UserRegs) -> Result<()> {
    let mut iov = IoVec {
        iov_base: regs as *const _ as *mut c_void,
        iov_len: std::mem::size_of::<UserRegs>(),
    };
    if ptrace_call(PTRACE_SETREGSET, pid, NT_PRSTATUS, &mut iov as *mut _ as u64) < 0 {
        bail!("PTRACE_SETREGSET: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

fn wait_stopped(pid: i32) -> Result<()> {
    let mut status = 0;
    unsafe {
        if libc::waitpid(pid, &mut status, 0) < 0 {
            bail!("waitpid: {}", std::io::Error::last_os_error());
        }
    }
    if !libc::WIFSTOPPED(status) {
        bail!("target did not stop: status=0x{status:x}");
    }
    Ok(())
}

fn poke_data(pid: i32, addr: u64, data: u64) -> Result<()> {
    if ptrace_call(PTRACE_POKEDATA, pid, addr, data) < 0 {
        bail!(
            "PTRACE_POKEDATA @ {:x}: {}",
            addr,
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[allow(dead_code)]
fn peek_data(pid: i32, addr: u64) -> Result<u64> {
    let ret = ptrace_call(PTRACE_PEEKDATA, pid, addr, 0);
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error().unwrap_or(0) != 0 {
            bail!("PTRACE_PEEKDATA @ {:x}: {}", addr, err);
        }
    }
    Ok(ret as u64)
}

fn validate_saved(saved: &UserRegs) -> Result<()> {
    if saved.sp == 0 {
        bail!("target thread has sp=0, refusing to write trampoline");
    }
    if saved.sp > (1u64 << 56) {
        bail!("target sp={:#x} is not a user address", saved.sp);
    }
    Ok(())
}

fn remote_call(
    pid: i32,
    saved: &UserRegs,
    func: u64,
    args: [u64; 6],
) -> Result<u64> {
    let tramp = (saved.sp - 0x100) & !0xF;
    let brk: u64 = 0xD4200000; // brk #0
    poke_data(pid, tramp, brk)?;

    let mut regs = *saved;
    regs.regs[0] = args[0];
    regs.regs[1] = args[1];
    regs.regs[2] = args[2];
    regs.regs[3] = args[3];
    regs.regs[4] = args[4];
    regs.regs[5] = args[5];
    regs.regs[30] = tramp; // lr
    regs.pc = func;

    set_regs(pid, &regs)?;
    ptrace_call(PTRACE_CONT, pid, 0, 0);
    wait_stopped(pid)?;

    let mut out = UserRegs::default();
    get_regs(pid, &mut out)?;
    Ok(out.regs[0])
}

fn remote_mmap(pid: i32, saved: &UserRegs, size: u64) -> Result<u64> {
    let tramp = (saved.sp - 0x200) & !0xF;
    let svc: u64 = 0xD4000001;
    let brk: u64 = 0xD4200000;
    poke_data(pid, tramp, svc)?;
    poke_data(pid, tramp + 8, brk)?;

    let mut regs = *saved;
    regs.regs[8] = NR_MMAP;
    regs.regs[0] = 0;
    regs.regs[1] = size;
    regs.regs[2] = PROT_READ_WRITE;
    regs.regs[3] = MAP_PRIVATE_ANON;
    regs.regs[4] = u64::MAX;
    regs.regs[5] = 0;
    regs.pc = tramp;

    set_regs(pid, &regs)?;
    ptrace_call(PTRACE_CONT, pid, 0, 0);
    wait_stopped(pid)?;

    let mut out = UserRegs::default();
    get_regs(pid, &mut out)?;
    Ok(out.regs[0])
}

fn write_remote(pid: i32, dst: u64, bytes: &[u8]) -> Result<()> {
    let mut i = 0;
    while i < bytes.len() {
        let mut word = [0u8; 8];
        let take = (bytes.len() - i).min(8);
        word[..take].copy_from_slice(&bytes[i..i + take]);
        poke_data(pid, dst + i as u64, u64::from_le_bytes(word))?;
        i += 8;
    }
    Ok(())
}

fn resolve_so_base(pid: i32, soname: &str) -> Result<(u64, String)> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .with_context(|| format!("read /proc/{pid}/maps"))?;

    for line in maps.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let path = parts[5];
        if !path.contains(soname) {
            continue;
        }
        let range = parts[0];
        let start = u64::from_str_radix(range.split('-').next().unwrap_or("0"), 16).unwrap_or(0);
        let file_offset = u64::from_str_radix(parts[2], 16).unwrap_or(u64::MAX);
        if start == 0 || file_offset == u64::MAX {
            continue;
        }
        let base = start.saturating_sub(file_offset);
        return Ok((base, path.to_string()));
    }
    bail!("{soname} not mapped in pid {pid}")
}

fn resolve_libc_symbol(pid: i32, name: &str) -> Result<u64> {
    let (base, path) = resolve_so_base(pid, "libc.so")?;
    let data = std::fs::read(&path).with_context(|| format!("read {path}"))?;
    let value =
        elf_dynsym_value(&data, name)?.with_context(|| format!("{name} not found in {path}"))?;
    Ok(base + value)
}

fn elf_dynsym_value(data: &[u8], name: &str) -> Result<Option<u64>> {
    if data.len() < 64 || &data[..4] != b"\x7fELF" || data[4] != 2 {
        bail!("not a 64-bit ELF");
    }
    let shoff = u64::from_le_bytes(data[40..48].try_into().unwrap()) as usize;
    let shentsize = u16::from_le_bytes(data[58..60].try_into().unwrap()) as usize;
    let shnum = u16::from_le_bytes(data[60..62].try_into().unwrap()) as usize;

    let mut dynsym_off = 0usize;
    let mut dynsym_size = 0usize;
    let mut dynstr_off = 0usize;
    let mut dynstr_size = 0usize;

    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        if sh + 64 > data.len() {
            break;
        }
        let sh_type = u32::from_le_bytes(data[sh + 4..sh + 8].try_into().unwrap());
        if sh_type == 11 {
            dynsym_off = u64::from_le_bytes(data[sh + 24..sh + 32].try_into().unwrap()) as usize;
            dynsym_size = u64::from_le_bytes(data[sh + 32..sh + 40].try_into().unwrap()) as usize;
            let link = u32::from_le_bytes(data[sh + 40..sh + 44].try_into().unwrap()) as usize;
            let str_sh = shoff + link * shentsize;
            if str_sh + 40 > data.len() {
                continue;
            }
            dynstr_off = u64::from_le_bytes(data[str_sh + 24..str_sh + 32].try_into().unwrap()) as usize;
            dynstr_size = u64::from_le_bytes(data[str_sh + 32..str_sh + 40].try_into().unwrap()) as usize;
            break;
        }
    }
    if dynsym_size == 0 || dynstr_size == 0 {
        return Ok(None);
    }

    let count = dynsym_size / 24;
    for i in 0..count {
        let sym = dynsym_off + i * 24;
        if sym + 24 > data.len() {
            break;
        }
        let st_name = u32::from_le_bytes(data[sym..sym + 4].try_into().unwrap()) as usize;
        let st_value = u64::from_le_bytes(data[sym + 8..sym + 16].try_into().unwrap());
        if st_name >= dynstr_size {
            continue;
        }
        let s = dynstr_off + st_name;
        if s >= data.len() {
            continue;
        }
        let end = data[s..(dynstr_off + dynstr_size).min(data.len())]
            .iter()
            .position(|b| *b == 0)
            .map(|p| s + p)
            .unwrap_or(s);
        let sym_name = std::str::from_utf8(&data[s..end]).unwrap_or("");
        if sym_name == name {
            return Ok(Some(st_value));
        }
    }
    Ok(None)
}

pub fn find_pid_by_comm(comm: &str) -> Option<i32> {
    for entry in std::fs::read_dir("/proc").ok()? {
        let entry = entry.ok()?;
        let name = entry.file_name();
        let Some(pid) = name.to_str()?.parse::<i32>().ok() else {
            continue;
        };
        if let Ok(c) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
            if c.trim() == comm {
                return Some(pid);
            }
        }
    }
    None
}

pub fn is_already_injected(pid: i32, so_name: &str) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .map(|s| s.lines().any(|l| l.contains(so_name)))
        .unwrap_or(false)
}

pub fn inject(pid: i32, so_path: &str) -> Result<()> {
    unsafe {
        if libc::ptrace(PTRACE_ATTACH, pid, 0, 0) < 0 {
            bail!("PTRACE_ATTACH: {}", std::io::Error::last_os_error());
        }
    }
    wait_stopped(pid).context("wait after attach")?;

    let result = inject_inner(pid, so_path);

    unsafe {
        libc::ptrace(PTRACE_DETACH, pid, 0, 0);
    }
    result
}

fn inject_inner(pid: i32, so_path: &str) -> Result<()> {
    let mut saved = UserRegs::default();
    get_regs(pid, &mut saved)?;
    validate_saved(&saved)?;

    let remote_mem = remote_mmap(pid, &saved, 0x1000)?;
    if remote_mem == 0 || (remote_mem as i64) < 0 {
        bail!("remote mmap failed (returned {:#x})", remote_mem);
    }

    let mut buf = Vec::with_capacity(so_path.len() + 1);
    buf.extend_from_slice(so_path.as_bytes());
    buf.push(0);
    write_remote(pid, remote_mem, &buf)?;

    let dlopen = resolve_libc_symbol(pid, "__libc_dlopen_mode")?;
    let ret = remote_call(pid, &saved, dlopen, [remote_mem, RTLD_NOW, 0, 0, 0, 0])?;
    if ret == 0 {
        bail!("__libc_dlopen_mode returned NULL");
    }
    log::info!("attest: injected {so_path} into pid {pid}, handle={ret:#x}");
    Ok(())
}
