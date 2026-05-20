use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> ExitCode {
    let _ = try_log();
    ExitCode::from(1)
}

const PENDING_LOG_MODE: u32 = 0o600;

fn try_log() -> Option<()> {
    let raw = env::args().nth(1)?;
    let name = sanitize(&raw)?;
    let path = resolve_log_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok()?;
    }
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let ts = unix_to_rfc3339(secs);
    let line = format!("{ts}\t{name}\thelper\n");
    let mut f = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(PENDING_LOG_MODE)
        .open(&path)
        .ok()?;
    let _ = f.set_permissions(std::fs::Permissions::from_mode(PENDING_LOG_MODE));
    f.write_all(line.as_bytes()).ok()?;
    Some(())
}

fn sanitize(s: &str) -> Option<String> {
    if s.is_empty() || s.len() > 255 {
        return None;
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return None;
    }
    Some(s.to_string())
}

fn resolve_log_path() -> PathBuf {
    if let Some(v) = env::var_os("SESHAT_PENDING_LOG") {
        return PathBuf::from(v);
    }
    if let Some(v) = env::var_os("SESHAT_STATE_ROOT") {
        return PathBuf::from(v).join("pending.log");
    }
    PathBuf::from("/var/lib/seshat/pending.log")
}

fn unix_to_rfc3339(secs: u64) -> String {
    let day = (secs / 86400) as i64;
    let sod = secs % 86400;
    let h = sod / 3600;
    let m = (sod / 60) % 60;
    let s = sod % 60;
    let (y, mo, d) = civil_from_days(day);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y_adj = if m <= 2 { y + 1 } else { y };
    (y_adj as i32, m as u32, d as u32)
}
