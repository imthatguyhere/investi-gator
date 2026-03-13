//=-- Shared utilities for Investi-Gator
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use std::error::Error;
use std::fs;
use windows::core::BSTR;
use wmi::Variant as WMIVariant;

/// Determine output directory: try local folder first, fallback to ProgramData
pub fn determine_output_directory() -> Result<String, Box<dyn Error>> {
    use std::env;

    //=-- Try current directory first
    let current_dir = env::current_dir()?;
    let test_file = current_dir.join(".write_test");

    //=-- Test if we can write to current directory
    match fs::write(&test_file, "test") {
        Ok(_) => {
            //=-- Can write locally, clean up test file
            let _ = fs::remove_file(&test_file);
            Ok(current_dir.to_string_lossy().to_string())
        }
        Err(_) => {
            //=-- Cannot write locally, use ProgramData fallback
            let program_data = env::var("ProgramData")
                .unwrap_or_else(|_| r"C:\ProgramData".to_string());
            let fallback_path = format!(r"{}\ITGH\Investi-Gator", program_data);
            fs::create_dir_all(&fallback_path)?;
            Ok(fallback_path)
        }
    }
}

/// Ensure output directory exists
pub fn ensure_output_directory(output_dir: &str) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(output_dir)?;
    Ok(())
}

/// Clean up path by removing \\?\ prefix
pub fn clean_path(path: &str) -> String {
    path.replace(r"\\?\", "")
}

/// Convert BSTR to String
pub fn bstr_to_string(bstr: &BSTR) -> String {
    bstr.to_string()
}

/// Get optional BSTR value
pub fn get_optional_bstr<F>(f: F) -> String
where
    F: FnOnce(*mut BSTR) -> windows::core::Result<()>,
{
    let mut bstr = BSTR::default();
    if f(&mut bstr).is_ok() {
        bstr.to_string()
    } else {
        String::new()
    }
}

/// Format system time from OLE format to readable string
pub fn format_system_time(time: f64) -> String {
    const OLE_EPOCH: f64 = 2415018.5;
    const SECONDS_PER_DAY: f64 = 86400.0;

    let days_since_epoch = time - OLE_EPOCH;
    let unix_timestamp = (days_since_epoch * SECONDS_PER_DAY) as i64;

    if let Some(datetime) = Utc.timestamp_opt(unix_timestamp, 0).single() {
        datetime.format("%Y-%m-%d %H:%M:%S").to_string()
    } else {
        String::new()
    }
}

/// Convert WMI variant to String
pub fn variant_to_string(variant: Option<&WMIVariant>) -> String {
    match variant {
        Some(WMIVariant::String(s)) => s.clone(),
        Some(WMIVariant::Null) => String::new(),
        Some(other) => format!("{:?}", other),
        None => String::new(),
    }
}

/// Convert WMI variant to u32
pub fn variant_to_u32(variant: Option<&WMIVariant>) -> u32 {
    match variant {
        Some(WMIVariant::UI4(n)) => *n,
        Some(WMIVariant::I4(n)) => *n as u32,
        Some(WMIVariant::Null) => 0,
        _ => 0,
    }
}

/// Convert WMI variant to u64
pub fn variant_to_u64(variant: Option<&WMIVariant>) -> u64 {
    match variant {
        Some(WMIVariant::UI8(n)) => *n,
        Some(WMIVariant::I8(n)) => *n as u64,
        Some(WMIVariant::UI4(n)) => *n as u64,
        Some(WMIVariant::I4(n)) => *n as u64,
        Some(WMIVariant::Null) => 0,
        _ => 0,
    }
}

/// Parse WMI datetime string to DateTime<Utc>
pub fn parse_wmi_datetime(datetime_str: &str) -> Option<DateTime<Utc>> {
    if datetime_str.len() < 14 {
        return None;
    }

    let year: i32 = datetime_str[0..4].parse().ok()?;
    let month: u32 = datetime_str[4..6].parse().ok()?;
    let day: u32 = datetime_str[6..8].parse().ok()?;
    let hour: u32 = datetime_str[8..10].parse().ok()?;
    let minute: u32 = datetime_str[10..12].parse().ok()?;
    let second: u32 = datetime_str[12..14].parse().ok()?;

    let naive_dt = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, minute, second)?;

    Some(DateTime::from_naive_utc_and_offset(naive_dt, Utc))
}
