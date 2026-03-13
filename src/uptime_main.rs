//=-- system-uptime-reporter
//=-- A Rust equivalent of the PowerShell system uptime script

use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::error::Error;
use wmi::{WMIConnection, Variant};

fn main() -> Result<(), Box<dyn Error>> {
    //=-- Connect to WMI (COM is initialized automatically)
    let wmi_con = WMIConnection::new()?;

    //=-- Query operating system info
    let (last_boot_time, local_time) = query_os_times(&wmi_con)?;

    //=-- Calculate uptime
    let uptime = calculate_uptime(last_boot_time, local_time)?;

    //=-- Format and display results
    println!(
        "System Uptime: {} days, {} hours, {} minutes",
        uptime.num_days(),
        uptime.num_hours() % 24,
        uptime.num_minutes() % 60
    );
    println!("Last Boot Time: {}", last_boot_time.format("%Y-%m-%d %H:%M:%S"));

    Ok(())
}

/// Helper to extract string from WMI Variant
fn variant_to_string(variant: Option<&Variant>) -> String {
    match variant {
        Some(Variant::String(s)) => s.clone(),
        Some(Variant::Null) => String::new(),
        Some(other) => format!("{:?}", other),
        None => String::new(),
    }
}

/// Parse WMI datetime format to DateTime<Utc>
/// WMI format: YYYYMMDDHHMMSS.milliseconds+UTCOffset
fn parse_wmi_datetime(datetime_str: &str) -> Option<DateTime<Utc>> {
    if datetime_str.len() < 14 {
        return None;
    }

    //=-- Extract components
    let year: i32 = datetime_str[0..4].parse().ok()?;
    let month: u32 = datetime_str[4..6].parse().ok()?;
    let day: u32 = datetime_str[6..8].parse().ok()?;
    let hour: u32 = datetime_str[8..10].parse().ok()?;
    let minute: u32 = datetime_str[10..12].parse().ok()?;
    let second: u32 = datetime_str[12..14].parse().ok()?;

    //=-- Create NaiveDateTime and convert to Utc
    let naive_dt = chrono::NaiveDate::from_ymd_opt(year, month, day)?
        .and_hms_opt(hour, minute, second)?;

    Some(DateTime::from_naive_utc_and_offset(naive_dt, Utc))
}

/// Query Win32_OperatingSystem for LastBootUpTime and LocalDateTime
fn query_os_times(wmi_con: &WMIConnection) -> Result<(DateTime<Utc>, DateTime<Utc>), Box<dyn Error>> {
    let query = "SELECT LastBootUpTime, LocalDateTime FROM Win32_OperatingSystem";

    let results: Vec<HashMap<String, Variant>> = wmi_con.raw_query(query)?;

    if let Some(result) = results.first() {
        let last_boot_str = variant_to_string(result.get("LastBootUpTime"));
        let local_time_str = variant_to_string(result.get("LocalDateTime"));

        let last_boot = parse_wmi_datetime(&last_boot_str)
            .ok_or("Failed to parse LastBootUpTime")?;
        let local_time = parse_wmi_datetime(&local_time_str)
            .ok_or("Failed to parse LocalDateTime")?;

        Ok((last_boot, local_time))
    } else {
        Err("No operating system information found".into())
    }
}

/// Calculate uptime from boot time to current time
fn calculate_uptime(
    last_boot: DateTime<Utc>,
    local_time: DateTime<Utc>,
) -> Result<Duration, Box<dyn Error>> {
    let duration = local_time.signed_duration_since(last_boot);
    Ok(duration)
}
