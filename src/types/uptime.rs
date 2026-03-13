//=-- Uptime module
use crate::utils::{parse_wmi_datetime, variant_to_string};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::error::Error;
use wmi::{Variant as WMIVariant, WMIConnection};

pub fn calculate_uptime(
    wmi_con: &WMIConnection,
) -> Result<(Duration, DateTime<Utc>), Box<dyn Error>> {
    let query = "SELECT LastBootUpTime, LocalDateTime FROM Win32_OperatingSystem";
    let results: Vec<HashMap<String, WMIVariant>> = wmi_con.raw_query(query)?;

    if let Some(result) = results.first() {
        let last_boot_str = variant_to_string(result.get("LastBootUpTime"));
        let local_time_str = variant_to_string(result.get("LocalDateTime"));

        let last_boot = parse_wmi_datetime(&last_boot_str)
            .ok_or("Failed to parse LastBootUpTime")?;
        let local_time = parse_wmi_datetime(&local_time_str)
            .ok_or("Failed to parse LocalDateTime")?;

        let duration = local_time.signed_duration_since(last_boot);
        Ok((duration, last_boot))
    } else {
        Err("No operating system information found".into())
    }
}
