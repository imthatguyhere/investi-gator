//=-- logged-on-users-reporter
//=-- A Rust equivalent of the PowerShell Win32_LoggedOnUser reporting script

use csv::Writer;
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::error::Error;
use std::path::Path;
use wmi::{WMIConnection, Variant};

//=-- Output path
const CSV_OUTPUT_PATH: &str = r"C:\kworking\LoggedOnUsers.csv";

//=-- Excluded domain pattern
const EXCLUDED_DOMAIN_PATTERN: &str = r"NT AUTHORITY";

/// Represents a logged on user entry
#[derive(Debug, Serialize)]
struct LoggedOnUserInfo {
    #[serde(rename = "Caption")]
    caption: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Domain")]
    domain: String,
    #[serde(rename = "LogonId")]
    logon_id: u32,
    #[serde(rename = "LogonType")]
    logon_type: u32,
    #[serde(rename = "StartTime")]
    start_time: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    //=-- Ensure output directory exists
    ensure_output_directory()?;

    //=-- Connect to WMI (COM is initialized automatically)
    let wmi_con = WMIConnection::new()?;

    //=-- Query logged on users
    let users = query_logged_on_users(&wmi_con)?;

    //=-- Filter users (exclude NT AUTHORITY domain and service logon type 5)
    let filtered_users = filter_users(users)?;

    //=-- Export to CSV
    export_to_csv(&filtered_users, CSV_OUTPUT_PATH)?;
    println!("Exported {} logged on users to {}", filtered_users.len(), CSV_OUTPUT_PATH);

    Ok(())
}

/// Ensure the output directory exists
fn ensure_output_directory() -> Result<(), Box<dyn Error>> {
    let csv_path = Path::new(CSV_OUTPUT_PATH);
    if let Some(parent) = csv_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
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

/// Helper to extract u32 from WMI Variant
fn variant_to_u32(variant: Option<&Variant>) -> u32 {
    match variant {
        Some(Variant::UI4(n)) => *n,
        Some(Variant::I4(n)) => *n as u32,
        Some(Variant::Null) => 0,
        _ => 0,
    }
}

/// Query Win32_LoggedOnUser instances via WMI
fn query_logged_on_users(wmi_con: &WMIConnection) -> Result<Vec<LoggedOnUserInfo>, Box<dyn Error>> {
    let query = "SELECT Caption, Name, Domain, LogonId, LogonType, StartTime FROM Win32_LoggedOnUser";

    let results: Vec<HashMap<String, Variant>> = wmi_con.raw_query(query)?;

    let mut users = Vec::new();

    for result in results {
        let caption = variant_to_string(result.get("Caption"));
        let name = variant_to_string(result.get("Name"));
        let domain = variant_to_string(result.get("Domain"));
        let logon_id = variant_to_u32(result.get("LogonId"));
        let logon_type = variant_to_u32(result.get("LogonType"));

        //=-- Format start time if available
        let start_time_value = variant_to_string(result.get("StartTime"));
        let start_time = if !start_time_value.is_empty() {
            //=-- WMI datetime format is YYYYMMDDHHMMSS.milliseconds+UTCOffset
            if start_time_value.len() >= 14 {
                format!("{}-{}-{} {}:{}:{}",
                    &start_time_value[0..4],
                    &start_time_value[4..6],
                    &start_time_value[6..8],
                    &start_time_value[8..10],
                    &start_time_value[10..12],
                    &start_time_value[12..14]
                )
            } else {
                start_time_value
            }
        } else {
            String::new()
        };

        users.push(LoggedOnUserInfo {
            caption,
            name,
            domain,
            logon_id,
            logon_type,
            start_time,
        });
    }

    Ok(users)
}

/// Filter users - exclude NT AUTHORITY domain and service logon type (5)
fn filter_users(users: Vec<LoggedOnUserInfo>) -> Result<Vec<LoggedOnUserInfo>, Box<dyn Error>> {
    let excluded_domain_regex = Regex::new(EXCLUDED_DOMAIN_PATTERN)?;

    let filtered: Vec<LoggedOnUserInfo> = users
        .into_iter()
        .filter(|u| {
            //=-- Exclude NT AUTHORITY domain
            !excluded_domain_regex.is_match(&u.domain)
                //=-- Exclude service logon type (5)
                && u.logon_type != 5
        })
        .collect();

    Ok(filtered)
}

/// Export users to CSV file
fn export_to_csv(users: &[LoggedOnUserInfo], path: &str) -> Result<(), Box<dyn Error>> {
    let mut writer = Writer::from_path(path)?;

    for user in users {
        writer.serialize(user)?;
    }

    writer.flush()?;
    Ok(())
}
