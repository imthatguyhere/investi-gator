//=-- services-reporter
//=-- A Rust equivalent of the PowerShell Win32_Service reporting script

use csv::Writer;
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use wmi::{WMIConnection, Variant};

//=-- Output paths
const CSV_OUTPUT_PATH: &str = r"C:\kworking\ServicesReport.csv";
const SUSPICIOUS_OUTPUT_PATH: &str = r"C:\kworking\SuspiciousServices.txt";

//=-- Suspicious path pattern
const SUSPICIOUS_PATTERN: &str = r"AppData|Temp|ProgramData|PerfLogs|Users\\Public";

/// Represents a Windows service with relevant properties
#[derive(Debug, Serialize)]
struct ServiceInfo {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "DisplayName")]
    display_name: String,
    #[serde(rename = "State")]
    state: String,
    #[serde(rename = "StartMode")]
    start_mode: String,
    #[serde(rename = "StartName")]
    start_name: String,
    #[serde(rename = "PathName")]
    path_name: String,
    #[serde(rename = "ProcessId")]
    process_id: u32,
}

/// Simplified representation for suspicious services output
struct SuspiciousService {
    name: String,
    display_name: String,
    start_name: String,
    path_name: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    //=-- Ensure output directory exists
    ensure_output_directory()?;

    //=-- Connect to WMI (COM is initialized automatically)
    let wmi_con = WMIConnection::new()?;

    //=-- Query all services
    let services = query_services(&wmi_con)?;

    //=-- Export to CSV
    export_to_csv(&services, CSV_OUTPUT_PATH)?;
    println!("Exported {} services to {}", services.len(), CSV_OUTPUT_PATH);

    //=-- Filter and export suspicious services
    let suspicious_count = export_suspicious_services(&services, SUSPICIOUS_OUTPUT_PATH)?;
    println!("Exported {} suspicious services to {}", suspicious_count, SUSPICIOUS_OUTPUT_PATH);

    Ok(())
}

/// Ensure the output directory exists
fn ensure_output_directory() -> Result<(), Box<dyn Error>> {
    let csv_path = Path::new(CSV_OUTPUT_PATH);
    let suspicious_path = Path::new(SUSPICIOUS_OUTPUT_PATH);

    if let Some(parent) = csv_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = suspicious_path.parent() {
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

/// Query all Win32_Service instances via WMI
fn query_services(wmi_con: &WMIConnection) -> Result<Vec<ServiceInfo>, Box<dyn Error>> {
    let query = "SELECT Name, DisplayName, State, StartMode, StartName, PathName, ProcessId FROM Win32_Service";

    let results: Vec<HashMap<String, Variant>> = wmi_con.raw_query(query)?;

    let mut services = Vec::new();

    for result in results {
        let name = variant_to_string(result.get("Name"));
        let display_name = variant_to_string(result.get("DisplayName"));
        let state = variant_to_string(result.get("State"));
        let start_mode = variant_to_string(result.get("StartMode"));
        let start_name = variant_to_string(result.get("StartName"));
        let path_name = variant_to_string(result.get("PathName"));
        let process_id = variant_to_u32(result.get("ProcessId"));

        services.push(ServiceInfo {
            name,
            display_name,
            state,
            start_mode,
            start_name,
            path_name,
            process_id,
        });
    }

    Ok(services)
}

/// Export services to CSV file
fn export_to_csv(services: &[ServiceInfo], path: &str) -> Result<(), Box<dyn Error>> {
    let mut writer = Writer::from_path(path)?;

    for service in services {
        writer.serialize(service)?;
    }

    writer.flush()?;
    Ok(())
}

/// Filter and export suspicious services
fn export_suspicious_services(
    services: &[ServiceInfo],
    path: &str,
) -> Result<usize, Box<dyn Error>> {
    let suspicious_regex = Regex::new(SUSPICIOUS_PATTERN)?;

    let suspicious_services: Vec<SuspiciousService> = services
        .iter()
        .filter(|s| suspicious_regex.is_match(&s.path_name))
        .map(|s| SuspiciousService {
            name: s.name.clone(),
            display_name: s.display_name.clone(),
            start_name: s.start_name.clone(),
            path_name: s.path_name.clone(),
        })
        .collect();

    let mut file = File::create(path)?;

    for service in &suspicious_services {
        writeln!(file, "Name: {}", service.name)?;
        writeln!(file, "DisplayName: {}", service.display_name)?;
        writeln!(file, "StartName: {}", service.start_name)?;
        writeln!(file, "PathName: {}", service.path_name)?;
        writeln!(file)?;
    }

    Ok(suspicious_services.len())
}
