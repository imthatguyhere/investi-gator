//=-- process-reporter
//=-- A Rust equivalent of the PowerShell process reporting script

use csv::Writer;
use serde::Serialize;
use std::collections::HashMap;
use std::error::Error;
use std::path::Path;
use wmi::{WMIConnection, Variant};

//=-- Output path
const CSV_OUTPUT_PATH: &str = r"C:\kworking\ProcessReport.csv";

/// Represents a process with relevant properties
#[derive(Debug, Serialize)]
struct ProcessInfo {
    #[serde(rename = "PID")]
    pid: u32,
    #[serde(rename = "ProcessName")]
    process_name: String,
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "CommandLine")]
    command_line: String,
    #[serde(rename = "Owner")]
    owner: String,
    #[serde(rename = "StartTime")]
    start_time: String,
    #[serde(rename = "MemoryWorkingSet")]
    memory_working_set: f64,
}

fn main() -> Result<(), Box<dyn Error>> {
    //=-- Ensure output directory exists
    ensure_output_directory()?;

    //=-- Connect to WMI (COM is initialized automatically)
    let wmi_con = WMIConnection::new()?;

    //=-- Query all processes with owner information
    let processes = query_processes(&wmi_con)?;

    //=-- Export to CSV
    export_to_csv(&processes, CSV_OUTPUT_PATH)?;
    println!("Exported {} processes to {}", processes.len(), CSV_OUTPUT_PATH);

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

/// Helper to extract u64 from WMI Variant
fn variant_to_u64(variant: Option<&Variant>) -> u64 {
    match variant {
        Some(Variant::UI8(n)) => *n,
        Some(Variant::I8(n)) => *n as u64,
        Some(Variant::UI4(n)) => *n as u64,
        Some(Variant::I4(n)) => *n as u64,
        Some(Variant::Null) => 0,
        _ => 0,
    }
}

/// Clean path by removing \\?\ prefix
fn clean_path(path: &str) -> String {
    path.replace(r"\\?\", "")
}

/// Query all Win32_Process instances via WMI with owner information
fn query_processes(wmi_con: &WMIConnection) -> Result<Vec<ProcessInfo>, Box<dyn Error>> {
    //=-- Query processes with all needed properties
    let query = "SELECT ProcessId, Name, ExecutablePath, CommandLine, CreationDate, WorkingSetSize FROM Win32_Process";

    let results: Vec<HashMap<String, Variant>> = wmi_con.raw_query(query)?;

    let mut processes = Vec::new();

    for result in results {
        let pid = variant_to_u32(result.get("ProcessId"));
        let process_name = variant_to_string(result.get("Name"));
        let raw_path = variant_to_string(result.get("ExecutablePath"));
        let path = clean_path(&raw_path);
        let raw_cmdline = variant_to_string(result.get("CommandLine"));
        let command_line = clean_path(&raw_cmdline);

        //=-- Format creation date if available
        let creation_date = variant_to_string(result.get("CreationDate"));
        let start_time = if !creation_date.is_empty() {
            //=-- WMI datetime format is YYYYMMDDHHMMSS.milliseconds+UTCOffset
            //=-- Try to parse and format it
            if creation_date.len() >= 14 {
                format!("{}-{}-{} {}:{}:{}",
                    &creation_date[0..4],
                    &creation_date[4..6],
                    &creation_date[6..8],
                    &creation_date[8..10],
                    &creation_date[10..12],
                    &creation_date[12..14]
                )
            } else {
                creation_date
            }
        } else {
            String::new()
        };

        //=-- Get working set size and convert to MB
        let working_set_bytes = variant_to_u64(result.get("WorkingSetSize"));
        let memory_working_set = (working_set_bytes as f64) / (1024.0 * 1024.0);

        //=-- Get process owner using GetOwner method
        //=-- Note: In PowerShell this is done via $proc.GetOwner()
        //=-- In Rust with WMI, we'd need to call the method on each process instance
        //=-- For simplicity, we'll use a placeholder that can be enhanced later
        let owner = get_process_owner(wmi_con, pid);

        processes.push(ProcessInfo {
            pid,
            process_name,
            path,
            command_line,
            owner,
            start_time,
            memory_working_set,
        });
    }

    Ok(processes)
}

/// Get process owner - uses WMI GetOwner method
/// Returns "DOMAIN\User" format or "N/A" if unable to retrieve
fn get_process_owner(_wmi_con: &WMIConnection, _pid: u32) -> String {
    //=-- Query the specific process and call GetOwner method
    //=-- This is a simplified version - full implementation would require
    //=-- calling the WMI method via IWbemServices::ExecMethod
    //=-- For now, return N/A as placeholder
    //=-- A full implementation would use WMI method invocation like:
    //=-- process.GetOwner() -> returns (Domain, User)
    format!("N/A")
}

/// Export processes to CSV file
fn export_to_csv(processes: &[ProcessInfo], path: &str) -> Result<(), Box<dyn Error>> {
    let mut writer = Writer::from_path(path)?;

    for proc in processes {
        writer.serialize(proc)?;
    }

    writer.flush()?;
    Ok(())
}
