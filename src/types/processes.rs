//=-- Processes module
use crate::utils::{clean_path, variant_to_string, variant_to_u32, variant_to_u64};
use csv::Writer;
use serde::Serialize;
use std::collections::HashMap;
use std::error::Error;
use wmi::{Variant as WMIVariant, WMIConnection};

#[derive(Debug, Serialize)]
pub struct ProcessInfo {
    #[serde(rename = "PID")]
    pub pid: u32,
    #[serde(rename = "ProcessName")]
    pub process_name: String,
    #[serde(rename = "Path")]
    pub path: String,
    #[serde(rename = "CommandLine")]
    pub command_line: String,
    #[serde(rename = "Owner")]
    pub owner: String,
    #[serde(rename = "StartTime")]
    pub start_time: String,
    #[serde(rename = "MemoryWorkingSet")]
    pub memory_working_set: f64,
}

pub fn gather_processes(wmi_con: &WMIConnection) -> Result<Vec<ProcessInfo>, Box<dyn Error>> {
    let query = "SELECT ProcessId, Name, ExecutablePath, CommandLine, CreationDate, WorkingSetSize FROM Win32_Process";
    let results: Vec<HashMap<String, WMIVariant>> = wmi_con.raw_query(query)?;

    let mut processes = Vec::new();

    for result in results {
        let pid = variant_to_u32(result.get("ProcessId"));
        let process_name = variant_to_string(result.get("Name"));
        let raw_path = variant_to_string(result.get("ExecutablePath"));
        let path = clean_path(&raw_path);
        let raw_cmdline = variant_to_string(result.get("CommandLine"));
        let command_line = clean_path(&raw_cmdline);

        let creation_date = variant_to_string(result.get("CreationDate"));
        let start_time = if !creation_date.is_empty() && creation_date.len() >= 14 {
            format!(
                "{}-{}-{} {}:{}:{}",
                &creation_date[0..4],
                &creation_date[4..6],
                &creation_date[6..8],
                &creation_date[8..10],
                &creation_date[10..12],
                &creation_date[12..14]
            )
        } else {
            creation_date
        };

        let working_set_bytes = variant_to_u64(result.get("WorkingSetSize"));
        let memory_working_set = (working_set_bytes as f64) / (1024.0 * 1024.0);

        processes.push(ProcessInfo {
            pid,
            process_name,
            path,
            command_line,
            owner: String::from("N/A"),
            start_time,
            memory_working_set,
        });
    }

    Ok(processes)
}

pub fn export_processes_to_csv(
    processes: &[ProcessInfo],
    path: &str,
) -> Result<(), Box<dyn Error>> {
    let mut writer = Writer::from_path(path)?;
    for proc in processes {
        writer.serialize(proc)?;
    }
    writer.flush()?;
    Ok(())
}
