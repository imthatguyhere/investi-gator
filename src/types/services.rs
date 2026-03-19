//=-- Services module
use crate::types::SUSPICIOUS_SERVICE_PATTERN;
use crate::utils::{variant_to_string, variant_to_u32};
use csv::Writer;
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use wmi::{Variant as WMIVariant, WMIConnection};

#[derive(Debug, Serialize)]
pub struct ServiceInfo {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "DisplayName")]
    pub display_name: String,
    #[serde(rename = "State")]
    pub state: String,
    #[serde(rename = "StartMode")]
    pub start_mode: String,
    #[serde(rename = "StartName")]
    pub start_name: String,
    #[serde(rename = "PathName")]
    pub path_name: String,
    #[serde(rename = "ProcessId")]
    pub process_id: u32,
}

pub fn gather_services(wmi_con: &WMIConnection) -> Result<Vec<ServiceInfo>, Box<dyn Error>> {
    let query = "SELECT Name, DisplayName, State, StartMode, StartName, PathName, ProcessId FROM Win32_Service";
    let results: Vec<HashMap<String, WMIVariant>> = wmi_con.raw_query(query)?;

    let mut services = Vec::new();

    for result in results {
        services.push(ServiceInfo {
            name: variant_to_string(result.get("Name")),
            display_name: variant_to_string(result.get("DisplayName")),
            state: variant_to_string(result.get("State")),
            start_mode: variant_to_string(result.get("StartMode")),
            start_name: variant_to_string(result.get("StartName")),
            path_name: variant_to_string(result.get("PathName")),
            process_id: variant_to_u32(result.get("ProcessId")),
        });
    }

    Ok(services)
}

pub fn export_services_to_csv(services: &[ServiceInfo], path: &str) -> Result<(), Box<dyn Error>> {
    let mut writer = Writer::from_path(path)?;
    for service in services {
        writer.serialize(service)?;
    }
    writer.flush()?;
    Ok(())
}

pub fn export_suspicious_services(
    services: &[ServiceInfo],
    path: &str,
) -> Result<usize, Box<dyn Error>> {
    let suspicious_regex = Regex::new(SUSPICIOUS_SERVICE_PATTERN)?;

    let suspicious_services: Vec<_> = services
        .iter()
        .filter(|s| suspicious_regex.is_match(&s.path_name))
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
