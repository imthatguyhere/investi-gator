//=-- Kernel Drivers module
use crate::types::SUSPICIOUS_DRIVER_PATTERN;
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
pub struct DriverInfo {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "DisplayName")]
    pub display_name: String,
    #[serde(rename = "PathName")]
    pub path_name: String,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "State")]
    pub state: String,
    #[serde(rename = "StartMode")]
    pub start_mode: String,
    #[serde(rename = "AcceptStop")]
    pub accept_stop: bool,
    #[serde(rename = "ServiceType")]
    pub service_type: String,
}

pub fn gather_drivers(wmi_con: &WMIConnection) -> Result<Vec<DriverInfo>, Box<dyn Error>> {
    let query = "SELECT Name, DisplayName, PathName, Status, State, StartMode, AcceptStop, ServiceType FROM Win32_SystemDriver";
    let results: Vec<HashMap<String, WMIVariant>> = wmi_con.raw_query(query)?;

    let mut drivers = Vec::new();

    for result in results {
        let path_name = variant_to_string(result.get("PathName"));
        //=-- Clean up path - remove device path prefix if present
        let clean_path = if path_name.starts_with("\\??\\") {
            path_name[4..].to_string()
        } else {
            path_name
        };

        drivers.push(DriverInfo {
            name: variant_to_string(result.get("Name")),
            display_name: variant_to_string(result.get("DisplayName")),
            path_name: clean_path,
            status: variant_to_string(result.get("Status")),
            state: variant_to_string(result.get("State")),
            start_mode: variant_to_string(result.get("StartMode")),
            accept_stop: matches!(variant_to_u32(result.get("AcceptStop")), 1),
            service_type: variant_to_string(result.get("ServiceType")),
        });
    }

    Ok(drivers)
}

pub fn export_drivers_to_csv(drivers: &[DriverInfo], path: &str) -> Result<(), Box<dyn Error>> {
    let mut writer = Writer::from_path(path)?;
    for driver in drivers {
        writer.serialize(driver)?;
    }
    writer.flush()?;
    Ok(())
}

pub fn export_suspicious_drivers(
    drivers: &[DriverInfo],
    path: &str,
) -> Result<usize, Box<dyn Error>> {
    let suspicious_regex = Regex::new(SUSPICIOUS_DRIVER_PATTERN)?;

    let suspicious_drivers: Vec<_> = drivers
        .iter()
        .filter(|d| suspicious_regex.is_match(&d.path_name))
        .collect();

    let mut file = File::create(path)?;
    for driver in &suspicious_drivers {
        writeln!(file, "Name: {}", driver.name)?;
        writeln!(file, "DisplayName: {}", driver.display_name)?;
        writeln!(file, "PathName: {}", driver.path_name)?;
        writeln!(file, "State: {}", driver.state)?;
        writeln!(file, "StartMode: {}", driver.start_mode)?;
        writeln!(file)?;
    }

    Ok(suspicious_drivers.len())
}
