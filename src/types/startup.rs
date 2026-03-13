//=-- Startup Commands module
use crate::types::SUSPICIOUS_STARTUP_PATTERN;
use crate::utils::variant_to_string;
use csv::Writer;
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use wmi::{Variant as WMIVariant, WMIConnection};

#[derive(Debug, Serialize)]
pub struct StartupCommandInfo {
    #[serde(rename = "Command")]
    pub command: String,
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "Location")]
    pub location: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "SettingID")]
    pub setting_id: String,
    #[serde(rename = "User")]
    pub user: String,
    #[serde(rename = "UserSID")]
    pub user_sid: String,
}

pub fn gather_startup_commands(
    wmi_con: &WMIConnection,
) -> Result<Vec<StartupCommandInfo>, Box<dyn Error>> {
    let query = "SELECT Command, Description, Location, Name, SettingID, User, UserSID FROM Win32_StartupCommand";
    let results: Vec<HashMap<String, WMIVariant>> = wmi_con.raw_query(query)?;

    let mut commands = Vec::new();

    for result in results {
        commands.push(StartupCommandInfo {
            command: variant_to_string(result.get("Command")),
            description: variant_to_string(result.get("Description")),
            location: variant_to_string(result.get("Location")),
            name: variant_to_string(result.get("Name")),
            setting_id: variant_to_string(result.get("SettingID")),
            user: variant_to_string(result.get("User")),
            user_sid: variant_to_string(result.get("UserSID")),
        });
    }

    Ok(commands)
}

pub fn export_startup_to_csv(
    commands: &[StartupCommandInfo],
    path: &str,
) -> Result<(), Box<dyn Error>> {
    let mut writer = Writer::from_path(path)?;
    for cmd in commands {
        writer.serialize(cmd)?;
    }
    writer.flush()?;
    Ok(())
}

pub fn export_suspicious_startup(
    commands: &[StartupCommandInfo],
    path: &str,
) -> Result<usize, Box<dyn Error>> {
    let suspicious_regex = Regex::new(SUSPICIOUS_STARTUP_PATTERN)?;

    let suspicious_commands: Vec<_> = commands
        .iter()
        .filter(|c| suspicious_regex.is_match(&c.command))
        .collect();

    let mut file = File::create(path)?;
    for cmd in &suspicious_commands {
        writeln!(file, "Name: {}", cmd.name)?;
        writeln!(file, "Location: {}", cmd.location)?;
        writeln!(file, "Command: {}", cmd.command)?;
        writeln!(file, "User: {}", cmd.user)?;
        writeln!(file)?;
    }

    Ok(suspicious_commands.len())
}
