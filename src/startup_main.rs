//=-- startup-commands-reporter
//=-- A Rust equivalent of the PowerShell Win32_StartupCommand reporting script

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
const CSV_OUTPUT_PATH: &str = r"C:\kworking\StartupCommandsReport.csv";
const SUSPICIOUS_OUTPUT_PATH: &str = r"C:\kworking\SuspiciousStartupCommands.txt";

//=-- Suspicious path pattern
const SUSPICIOUS_PATTERN: &str = r"AppData\\Local\\Temp|\\Temp\\|\`\`\`|\\\\[a-zA-Z0-9]|\\\\\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}";

/// Represents a startup command entry
#[derive(Debug, Serialize)]
struct StartupCommandInfo {
    #[serde(rename = "Command")]
    command: String,
    #[serde(rename = "Description")]
    description: String,
    #[serde(rename = "Location")]
    location: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "SettingID")]
    setting_id: String,
    #[serde(rename = "User")]
    user: String,
    #[serde(rename = "UserSID")]
    user_sid: String,
}

/// Simplified representation for suspicious startup commands
struct SuspiciousStartupCommand {
    name: String,
    location: String,
    command: String,
    user: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    //=-- Ensure output directory exists
    ensure_output_directory()?;

    //=-- Connect to WMI (COM is initialized automatically)
    let wmi_con = WMIConnection::new()?;

    //=-- Query all startup commands
    let commands = query_startup_commands(&wmi_con)?;

    //=-- Export to CSV
    export_to_csv(&commands, CSV_OUTPUT_PATH)?;
    println!("Exported {} startup commands to {}", commands.len(), CSV_OUTPUT_PATH);

    //=-- Filter and export suspicious commands
    let suspicious_count = export_suspicious_commands(&commands, SUSPICIOUS_OUTPUT_PATH)?;
    println!("Exported {} suspicious startup commands to {}", suspicious_count, SUSPICIOUS_OUTPUT_PATH);

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

/// Query all Win32_StartupCommand instances via WMI
fn query_startup_commands(wmi_con: &WMIConnection) -> Result<Vec<StartupCommandInfo>, Box<dyn Error>> {
    let query = "SELECT Command, Description, Location, Name, SettingID, User, UserSID FROM Win32_StartupCommand";

    let results: Vec<HashMap<String, Variant>> = wmi_con.raw_query(query)?;

    let mut commands = Vec::new();

    for result in results {
        let command = variant_to_string(result.get("Command"));
        let description = variant_to_string(result.get("Description"));
        let location = variant_to_string(result.get("Location"));
        let name = variant_to_string(result.get("Name"));
        let setting_id = variant_to_string(result.get("SettingID"));
        let user = variant_to_string(result.get("User"));
        let user_sid = variant_to_string(result.get("UserSID"));

        commands.push(StartupCommandInfo {
            command,
            description,
            location,
            name,
            setting_id,
            user,
            user_sid,
        });
    }

    Ok(commands)
}

/// Export startup commands to CSV file
fn export_to_csv(commands: &[StartupCommandInfo], path: &str) -> Result<(), Box<dyn Error>> {
    let mut writer = Writer::from_path(path)?;

    for cmd in commands {
        writer.serialize(cmd)?;
    }

    writer.flush()?;
    Ok(())
}

/// Filter and export suspicious startup commands
fn export_suspicious_commands(
    commands: &[StartupCommandInfo],
    path: &str,
) -> Result<usize, Box<dyn Error>> {
    let suspicious_regex = Regex::new(SUSPICIOUS_PATTERN)?;

    let suspicious_commands: Vec<SuspiciousStartupCommand> = commands
        .iter()
        .filter(|c| suspicious_regex.is_match(&c.command))
        .map(|c| SuspiciousStartupCommand {
            name: c.name.clone(),
            location: c.location.clone(),
            command: c.command.clone(),
            user: c.user.clone(),
        })
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
