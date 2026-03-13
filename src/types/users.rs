//=-- Logged-on Users module
use crate::utils::variant_to_string;
use csv::Writer;
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::error::Error;
use wmi::{Variant as WMIVariant, WMIConnection};

#[derive(Debug, Serialize)]
pub struct LoggedOnUserInfo {
    #[serde(rename = "Caption")]
    pub caption: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Domain")]
    pub domain: String,
    #[serde(rename = "LogonId")]
    pub logon_id: u32,
    #[serde(rename = "LogonType")]
    pub logon_type: u32,
    #[serde(rename = "StartTime")]
    pub start_time: String,
}

pub fn gather_logged_on_users(
    wmi_con: &WMIConnection,
) -> Result<Vec<LoggedOnUserInfo>, Box<dyn Error>> {
    //=-- Use Win32_ComputerSystem to get the actual current user
    let query = "SELECT UserName FROM Win32_ComputerSystem";
    let results: Vec<HashMap<String, WMIVariant>> = wmi_con.raw_query(query)?;

    let mut users = Vec::new();

    if let Some(result) = results.first() {
        let username = variant_to_string(result.get("UserName"));
        if !username.is_empty() {
            //=-- Parse DOMAIN\username format
            let parts: Vec<&str> = username.split('\\').collect();
            let (domain, name) = if parts.len() == 2 {
                (parts[0].to_string(), parts[1].to_string())
            } else {
                (String::from("."), username.clone())
            };

            users.push(LoggedOnUserInfo {
                caption: username.clone(),
                name,
                domain,
                logon_id: 0,
                logon_type: 2, //=-- Interactive logon
                start_time: String::new(),
            });
        }
    }

    Ok(users)
}

pub fn filter_users(users: Vec<LoggedOnUserInfo>) -> Result<Vec<LoggedOnUserInfo>, Box<dyn Error>> {
    let excluded_domain_regex = Regex::new(r"NT AUTHORITY")?;

    let filtered: Vec<LoggedOnUserInfo> = users
        .into_iter()
        .filter(|u| !excluded_domain_regex.is_match(&u.domain) && u.logon_type != 5)
        .collect();

    Ok(filtered)
}

pub fn export_users_to_csv(users: &[LoggedOnUserInfo], path: &str) -> Result<(), Box<dyn Error>> {
    let mut writer = Writer::from_path(path)?;
    for user in users {
        writer.serialize(user)?;
    }
    writer.flush()?;
    Ok(())
}
