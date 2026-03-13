//=-- Investi-Gator - The Alligator System Reporter
//=-- "Snap!" - A comprehensive system reporter combining scheduled tasks,
//=-- services, startup commands, processes, logged-on users, and system uptime
//=-- Just like an alligator lurks in the waters, this tool lurks in your system!

use chrono::{Datelike, Timelike};
use std::error::Error;
use std::fs::File;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
use wmi::WMIConnection;

mod types;
mod utils;

use types::{
    drivers, processes, services, startup, tasks, uptime, users,
};
use utils::{determine_output_directory, ensure_output_directory};

//=-- Output paths will be set dynamically at runtime
static OUTPUT_DIR: Mutex<Option<String>> = Mutex::new(None);

fn get_output_dir() -> String {
    let guard = OUTPUT_DIR.lock().unwrap();
    guard.as_ref().expect("Output directory not initialized").clone()
}

fn set_output_dir(dir: String) {
    let mut guard = OUTPUT_DIR.lock().unwrap();
    *guard = Some(dir);
}

fn get_output_paths() -> (String, String, String, String, String, String, String, String, String, String, String) {
    let dir = get_output_dir();
    let log_path = format!(r"{}\gator-log.txt", dir);
    let csv_tasks = format!(r"{}\Task--Report.csv", dir);
    let txt_suspicious_tasks = format!(r"{}\Task--Suspicious.txt", dir);
    let csv_services = format!(r"{}\Service--Report.csv", dir);
    let txt_suspicious_services = format!(r"{}\Service--Suspicious.txt", dir);
    let csv_startup = format!(r"{}\Startup--Report.csv", dir);
    let txt_suspicious_startup = format!(r"{}\Startup--Suspicious.txt", dir);
    let csv_processes = format!(r"{}\Process--Report.csv", dir);
    let csv_loggedon = format!(r"{}\Users--Report.csv", dir);
    let csv_drivers = format!(r"{}\Driver--Report.csv", dir);
    let txt_suspicious_drivers = format!(r"{}\Driver--Suspicious.txt", dir);
    
    (log_path, csv_tasks, txt_suspicious_tasks, csv_services, txt_suspicious_services, 
     csv_startup, txt_suspicious_startup, csv_processes, csv_loggedon, csv_drivers, txt_suspicious_drivers)
}

//=-- Tee writer that writes to both stdout and a log file
struct TeeWriter {
    log_file: Arc<Mutex<File>>,
}

impl TeeWriter {
    fn new(log_path: &str) -> io::Result<Self> {
        let file = File::create(log_path)?;
        Ok(TeeWriter {
            log_file: Arc::new(Mutex::new(file)),
        })
    }
    
    fn writeln(&self, s: &str) {
        println!("{}", s);
        if let Ok(mut file) = self.log_file.lock() {
            let _ = writeln!(file, "{}", s);
        }
    }
}

impl Clone for TeeWriter {
    fn clone(&self) -> Self {
        TeeWriter {
            log_file: Arc::clone(&self.log_file),
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    //=-- Determine base output directory (local or ProgramData)
    let base_dir = determine_output_directory()?;
    
    //=-- Create timestamped subfolder: chomp--YYYY-MM-DD--H-MM-SS-am/pm
    let timestamp = chrono::Local::now().naive_local();
    let hour = timestamp.hour();
    let hour_12 = if hour == 0 { 12 } else if hour > 12 { hour - 12 } else { hour };
    let am_pm = if hour >= 12 { "pm" } else { "am" };
    let subfolder = format!(
        "chomp--{}-{}-{}--{}-{}-{:02}-{}",
        timestamp.year(),
        timestamp.month(),
        timestamp.day(),
        hour_12,
        timestamp.minute(),
        timestamp.second(),
        am_pm
    );
    let output_dir = format!(r"{}\{}", base_dir, subfolder);
    
    set_output_dir(output_dir.clone());
    
    //=-- Ensure output directory exists BEFORE creating TeeWriter
    ensure_output_directory(&output_dir)?;
    
    //=-- Get all output paths
    let (log_path, csv_tasks, txt_suspicious_tasks, csv_services, txt_suspicious_services,
         csv_startup, txt_suspicious_startup, csv_processes, csv_loggedon, csv_drivers, txt_suspicious_drivers) = get_output_paths();
    
    //=-- Create TeeWriter for logging to both console and file
    let tee = TeeWriter::new(&log_path)?;

    tee.writeln("========================================");
    tee.writeln("   🐊 Investi-Gator System Reporter 🐊");
    tee.writeln("========================================");
    tee.writeln("  Made by Imthatguyhere (ITGH | Tyler)");
    tee.writeln("");
    tee.writeln(&format!("Output directory: {}", output_dir));
    tee.writeln("");
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
    }

    //=-- Initialize WMI connection (will be used by multiple modules)
    let wmi_con = WMIConnection::new()?;

    //=-- 1. Scheduled Tasks Report
    tee.writeln("🐊 [1/7] Lurking for scheduled tasks...");
    match tasks::gather_scheduled_tasks() {
        Ok(tasks) => {
            if let Err(e) = tasks::export_tasks_to_csv(&tasks, &csv_tasks) {
                tee.writeln(&format!("  Error exporting tasks to CSV: {}", e));
            } else {
                tee.writeln(&format!("  Exported {} tasks to {}", tasks.len(), csv_tasks));
            }
            match tasks::export_suspicious_tasks(&tasks, &txt_suspicious_tasks) {
                Ok(count) => tee.writeln(&format!("  Exported {} suspicious tasks to {}", count, txt_suspicious_tasks)),
                Err(e) => tee.writeln(&format!("  Error exporting suspicious tasks: {}", e)),
            }
        }
        Err(e) => tee.writeln(&format!("  Error gathering scheduled tasks: {}", e)),
    }

    //=-- 2. Services Report
    tee.writeln("");
    tee.writeln("🐊 [2/7] Snapping up services...");
    match services::gather_services(&wmi_con) {
        Ok(services) => {
            if let Err(e) = services::export_services_to_csv(&services, &csv_services) {
                tee.writeln(&format!("  Error exporting services to CSV: {}", e));
            } else {
                tee.writeln(&format!("  Exported {} services to {}", services.len(), csv_services));
            }
            match services::export_suspicious_services(&services, &txt_suspicious_services) {
                Ok(count) => tee.writeln(&format!("  Exported {} suspicious services to {}", count, txt_suspicious_services)),
                Err(e) => tee.writeln(&format!("  Error exporting suspicious services: {}", e)),
            }
        }
        Err(e) => tee.writeln(&format!("  Error gathering services: {}", e)),
    }

    //=-- 3. Startup Commands Report
    tee.writeln("");
    tee.writeln("🐊 [3/7] Chomping through startup commands...");
    match startup::gather_startup_commands(&wmi_con) {
        Ok(commands) => {
            if let Err(e) = startup::export_startup_to_csv(&commands, &csv_startup) {
                tee.writeln(&format!("  Error exporting startup commands to CSV: {}", e));
            } else {
                tee.writeln(&format!("  Exported {} startup commands to {}", commands.len(), csv_startup));
            }
            match startup::export_suspicious_startup(&commands, &txt_suspicious_startup) {
                Ok(count) => tee.writeln(&format!("  Exported {} suspicious startup commands to {}", count, txt_suspicious_startup)),
                Err(e) => tee.writeln(&format!("  Error exporting suspicious startup: {}", e)),
            }
        }
        Err(e) => tee.writeln(&format!("  Error gathering startup commands: {}", e)),
    }

    //=-- 4. Processes Report
    tee.writeln("");
    tee.writeln("🐊 [4/7] Hunting down processes...");
    match processes::gather_processes(&wmi_con) {
        Ok(processes) => {
            if let Err(e) = processes::export_processes_to_csv(&processes, &csv_processes) {
                tee.writeln(&format!("  Error exporting processes to CSV: {}", e));
            } else {
                tee.writeln(&format!("  Exported {} processes to {}", processes.len(), csv_processes));
            }
        }
        Err(e) => tee.writeln(&format!("  Error gathering processes: {}", e)),
    }

    //=-- 5. Logged-On Users Report
    tee.writeln("");
    tee.writeln("🐊 [5/7] Spying on logged-on users...");
    match users::gather_logged_on_users(&wmi_con) {
        Ok(users) => {
            let filtered = users::filter_users(users)?;
            if let Err(e) = users::export_users_to_csv(&filtered, &csv_loggedon) {
                tee.writeln(&format!("  Error exporting users to CSV: {}", e));
            } else {
                tee.writeln(&format!("  Exported {} users to {}", filtered.len(), csv_loggedon));
            }
        }
        Err(e) => tee.writeln(&format!("  Error gathering logged-on users: {}", e)),
    }

    //=-- 6. System Uptime
    tee.writeln("");
    tee.writeln("🐊 [6/7] Measuring swamp uptime...");
    match uptime::calculate_uptime(&wmi_con) {
        Ok((uptime, boot_time)) => {
            tee.writeln(&format!(
                "  System Uptime: {} days, {} hours, {} minutes",
                uptime.num_days(),
                uptime.num_hours() % 24,
                uptime.num_minutes() % 60
            ));
            tee.writeln(&format!("  Last Boot Time: {}", boot_time.format("%Y-%m-%d %H:%M:%S")));
        }
        Err(e) => tee.writeln(&format!("  Error calculating uptime: {}", e)),
    }

    //=-- 7. Drivers Report
    tee.writeln("");
    tee.writeln("🐊 [7/7] Creeping on kernel drivers...");
    match drivers::gather_drivers(&wmi_con) {
        Ok(drivers) => {
            if let Err(e) = drivers::export_drivers_to_csv(&drivers, &csv_drivers) {
                tee.writeln(&format!("  Error exporting drivers to CSV: {}", e));
            } else {
                tee.writeln(&format!("  Exported {} drivers to {}", drivers.len(), csv_drivers));
            }
            match drivers::export_suspicious_drivers(&drivers, &txt_suspicious_drivers) {
                Ok(count) => tee.writeln(&format!("  Exported {} suspicious drivers to {}", count, txt_suspicious_drivers)),
                Err(e) => tee.writeln(&format!("  Error exporting suspicious drivers: {}", e)),
            }
        }
        Err(e) => tee.writeln(&format!("  Error gathering drivers: {}", e)),
    }

    //=-- Cleanup - WMI connection is dropped here automatically
    //=-- Don't call CoUninitialize() manually as it causes segfault when WMIConnection still exists
    //=-- The OS will clean up COM when the process exits

    tee.writeln("");
    tee.writeln("========================================");
    tee.writeln("   🐊 Investi-Gator has snapped! 🐊");
    tee.writeln("========================================");

    Ok(())
}
