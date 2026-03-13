//=-- Investi-Gator - The Alligator System Reporter
//=-- "Snap!" - A comprehensive system reporter combining scheduled tasks,
//=-- services, startup commands, processes, logged-on users, and system uptime
//=-- Just like an alligator lurks in the waters, this tool lurks in your system!

use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc, Datelike, Timelike};
use csv::Writer;
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use windows::core::{BSTR, Interface};
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_ALL, COINIT_MULTITHREADED};
use windows::Win32::System::Variant::VARIANT;
use windows::Win32::System::TaskScheduler::{
    ITaskFolder, ITaskService, IRegisteredTask, ITaskDefinition, IRegistrationInfo,
    IPrincipal, IActionCollection, IExecAction, IComHandlerAction,
    ITriggerCollection,
    TASK_ENUM_HIDDEN, TASK_RUNLEVEL_TYPE, TASK_ACTION_TYPE, TASK_TRIGGER_TYPE2,
    TASK_ACTION_EXEC, TASK_ACTION_COM_HANDLER,
};
use wmi::{WMIConnection, Variant as WMIVariant};

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
    let csv_tasks = format!(r"{}\ScheduledTasksReport.csv", dir);
    let txt_suspicious_tasks = format!(r"{}\SuspiciousTasks.txt", dir);
    let csv_services = format!(r"{}\ServicesReport.csv", dir);
    let txt_suspicious_services = format!(r"{}\SuspiciousServices.txt", dir);
    let csv_startup = format!(r"{}\StartupCommandsReport.csv", dir);
    let txt_suspicious_startup = format!(r"{}\SuspiciousStartupCommands.txt", dir);
    let csv_processes = format!(r"{}\ProcessReport.csv", dir);
    let csv_loggedon = format!(r"{}\LoggedOnUsers.csv", dir);
    let csv_drivers = format!(r"{}\DriversReport.csv", dir);
    let txt_suspicious_drivers = format!(r"{}\SuspiciousDrivers.txt", dir);
    
    (log_path, csv_tasks, txt_suspicious_tasks, csv_services, txt_suspicious_services, 
     csv_startup, txt_suspicious_startup, csv_processes, csv_loggedon, csv_drivers, txt_suspicious_drivers)
}

/// Determine output directory: try local folder first, fallback to ProgramData
fn determine_output_directory() -> Result<String, Box<dyn Error>> {
    //=-- Try current directory first
    let current_dir = env::current_dir()?;
    let test_file = current_dir.join(".write_test");
    
    //=-- Test if we can write to current directory
    match fs::write(&test_file, "test") {
        Ok(_) => {
            //=-- Can write locally, clean up test file
            let _ = fs::remove_file(&test_file);
            return Ok(current_dir.to_string_lossy().to_string());
        }
        Err(_) => {
            //=-- Cannot write locally, use ProgramData fallback
            let program_data = env::var("ProgramData")
                .unwrap_or_else(|_| r"C:\ProgramData".to_string());
            let fallback_path = format!(r"{}\ITGH\Investi-Gator", program_data);
            fs::create_dir_all(&fallback_path)?;
            return Ok(fallback_path);
        }
    }
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

//=-- Suspicious patterns
const SUSPICIOUS_TASK_PATTERN: &str = r"cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe|bitsadmin\.exe|certutil\.exe";
const SUSPICIOUS_SERVICE_PATTERN: &str = r"AppData|Temp|ProgramData|PerfLogs|Users\\Public";
const SUSPICIOUS_STARTUP_PATTERN: &str = r"AppData\\Local\\Temp|\\Temp\\|\`\`\`|\\\\[a-zA-Z0-9]|\\\\\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}";
const SUSPICIOUS_DRIVER_PATTERN: &str = r"AppData|Temp|ProgramData|PerfLogs|Users\\Public";

//=-- ==========================================================================
//=-- DATA STRUCTURES
//=-- ==========================================================================

#[derive(Debug, Serialize)]
struct ScheduledTask {
    #[serde(rename = "TaskPath")]
    task_path: String,
    #[serde(rename = "TaskName")]
    task_name: String,
    #[serde(rename = "State")]
    state: String,
    #[serde(rename = "Author")]
    author: String,
    #[serde(rename = "RunAsUser")]
    run_as_user: String,
    #[serde(rename = "RunLevel")]
    run_level: String,
    #[serde(rename = "Actions")]
    actions: String,
    #[serde(rename = "Triggers")]
    triggers: String,
    #[serde(rename = "LastRunTime")]
    last_run_time: String,
    #[serde(rename = "LastTaskResult")]
    last_task_result: String,
    #[serde(rename = "NextRunTime")]
    next_run_time: String,
}

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

#[derive(Debug, Serialize)]
struct DriverInfo {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "DisplayName")]
    display_name: String,
    #[serde(rename = "PathName")]
    path_name: String,
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "State")]
    state: String,
    #[serde(rename = "StartMode")]
    start_mode: String,
    #[serde(rename = "AcceptStop")]
    accept_stop: bool,
    #[serde(rename = "ServiceType")]
    service_type: String,
}

//=-- ==========================================================================
//=-- MAIN
//=-- ==========================================================================

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

    //=-- Initialize COM for Task Scheduler
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
    }

    //=-- Initialize WMI connection (will be used by multiple modules)
    let wmi_con = WMIConnection::new()?;

    //=-- 1. Scheduled Tasks Report
    tee.writeln("🐊 [1/7] Lurking for scheduled tasks...");
    match gather_scheduled_tasks() {
        Ok(tasks) => {
            if let Err(e) = export_tasks_to_csv(&tasks, &csv_tasks) {
                tee.writeln(&format!("  Error exporting tasks to CSV: {}", e));
            } else {
                tee.writeln(&format!("  Exported {} tasks to {}", tasks.len(), csv_tasks));
            }
            match export_suspicious_tasks(&tasks, &txt_suspicious_tasks) {
                Ok(count) => tee.writeln(&format!("  Exported {} suspicious tasks to {}", count, txt_suspicious_tasks)),
                Err(e) => tee.writeln(&format!("  Error exporting suspicious tasks: {}", e)),
            }
        }
        Err(e) => tee.writeln(&format!("  Error gathering scheduled tasks: {}", e)),
    }

    //=-- 2. Services Report
    tee.writeln("");
    tee.writeln("🐊 [2/7] Snapping up services...");
    match gather_services(&wmi_con) {
        Ok(services) => {
            if let Err(e) = export_services_to_csv(&services, &csv_services) {
                tee.writeln(&format!("  Error exporting services to CSV: {}", e));
            } else {
                tee.writeln(&format!("  Exported {} services to {}", services.len(), csv_services));
            }
            match export_suspicious_services(&services, &txt_suspicious_services) {
                Ok(count) => tee.writeln(&format!("  Exported {} suspicious services to {}", count, txt_suspicious_services)),
                Err(e) => tee.writeln(&format!("  Error exporting suspicious services: {}", e)),
            }
        }
        Err(e) => tee.writeln(&format!("  Error gathering services: {}", e)),
    }

    //=-- 3. Startup Commands Report
    tee.writeln("");
    tee.writeln("🐊 [3/7] Chomping through startup commands...");
    match gather_startup_commands(&wmi_con) {
        Ok(commands) => {
            if let Err(e) = export_startup_to_csv(&commands, &csv_startup) {
                tee.writeln(&format!("  Error exporting startup commands to CSV: {}", e));
            } else {
                tee.writeln(&format!("  Exported {} startup commands to {}", commands.len(), csv_startup));
            }
            match export_suspicious_startup(&commands, &txt_suspicious_startup) {
                Ok(count) => tee.writeln(&format!("  Exported {} suspicious startup commands to {}", count, txt_suspicious_startup)),
                Err(e) => tee.writeln(&format!("  Error exporting suspicious startup: {}", e)),
            }
        }
        Err(e) => tee.writeln(&format!("  Error gathering startup commands: {}", e)),
    }

    //=-- 4. Processes Report
    tee.writeln("");
    tee.writeln("🐊 [4/7] Hunting down processes...");
    match gather_processes(&wmi_con) {
        Ok(processes) => {
            if let Err(e) = export_processes_to_csv(&processes, &csv_processes) {
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
    match gather_logged_on_users(&wmi_con) {
        Ok(users) => {
            let filtered = filter_users(users)?;
            if let Err(e) = export_users_to_csv(&filtered, &csv_loggedon) {
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
    match calculate_uptime(&wmi_con) {
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
    match gather_drivers(&wmi_con) {
        Ok(drivers) => {
            if let Err(e) = export_drivers_to_csv(&drivers, &csv_drivers) {
                tee.writeln(&format!("  Error exporting drivers to CSV: {}", e));
            } else {
                tee.writeln(&format!("  Exported {} drivers to {}", drivers.len(), csv_drivers));
            }
            match export_suspicious_drivers(&drivers, &txt_suspicious_drivers) {
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

//=-- ==========================================================================
//=-- UTILITY FUNCTIONS
//=-- ==========================================================================

fn ensure_output_directory(output_dir: &str) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(output_dir)?;
    Ok(())
}

fn bstr_to_string(bstr: &BSTR) -> String {
    bstr.to_string()
}

fn get_optional_bstr<F>(f: F) -> String
where
    F: FnOnce(*mut BSTR) -> windows::core::Result<()>,
{
    let mut bstr = BSTR::default();
    if f(&mut bstr).is_ok() {
        bstr.to_string()
    } else {
        String::new()
    }
}

fn variant_to_string(variant: Option<&WMIVariant>) -> String {
    match variant {
        Some(WMIVariant::String(s)) => s.clone(),
        Some(WMIVariant::Null) => String::new(),
        Some(other) => format!("{:?}", other),
        None => String::new(),
    }
}

fn variant_to_u32(variant: Option<&WMIVariant>) -> u32 {
    match variant {
        Some(WMIVariant::UI4(n)) => *n,
        Some(WMIVariant::I4(n)) => *n as u32,
        Some(WMIVariant::Null) => 0,
        _ => 0,
    }
}

fn variant_to_u64(variant: Option<&WMIVariant>) -> u64 {
    match variant {
        Some(WMIVariant::UI8(n)) => *n,
        Some(WMIVariant::I8(n)) => *n as u64,
        Some(WMIVariant::UI4(n)) => *n as u64,
        Some(WMIVariant::I4(n)) => *n as u64,
        Some(WMIVariant::Null) => 0,
        _ => 0,
    }
}

fn format_system_time(time: f64) -> String {
    const OLE_EPOCH: f64 = 2415018.5;
    const SECONDS_PER_DAY: f64 = 86400.0;

    let days_since_epoch = time - OLE_EPOCH;
    let unix_timestamp = (days_since_epoch * SECONDS_PER_DAY) as i64;

    if let Some(datetime) = Utc.timestamp_opt(unix_timestamp, 0).single() {
        datetime.format("%Y-%m-%d %H:%M:%S").to_string()
    } else {
        String::new()
    }
}

fn clean_path(path: &str) -> String {
    path.replace(r"\\?\", "")
}

fn parse_wmi_datetime(datetime_str: &str) -> Option<DateTime<Utc>> {
    if datetime_str.len() < 14 {
        return None;
    }

    let year: i32 = datetime_str[0..4].parse().ok()?;
    let month: u32 = datetime_str[4..6].parse().ok()?;
    let day: u32 = datetime_str[6..8].parse().ok()?;
    let hour: u32 = datetime_str[8..10].parse().ok()?;
    let minute: u32 = datetime_str[10..12].parse().ok()?;
    let second: u32 = datetime_str[12..14].parse().ok()?;

    let naive_dt = NaiveDate::from_ymd_opt(year, month, day)?
        .and_hms_opt(hour, minute, second)?;

    Some(DateTime::from_naive_utc_and_offset(naive_dt, Utc))
}

//=-- ==========================================================================
//=-- SCHEDULED TASKS FUNCTIONS
//=-- ==========================================================================

fn gather_scheduled_tasks() -> Result<Vec<ScheduledTask>, Box<dyn Error>> {
    let mut tasks = Vec::new();

    unsafe {
        let task_service: ITaskService = CoCreateInstance(
            &windows::Win32::System::TaskScheduler::TaskScheduler,
            None,
            CLSCTX_ALL,
        )?;

        let null_variant = VARIANT::default();
        task_service.Connect(&null_variant, &null_variant, &null_variant, &null_variant)?;

        let root_folder: ITaskFolder = task_service.GetFolder(&BSTR::from("\\"))?;
        enumerate_tasks_in_folder(&root_folder, &mut tasks)?;
    }

    Ok(tasks)
}

unsafe fn enumerate_tasks_in_folder(
    folder: &ITaskFolder,
    tasks: &mut Vec<ScheduledTask>,
) -> Result<(), Box<dyn Error>> {
    let tasks_collection = folder.GetTasks(TASK_ENUM_HIDDEN.0 as i32)?;
    let count = tasks_collection.Count()?;

    for i in 1..=count {
        let var_index = VARIANT::from(i);
        let registered_task = tasks_collection.get_Item(&var_index)?;
        if let Ok(task_info) = extract_task_info(&registered_task) {
            tasks.push(task_info);
        }
    }

    let folders_collection = folder.GetFolders(0)?;
    let folder_count = folders_collection.Count()?;

    for i in 1..=folder_count {
        let var_index = VARIANT::from(i);
        let subfolder = folders_collection.get_Item(&var_index)?;
        enumerate_tasks_in_folder(&subfolder, tasks)?;
    }

    Ok(())
}

unsafe fn extract_task_info(registered_task: &IRegisteredTask) -> Result<ScheduledTask, Box<dyn Error>> {
    let task_path = bstr_to_string(&registered_task.Path()?);
    let task_name = bstr_to_string(&registered_task.Name()?);
    let state = registered_task.State()?;
    let state_str = format!("{:?}", state);

    let task_definition: ITaskDefinition = registered_task.Definition()?;
    let registration_info: IRegistrationInfo = task_definition.RegistrationInfo()?;
    let author = get_optional_bstr(|b| registration_info.Author(b));

    let principal: IPrincipal = task_definition.Principal()?;
    let run_as_user = get_optional_bstr(|b| principal.UserId(b));

    let mut run_level = TASK_RUNLEVEL_TYPE::default();
    principal.RunLevel(&mut run_level)?;
    let run_level_str = format!("{:?}", run_level);

    let actions_collection: IActionCollection = task_definition.Actions()?;
    let actions = format_actions(&actions_collection)?;

    let triggers_collection: ITriggerCollection = task_definition.Triggers()?;
    let triggers = format_triggers(&triggers_collection)?;

    let last_run_time = match registered_task.LastRunTime() {
        Ok(time) => format_system_time(time),
        Err(_) => String::new(),
    };

    let last_task_result = match registered_task.LastTaskResult() {
        Ok(result) => result.to_string(),
        Err(_) => String::new(),
    };

    let next_run_time = match registered_task.NextRunTime() {
        Ok(time) => format_system_time(time),
        Err(_) => String::new(),
    };

    Ok(ScheduledTask {
        task_path,
        task_name,
        state: state_str,
        author,
        run_as_user,
        run_level: run_level_str,
        actions,
        triggers,
        last_run_time,
        last_task_result,
        next_run_time,
    })
}

unsafe fn format_actions(actions: &IActionCollection) -> Result<String, Box<dyn Error>> {
    let mut count: i32 = 0;
    actions.Count(&mut count)?;
    let mut action_strings = Vec::new();

    for i in 1..=count {
        let action = actions.get_Item(i)?;
        let mut action_type: TASK_ACTION_TYPE = Default::default();
        action.Type(&mut action_type)?;

        if action_type == TASK_ACTION_EXEC {
            let exec_action: IExecAction = action.cast()?;
            let path = get_optional_bstr(|b| exec_action.Path(b));
            let arguments = get_optional_bstr(|b| exec_action.Arguments(b));
            let action_str = format!("{} {}", path, arguments).trim().to_string();
            action_strings.push(action_str);
        } else if action_type == TASK_ACTION_COM_HANDLER {
            let com_action: IComHandlerAction = action.cast()?;
            let class_id = get_optional_bstr(|b| com_action.ClassId(b));
            action_strings.push(format!("COM: {}", class_id));
        } else {
            action_strings.push("Other".to_string());
        }
    }

    Ok(action_strings.join(" | "))
}

unsafe fn format_triggers(triggers: &ITriggerCollection) -> Result<String, Box<dyn Error>> {
    let mut count: i32 = 0;
    triggers.Count(&mut count)?;
    let mut trigger_strings = Vec::new();

    for i in 1..=count {
        let trigger = triggers.get_Item(i)?;
        let mut trigger_type: TASK_TRIGGER_TYPE2 = Default::default();
        trigger.Type(&mut trigger_type)?;
        let trigger_type_value = trigger_type.0;

        let trigger_name = match trigger_type_value {
            1 => "BootTrigger",
            2 => "LogonTrigger",
            3 => "IdleTrigger",
            4 => "RegistrationTrigger",
            5 => "TimeTrigger",
            6 => "EventTrigger",
            8 => "DailyTrigger",
            9 => "WeeklyTrigger",
            10 => "MonthlyTrigger",
            11 => "MonthlyDOWTrigger",
            12 => "SessionStateChangeTrigger",
            13 => "CustomTrigger",
            _ => "UnknownTrigger",
        };

        trigger_strings.push(trigger_name.to_string());
    }

    Ok(trigger_strings.join(" | "))
}

fn export_tasks_to_csv(tasks: &[ScheduledTask], path: &str) -> Result<(), Box<dyn Error>> {
    let mut writer = Writer::from_path(path)?;
    for task in tasks {
        writer.serialize(task)?;
    }
    writer.flush()?;
    Ok(())
}

fn export_suspicious_tasks(tasks: &[ScheduledTask], path: &str) -> Result<usize, Box<dyn Error>> {
    let suspicious_regex = Regex::new(SUSPICIOUS_TASK_PATTERN)?;
    let system_regex = Regex::new(r"SYSTEM")?;

    let suspicious_tasks: Vec<_> = tasks
        .iter()
        .filter(|t| system_regex.is_match(&t.run_as_user) && suspicious_regex.is_match(&t.actions))
        .collect();

    let mut file = File::create(path)?;
    for task in &suspicious_tasks {
        writeln!(file, "TaskName: {}", task.task_name)?;
        writeln!(file, "TaskPath: {}", task.task_path)?;
        writeln!(file, "Actions: {}", task.actions)?;
        writeln!(file, "Triggers: {}", task.triggers)?;
        writeln!(file)?;
    }

    Ok(suspicious_tasks.len())
}

//=-- ==========================================================================
//=-- SERVICES FUNCTIONS
//=-- ==========================================================================

fn gather_services(wmi_con: &WMIConnection) -> Result<Vec<ServiceInfo>, Box<dyn Error>> {
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

fn export_services_to_csv(services: &[ServiceInfo], path: &str) -> Result<(), Box<dyn Error>> {
    let mut writer = Writer::from_path(path)?;
    for service in services {
        writer.serialize(service)?;
    }
    writer.flush()?;
    Ok(())
}

fn export_suspicious_services(services: &[ServiceInfo], path: &str) -> Result<usize, Box<dyn Error>> {
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

//=-- ==========================================================================
//=-- STARTUP COMMANDS FUNCTIONS
//=-- ==========================================================================

fn gather_startup_commands(wmi_con: &WMIConnection) -> Result<Vec<StartupCommandInfo>, Box<dyn Error>> {
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

fn export_startup_to_csv(commands: &[StartupCommandInfo], path: &str) -> Result<(), Box<dyn Error>> {
    let mut writer = Writer::from_path(path)?;
    for cmd in commands {
        writer.serialize(cmd)?;
    }
    writer.flush()?;
    Ok(())
}

fn export_suspicious_startup(commands: &[StartupCommandInfo], path: &str) -> Result<usize, Box<dyn Error>> {
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

//=-- ==========================================================================
//=-- PROCESSES FUNCTIONS
//=-- ==========================================================================

fn gather_processes(wmi_con: &WMIConnection) -> Result<Vec<ProcessInfo>, Box<dyn Error>> {
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

fn export_processes_to_csv(processes: &[ProcessInfo], path: &str) -> Result<(), Box<dyn Error>> {
    let mut writer = Writer::from_path(path)?;
    for proc in processes {
        writer.serialize(proc)?;
    }
    writer.flush()?;
    Ok(())
}

//=-- ==========================================================================
//=-- LOGGED-ON USERS FUNCTIONS
//=-- ==========================================================================

fn gather_logged_on_users(wmi_con: &WMIConnection) -> Result<Vec<LoggedOnUserInfo>, Box<dyn Error>> {
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

fn filter_users(users: Vec<LoggedOnUserInfo>) -> Result<Vec<LoggedOnUserInfo>, Box<dyn Error>> {
    let excluded_domain_regex = Regex::new(r"NT AUTHORITY")?;

    let filtered: Vec<LoggedOnUserInfo> = users
        .into_iter()
        .filter(|u| !excluded_domain_regex.is_match(&u.domain) && u.logon_type != 5)
        .collect();

    Ok(filtered)
}

fn export_users_to_csv(users: &[LoggedOnUserInfo], path: &str) -> Result<(), Box<dyn Error>> {
    let mut writer = Writer::from_path(path)?;
    for user in users {
        writer.serialize(user)?;
    }
    writer.flush()?;
    Ok(())
}

//=-- ==========================================================================
//=-- UPTIME FUNCTIONS
//=-- ==========================================================================

fn calculate_uptime(wmi_con: &WMIConnection) -> Result<(Duration, DateTime<Utc>), Box<dyn Error>> {
    let query = "SELECT LastBootUpTime, LocalDateTime FROM Win32_OperatingSystem";
    let results: Vec<HashMap<String, WMIVariant>> = wmi_con.raw_query(query)?;

    if let Some(result) = results.first() {
        let last_boot_str = variant_to_string(result.get("LastBootUpTime"));
        let local_time_str = variant_to_string(result.get("LocalDateTime"));

        let last_boot = parse_wmi_datetime(&last_boot_str)
            .ok_or("Failed to parse LastBootUpTime")?;
        let local_time = parse_wmi_datetime(&local_time_str)
            .ok_or("Failed to parse LocalDateTime")?;

        let duration = local_time.signed_duration_since(last_boot);
        Ok((duration, last_boot))
    } else {
        Err("No operating system information found".into())
    }
}

//=-- ==========================================================================
//=-- DRIVERS FUNCTIONS
//=-- ==========================================================================

fn gather_drivers(wmi_con: &WMIConnection) -> Result<Vec<DriverInfo>, Box<dyn Error>> {
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

fn export_drivers_to_csv(drivers: &[DriverInfo], path: &str) -> Result<(), Box<dyn Error>> {
    let mut writer = Writer::from_path(path)?;
    for driver in drivers {
        writer.serialize(driver)?;
    }
    writer.flush()?;
    Ok(())
}

fn export_suspicious_drivers(drivers: &[DriverInfo], path: &str) -> Result<usize, Box<dyn Error>> {
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
