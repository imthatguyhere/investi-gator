//=-- scheduled-tasks-reporter
//=-- A Rust equivalent of the PowerShell scheduled tasks reporting script

use chrono::{Local, TimeZone};
use csv::Writer;
use regex::Regex;
use serde::Serialize;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::path::Path;
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

//=-- Output paths
const CSV_OUTPUT_PATH: &str = r"C:\kworking\ScheduledTasksReport.csv";
const SUSPICIOUS_OUTPUT_PATH: &str = r"C:\kworking\SuspiciousTasks.txt";

//=-- Suspicious executables pattern
const SUSPICIOUS_PATTERN: &str = r"cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe|bitsadmin\.exe|certutil\.exe";

/// Represents a scheduled task with all relevant properties
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

/// Simplified representation for suspicious tasks output
struct SuspiciousTask {
    task_name: String,
    task_path: String,
    actions: String,
    triggers: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    //=-- Ensure output directory exists
    ensure_output_directory()?;

    //=-- Initialize COM
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
    }

    //=-- Connect to Task Scheduler service
    let task_service = connect_task_service()?;

    //=-- Get root folder and enumerate all tasks
    let tasks = enumerate_all_tasks(&task_service)?;

    //=-- Export to CSV
    export_to_csv(&tasks, CSV_OUTPUT_PATH)?;
    println!("Exported {} tasks to {}", tasks.len(), CSV_OUTPUT_PATH);

    //=-- Filter and export suspicious tasks
    let suspicious_count = export_suspicious_tasks(&tasks, SUSPICIOUS_OUTPUT_PATH)?;
    println!("Exported {} suspicious tasks to {}", suspicious_count, SUSPICIOUS_OUTPUT_PATH);

    //=-- Uninitialize COM (not strictly necessary as process exits)
    unsafe {
        windows::Win32::System::Com::CoUninitialize();
    }

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

/// Helper to get BSTR as String safely
fn bstr_to_string(bstr: &BSTR) -> String {
    bstr.to_string()
}

/// Helper to get optional BSTR field
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

/// Connect to the Task Scheduler service
fn connect_task_service() -> Result<ITaskService, Box<dyn Error>> {
    unsafe {
        let task_service: ITaskService = CoCreateInstance(
            &windows::Win32::System::TaskScheduler::TaskScheduler,
            None,
            CLSCTX_ALL,
        )?;

        //=-- Connect to local machine (all parameters are optional/null)
        let null_variant = VARIANT::default();
        task_service.Connect(&null_variant, &null_variant, &null_variant, &null_variant)?;

        Ok(task_service)
    }
}

/// Enumerate all tasks from the Task Scheduler
fn enumerate_all_tasks(task_service: &ITaskService) -> Result<Vec<ScheduledTask>, Box<dyn Error>> {
    let mut tasks = Vec::new();

    unsafe {
        //=-- Get root folder
        let root_folder: ITaskFolder = task_service.GetFolder(&BSTR::from("\\"))?;

        //=-- Enumerate tasks recursively
        enumerate_tasks_in_folder(&root_folder, &mut tasks)?;
    }

    Ok(tasks)
}

/// Recursively enumerate tasks in a folder
fn enumerate_tasks_in_folder(
    folder: &ITaskFolder,
    tasks: &mut Vec<ScheduledTask>,
) -> Result<(), Box<dyn Error>> {
    unsafe {
        //=-- Get tasks in current folder
        let tasks_collection = folder.GetTasks(TASK_ENUM_HIDDEN.0 as i32)?;
        let count = tasks_collection.Count()?;

        for i in 1..=count {
            let var_index = VARIANT::from(i);
            let registered_task = tasks_collection.get_Item(&var_index)?;

            if let Ok(task_info) = extract_task_info(&registered_task) {
                tasks.push(task_info);
            }
        }

        //=-- Recursively process subfolders
        let folders_collection = folder.GetFolders(0)?;
        let folder_count = folders_collection.Count()?;

        for i in 1..=folder_count {
            let var_index = VARIANT::from(i);
            let subfolder = folders_collection.get_Item(&var_index)?;
            enumerate_tasks_in_folder(&subfolder, tasks)?;
        }
    }

    Ok(())
}

/// Extract task information from a registered task
fn extract_task_info(
    registered_task: &IRegisteredTask,
) -> Result<ScheduledTask, Box<dyn Error>> {
    unsafe {
        //=-- Basic properties
        let task_path = bstr_to_string(&registered_task.Path()?);
        let task_name = bstr_to_string(&registered_task.Name()?);

        //=-- Get state (returns TASK_STATE directly)
        let state = registered_task.State()?;
        let state_str = format!("{:?}", state);

        //=-- Get task definition
        let task_definition: ITaskDefinition = registered_task.Definition()?;

        //=-- Get registration info for author
        let registration_info: IRegistrationInfo = task_definition.RegistrationInfo()?;
        let author = get_optional_bstr(|b| registration_info.Author(b));

        //=-- Get principal (run-as user and run level)
        let principal: IPrincipal = task_definition.Principal()?;
        let run_as_user = get_optional_bstr(|b| principal.UserId(b));

        //=-- Get run level (uses out-parameter)
        let mut run_level = TASK_RUNLEVEL_TYPE::default();
        principal.RunLevel(&mut run_level)?;
        let run_level_str = format!("{:?}", run_level);

        //=-- Get actions
        let actions_collection: IActionCollection = task_definition.Actions()?;
        let actions = format_actions(&actions_collection)?;

        //=-- Get triggers
        let triggers_collection: ITriggerCollection = task_definition.Triggers()?;
        let triggers = format_triggers(&triggers_collection)?;

        //=-- Get task info (run times, results)
        let (last_run_time, last_task_result, next_run_time) = get_task_run_info(registered_task)?;

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
}

/// Format actions collection into a string
fn format_actions(
    actions: &IActionCollection,
) -> Result<String, Box<dyn Error>> {
    unsafe {
        //=-- Count uses out-parameter
        let mut count: i32 = 0;
        actions.Count(&mut count)?;
        let mut action_strings = Vec::new();

        for i in 1..=count {
            let action = actions.get_Item(i)?;

            //=-- Get action type (uses out-parameter)
            let mut action_type: TASK_ACTION_TYPE = Default::default();
            action.Type(&mut action_type)?;

            if action_type == TASK_ACTION_EXEC {
                //=-- Get the exec action
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
}

/// Format triggers collection into a string
fn format_triggers(
    triggers: &ITriggerCollection,
) -> Result<String, Box<dyn Error>> {
    unsafe {
        //=-- Count uses out-parameter
        let mut count: i32 = 0;
        triggers.Count(&mut count)?;
        let mut trigger_strings = Vec::new();

        for i in 1..=count {
            let trigger = triggers.get_Item(i)?;

            //=-- Get trigger type (uses out-parameter)
            let mut trigger_type: TASK_TRIGGER_TYPE2 = Default::default();
            trigger.Type(&mut trigger_type)?;
            let trigger_type_value = trigger_type.0;

            //=-- Map trigger types to names (similar to MSFT_Task prefix removal)
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
}

/// Get task run information (last run time, result, next run time)
fn get_task_run_info(
    registered_task: &IRegisteredTask,
) -> Result<(String, String, String), Box<dyn Error>> {
    unsafe {
        //=-- Get last run time
        let last_run_time = match registered_task.LastRunTime() {
            Ok(time) => format_system_time(time),
            Err(_) => String::new(),
        };

        //=-- Get last task result
        let last_task_result = match registered_task.LastTaskResult() {
            Ok(result) => result.to_string(),
            Err(_) => String::new(),
        };

        //=-- Get next run time
        let next_run_time = match registered_task.NextRunTime() {
            Ok(time) => format_system_time(time),
            Err(_) => String::new(),
        };

        Ok((last_run_time, last_task_result, next_run_time))
    }
}

/// Format a system time to a readable string
fn format_system_time(time: f64) -> String {
    //=-- Convert OLE Automation date to DateTime
    //=-- OLE date is days since December 30, 1899
    const OLE_EPOCH: f64 = 2415018.5; //=-- Julian day number for 1899-12-30
    const SECONDS_PER_DAY: f64 = 86400.0;

    let days_since_epoch = time - OLE_EPOCH;
    let unix_timestamp = (days_since_epoch * SECONDS_PER_DAY) as i64;

    if let Some(datetime) = Local.timestamp_opt(unix_timestamp, 0).single() {
        datetime.format("%Y-%m-%d %H:%M:%S").to_string()
    } else {
        String::new()
    }
}

/// Export tasks to CSV file
fn export_to_csv(tasks: &[ScheduledTask], path: &str) -> Result<(), Box<dyn Error>> {
    let mut writer = Writer::from_path(path)?;

    for task in tasks {
        writer.serialize(task)?;
    }

    writer.flush()?;
    Ok(())
}

/// Filter and export suspicious tasks
fn export_suspicious_tasks(
    tasks: &[ScheduledTask],
    path: &str,
) -> Result<usize, Box<dyn Error>> {
    let suspicious_regex = Regex::new(SUSPICIOUS_PATTERN)?;
    let system_regex = Regex::new(r"SYSTEM")?;

    let suspicious_tasks: Vec<SuspiciousTask> = tasks
        .iter()
        .filter(|t| {
            system_regex.is_match(&t.run_as_user)
                && suspicious_regex.is_match(&t.actions)
        })
        .map(|t| SuspiciousTask {
            task_name: t.task_name.clone(),
            task_path: t.task_path.clone(),
            actions: t.actions.clone(),
            triggers: t.triggers.clone(),
        })
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
