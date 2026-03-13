//=-- Scheduled Tasks module
use crate::types::SUSPICIOUS_TASK_PATTERN;
use crate::utils::{bstr_to_string, format_system_time, get_optional_bstr};
use csv::Writer;
use regex::Regex;
use serde::Serialize;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use windows::core::{BSTR, Interface};
use windows::Win32::System::Com::CoCreateInstance;
use windows::Win32::System::TaskScheduler::{
    IActionCollection, IComHandlerAction, IExecAction, IPrincipal, IRegisteredTask,
    IRegistrationInfo, ITaskDefinition, ITaskFolder, ITaskService, ITriggerCollection,
    TASK_ACTION_COM_HANDLER, TASK_ACTION_EXEC, TASK_ENUM_HIDDEN, TASK_RUNLEVEL_TYPE,
    TASK_TRIGGER_TYPE2,
};
use windows::Win32::System::Variant::VARIANT;

#[derive(Debug, Serialize)]
pub struct ScheduledTask {
    #[serde(rename = "TaskPath")]
    pub task_path: String,
    #[serde(rename = "TaskName")]
    pub task_name: String,
    #[serde(rename = "State")]
    pub state: String,
    #[serde(rename = "Author")]
    pub author: String,
    #[serde(rename = "RunAsUser")]
    pub run_as_user: String,
    #[serde(rename = "RunLevel")]
    pub run_level: String,
    #[serde(rename = "Actions")]
    pub actions: String,
    #[serde(rename = "Triggers")]
    pub triggers: String,
    #[serde(rename = "LastRunTime")]
    pub last_run_time: String,
    #[serde(rename = "LastTaskResult")]
    pub last_task_result: String,
    #[serde(rename = "NextRunTime")]
    pub next_run_time: String,
}

pub fn gather_scheduled_tasks() -> Result<Vec<ScheduledTask>, Box<dyn Error>> {
    use windows::Win32::System::Com::CLSCTX_ALL;

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

unsafe fn extract_task_info(
    registered_task: &IRegisteredTask,
) -> Result<ScheduledTask, Box<dyn Error>> {
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
    use windows::Win32::System::TaskScheduler::TASK_ACTION_TYPE;

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

pub fn export_tasks_to_csv(tasks: &[ScheduledTask], path: &str) -> Result<(), Box<dyn Error>> {
    let mut writer = Writer::from_path(path)?;
    for task in tasks {
        writer.serialize(task)?;
    }
    writer.flush()?;
    Ok(())
}

pub fn export_suspicious_tasks(
    tasks: &[ScheduledTask],
    path: &str,
) -> Result<usize, Box<dyn Error>> {
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
