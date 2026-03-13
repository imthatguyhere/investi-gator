//=-- Types module - all data structures and their operations

pub mod tasks;
pub mod services;
pub mod startup;
pub mod processes;
pub mod users;
pub mod drivers;
pub mod uptime;

//=-- Suspicious pattern constants
pub const SUSPICIOUS_TASK_PATTERN: &str =
    r"cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe|bitsadmin\.exe|certutil\.exe";
pub const SUSPICIOUS_SERVICE_PATTERN: &str = r"AppData|Temp|ProgramData|PerfLogs|Users\\Public";
pub const SUSPICIOUS_STARTUP_PATTERN: &str =
    r"AppData\\Local\\Temp|\\Temp\\|\`\`\`|\\\\[a-zA-Z0-9]|\\\\\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}";
pub const SUSPICIOUS_DRIVER_PATTERN: &str = r"AppData|Temp|ProgramData|PerfLogs|Users\\Public";
