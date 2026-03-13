<p align="center">
  <img src="resources/investi-gator.webp" alt="Investi-Gator Logo" width="300" />
</p>

<h1 align="center">🐊 Investi-Gator 🐊</h1>

<p align="center">
  <em>"See you later, investigator... oh wait, it's the same thing."</em>
</p>

<p align="center">
  A single-binary Windows system reporter that lurks through your machine like a gator in the swamp, snapping up data on scheduled tasks, services, startup commands, processes, logged-on users, system uptime, and kernel drivers — then spits it all out into neat, organized files.
</p>

<p align="center">
  <strong>Made by Imthatguyhere (ITGH | Tyler)</strong>
</p>

---

## 🐊 What Is This Thing?

Investi-Gator is a lightweight, compiled Rust executable built for **Windows** that chomps through your system in seconds and produces a full snapshot of what's going on under the hood. It's designed for IT pros, incident responders, or anyone who wants a quick "lay of the swamp" without installing a bunch of tools.

One exe. One chomp. All the data.

No dependencies to install. No PowerShell scripts to juggle. Just run `investi-gator.exe` and let the gator do its thing.

---

## 🐊 The Chomp — How It Works

When you run Investi-Gator, it takes a big ol' bite out of 7 different areas of your system, one after another:

| Step | The Bite | What It Grabs |
|------|----------|---------------|
| 1/7 | **Lurking for scheduled tasks...** | Every scheduled task on the system — path, name, state, author, run-as user, run level, actions, triggers, last/next run times |
| 2/7 | **Snapping up services...** | All Windows services — name, display name, state, start mode, start name, executable path, PID |
| 3/7 | **Chomping through startup commands...** | Startup entries — command, description, registry location, name, user, and user SID |
| 4/7 | **Hunting down processes...** | Running processes — PID, name, executable path, command line, start time, memory working set (MB) |
| 5/7 | **Spying on logged-on users...** | Currently logged-on interactive users (filters out NT AUTHORITY and service logons) |
| 6/7 | **Measuring swamp uptime...** | System uptime in days/hours/minutes plus the last boot timestamp |
| 7/7 | **Creeping on kernel drivers...** | All kernel drivers — name, display name, path, status, state, start mode, service type |

Each step queries the system using the **Windows Task Scheduler COM API** (for scheduled tasks) and **WMI** (for everything else), so there's no shelling out to PowerShell or parsing messy text output. Pure native Windows API calls, gator-style.

---

## 🐊 Output — The Gator's Nest

Every time you run Investi-Gator, it creates a **timestamped subfolder** called a "chomp":

```txt
chomp--2026-3-13--1-28-05-pm/
```

The format is `chomp--YEAR-MONTH-DAY--HOUR-MINUTE-SECOND-am/pm` (12-hour clock, seconds always zero-padded). This means you can run it multiple times and never overwrite previous results. Each chomp is its own snapshot in time.

### Inside the Chomp Folder

```txt
chomp--2026-3-13--1-28-05-pm/
├── gator-log.txt              # Full console output log
├── Task--Report.csv           # All scheduled tasks
├── Task--Suspicious.txt       # Flagged suspicious tasks
├── Service--Report.csv        # All services
├── Service--Suspicious.txt    # Flagged suspicious services
├── Startup--Report.csv        # All startup commands
├── Startup--Suspicious.txt    # Flagged suspicious startup entries
├── Process--Report.csv        # All running processes
├── Users--Report.csv          # Logged-on users
├── Driver--Report.csv         # All kernel drivers
└── Driver--Suspicious.txt     # Flagged suspicious drivers
```

Files follow the `Type--Report` and `Type--Suspicious` naming convention so they sort nicely and you always know what you're looking at.

- **`--Report.csv`** files contain the **full data** for that category, serialized to CSV with headers. Open them in Excel, import them into a SIEM, grep through them — whatever floats your swamp boat.
- **`--Suspicious.txt`** files contain only the entries that matched the gator's suspicious filters (more on that below). These are human-readable text files with key fields broken out line-by-line for quick review.
- **`gator-log.txt`** is a mirror of everything printed to the console. Every line you see on screen also gets written here, so you've got a permanent record of what the gator found and any errors it hit.

---

## 🐊 Suspicious Filters — The Gator's Instincts

Not everything in the swamp is dangerous, but the gator knows what to keep an eye on. Each report type has its own regex-based filter that flags entries worth a closer look:

### Suspicious Scheduled Tasks

Flags tasks running as **SYSTEM** whose actions invoke any of these classic living-off-the-land binaries:

- `cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `bitsadmin.exe`, `certutil.exe`

These are legitimate Windows tools that attackers love to abuse. A SYSTEM-level task running `powershell.exe` with a sketchy command line? That's gator bait.

### Suspicious Services

Flags services whose **executable path** points to unusual locations:

- `AppData`, `Temp`, `ProgramData`, `PerfLogs`, `Users\Public`

Legit services live in `System32` or `Program Files`. If a service binary is hiding in someone's temp folder, the gator wants to know about it.

### Suspicious Startup Commands

Flags startup entries whose **command** matches:

- Paths containing `AppData\Local\Temp` or `\Temp\`
- Commands with backtick obfuscation (``` ` ```)
- UNC paths pointing to hostnames (`\\hostname`) or IP addresses (`\\1.2.3.4`)

Startup persistence using temp paths or network shares? Classic swamp creature behavior.

### Suspicious Drivers

Flags drivers whose **path** points to unusual locations (same pattern as services):

- `AppData`, `Temp`, `ProgramData`, `PerfLogs`, `Users\Public`

Kernel drivers should live in `System32\drivers`. Anything lurking elsewhere is suspicious — and the gator doesn't let suspicious things slide.

---

## 🐊 Where Does the Output Go? — The Gator Finds a Swamp

Investi-Gator is smart about where it drops its files. It uses a **two-tier fallback** system:

1. **Local directory first** — When you run the exe, it tests if it can write to the current working directory by creating (and immediately deleting) a tiny test file. If it can write there, that's where your `chomp--` folder goes. Nice and simple.

2. **ProgramData fallback** — If the local directory isn't writable (maybe you're running from a read-only share, or permissions are locked down), the gator falls back to:
   ```txt
   C:\ProgramData\ITGH\Investi-Gator\
   ```
   It creates that path if it doesn't exist. The `chomp--` timestamped subfolder goes inside there instead.

This means you can throw `investi-gator.exe` on a USB drive, run it from anywhere, and it'll figure out where to put the goods. No config files, no arguments needed. The gator adapts to its environment.

---

## 🐊 Building from Source — Hatching Your Own Gator

### Prerequisites

- [Rust](https://rustup.rs/) (2021 edition)
- Windows (this is a Windows-native tool — it uses Win32 APIs and WMI directly)

### Build It

```powershell
cargo build --release
```

The executable lands in `target/release/investi-gator.exe`. It comes with an embedded alligator icon because of course it does.

### Release Profile

The release build is optimized for **minimal size**:

- `opt-level = "z"` — optimize for size
- `strip = true` — strip symbols
- `lto = true` — link-time optimization
- `codegen-units = 1` — single codegen unit for maximum optimization

One small, mean, lean gator binary.

---

## 🐊 Running It — Let the Gator Loose

```powershell
.\investi-gator.exe
```

That's it. No flags. No config. No arguments. Just chomp.

You'll see output like:

```txt
========================================
   🐊 Investi-Gator System Reporter 🐊
========================================
  Made by Imthatguyhere (ITGH | Tyler)

Output directory: C:\wherever\you\ran\it\chomp--2026-3-13--1-28-05-pm

🐊 [1/7] Lurking for scheduled tasks...
  Exported 247 tasks to ...\Task--Report.csv
  Exported 3 suspicious tasks to ...\Task--Suspicious.txt

🐊 [2/7] Snapping up services...
  Exported 312 services to ...\Service--Report.csv
  Exported 1 suspicious services to ...\Service--Suspicious.txt

...

========================================
   🐊 Investi-Gator has snapped! 🐊
========================================
```

Everything you see on screen is also saved to `gator-log.txt` inside the chomp folder.

---

## 🐊 Tech Stack — What's Under the Scales

| Crate | What It Does |
| ------- | ------------- |
| `windows` | Native Win32 API bindings for COM and Task Scheduler |
| `wmi` | WMI queries for services, processes, users, uptime, startup commands, and drivers |
| `chrono` | Timestamp generation and datetime parsing |
| `csv` | CSV serialization for report files |
| `serde` | Struct serialization with custom field name mapping |
| `regex` | Pattern matching for suspicious entry detection |
| `embed-resource` | Embeds the gator icon into the executable at build time |

---

## 🐊 License

See you later, alligator. In a while, crocodile.

This project is maintained by **Imthatguyhere (ITGH | Tyler)**.
