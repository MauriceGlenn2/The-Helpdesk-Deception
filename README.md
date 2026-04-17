# The-Helpdesk-Deception (WIP)

# Scenario
A routine support request should have ended with a reset and reassurance. Instead, the so-called “help” left behind a trail of anomalies that don’t add up.

What was framed as troubleshooting looked more like an audit of the system itself — probing, cataloging, leaving subtle traces in its wake. Actions chained together in suspicious sequence: first gaining a foothold, then expanding reach, then preparing to linger long after the session ended.

And just when the activity should have raised questions, a neat explanation appeared — a story planted in plain sight, designed to justify the very behavior that demanded scrutiny.

This wasn’t remote assistance. It was a misdirection.

Your mission this time is to reconstruct the timeline, connect the scattered remnants of this “support session”, and decide what was legitimate, and what was staged.

The evidence is here. The question is whether you’ll see through the story or believe it.

1. Multiple machines in the department started spawning processes originating from the download folders. This unexpected scenario occurred during the first half of October 2025. 
2. Several machines were found to share the same types of files — similar executables, naming patterns, and other traits.
3. Common keywords among the discovered files included “desk,” “help,” “support,” and “tool.”
4. Intern operated machines seem to be affected to certain degree.


# Query 1: Identify the Most Suspicious Machine
The KQL query shown in the screenshot was used to investigate suspicious file activity on intern-operated devices during October 2025. The query targeted `DeviceFileEvents` within the date range of October 1–30, 2025, filtering for devices with "intern" in the name and files matching keywords like "desk," "Help," "Support," and "tool."

---

## Key Findings

The results confirm that **gab-intern-vm** was actively involved in this suspicious activity. The device repeatedly had files created under paths like:

```
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\7-Zip\
```

Notably **7-Zip Help.lnk** across multiple days (October 6–10, 2025). All logged actions were `FileCreated` events.


<img width="2068" height="931" alt="image" src="https://github.com/user-attachments/assets/03b440a0-3aae-43fb-851c-adb9b8f7566c" />

# Query 2: Initial Execution Detection
A follow-up KQL query was executed against `DeviceFileEvents` for the same October 1–30, 2025 timeframe, this time targeting the specific file **7z2408-x64.exe** on intern-named devices. The goal was to identify what process was responsible for downloading the 7-Zip installer onto the affected machine.

---

## Key Findings

The results confirm that **gab-intern-vm** was the affected device, with **7z2408-x64.exe** being repeatedly created under:

```
C:\ProgramData\7z2408-x64.exe
```

All events were logged as `FileCreated` actions, occurring consistently across multiple days from **October 6–10, 2025**.
<img width="1830" height="933" alt="image" src="https://github.com/user-attachments/assets/915b1e74-0c95-4e56-9691-67816be013df" />

---

## Initiating Process

Every single file creation event was initiated by **powershell.exe**, with the following command line observed across all entries:

```
powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1
```

This is highly significant. The `-ExecutionPolicy Bypass` flag was used to circumvent PowerShell's built-in script execution restrictions, and the script responsible — **exfiltratedata.ps1** — was run directly from `C:\ProgramData\`, a commonly abused directory due to its low permission requirements.

---
