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

<br><br><br>
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

<br><br><br>
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
<br><br><br>
# Query 3: Staged Tamper Indicator Detection

A KQL query was executed against `DeviceFileEvents` for the October 1–30, 2025 timeframe,
targeting intern-named devices for file activity initiated by interactive processes. The goal
was to identify artifacts suggesting attempts to imply or simulate a change in security posture.

---

## Key Findings

The results confirm that **gab-intern-vm** was the affected device, under account **g4bri3lintern**.
A file named **DefenderTamperArtifact.lnk** was created at `12:34 PM UTC on October 9, 2025`,
with **explorer.exe** listed as the initiating process and **Explorer.EXE** as the command line.

<img width="2037" height="930" alt="image" src="https://github.com/user-attachments/assets/76a83d12-cd21-4588-a84f-b686d968f92f" />


---

## Initiating Process

Unlike the other events in this dataset which were driven by PowerShell, this specific file
was initiated by **explorer.exe** — meaning a user was physically navigating the filesystem
when this file was created. This is the direct indicator that the file was **manually placed**,
not dropped by a script or automated process.

The filename itself is the most significant detail. `DefenderTamperArtifact.lnk` explicitly
references Defender tampering in its name, serving as a planted signal designed to imply that
a security control was interfered with. A `.lnk` file is a Windows shortcut — it holds no
real configuration value and cannot disable Defender on its own. Its only purpose here is
to **exist as a tamper hint**, making it a textbook staged indicator.

---
<br><br><br>
# Query 4: Clipboard Access Detection

A KQL query was executed against `DeviceProcessEvents` for the October 1–30, 2025 timeframe,
targeting intern-named devices for PowerShell processes containing clipboard-reading commands.
The goal was to spot brief, opportunistic checks for readily available sensitive content.

---

## Key Findings

The results confirm that **gab-intern-vm** was the affected device, under account **g4bri3lintern**.
A single clipboard access event was recorded at `12:50 PM UTC on October 9, 2025`, initiated
by **powershell.exe**.

<img width="1649" height="589" alt="image" src="https://github.com/user-attachments/assets/f4a6497b-194b-40b3-b206-ba2c920692c4" />

---

## Initiating Process

The event was driven by **powershell.exe** with the following command observed: 
`Get-Clipboard` is a PowerShell cmdlet that reads whatever is currently stored in the system
clipboard — this can include copied passwords, tokens, URLs, or any other sensitive content
a user may have recently copied. The result was piped to `Out-Null`, meaning the output was
intentionally suppressed to avoid leaving traces in logs or console output. The `try/catch`
block wraps the command to silently swallow any errors, further reducing its visibility.

The `-NoProfile` and `-Sta` flags indicate the command was designed to run quietly and
independently, consistent with a brief, opportunistic check rather than a sustained data
collection effort.

---
<br><br><br>
# Query 5: Host Context Recon

A KQL query was executed against `DeviceProcessEvents` for the October 9, 2025 timeframe,
targeting intern-named devices for processes associated with session reconnaissance via `qwinsta`.
The goal was to identify passive discovery activity consistent with an attacker gathering user
and session context without modifying the system.

---

## Key Findings

The results confirm that **gab-intern-vm** was the affected device, under account **g4bri3lintern**.
Two session enumeration events were recorded between `12:50 and 12:51 PM UTC on October 9, 2025`,
initiated by **cmd.exe** and **query.exe** respectively.
<img width="1276" height="551" alt="image" src="https://github.com/user-attachments/assets/17fb7a33-4388-49ff-89e9-e21084f883af" />

---

## Initiating Processes
The first event was driven by **cmd.exe** with the command `qwinsta`. The second event was
driven by **query.exe** calling `qwinsta.exe` directly.
`qwinsta` is a built-in Windows binary that lists active and disconnected Remote Desktop and
terminal sessions on a host, including logged-in usernames and session states. Attackers use
this to determine who is present on the machine, whether an administrator is active, and how
closely the environment is being monitored — all without writing files or making any system
changes. The two executions occurring within 45 seconds of each other suggest the actor was
confirming results or testing alternate call paths to assess detection boundaries.
The use of native Windows binaries with no additional flags or obfuscation is consistent with
a quiet, living-off-the-land approach designed to blend into normal system activity and avoid
triggering standard alerts.

---
<br><br><br>
# Query 6: Storage Surface Mapping
A KQL query was executed against `DeviceProcessEvents` for the October 1–30, 2025 timeframe,
targeting intern-named devices for processes associated with local and network storage enumeration.
The goal was to identify lightweight checks of available storage consistent with an attacker
mapping where data lives as a preparatory step for collection and staging.

---

## Key Findings
The results confirm that **gab-intern-vm** was the affected device, under account **g4bri3lintern**.
Three storage enumeration events were recorded within seconds of each other at
`12:51 PM UTC on October 9, 2025`, all initiated by **powershell.exe** and **cmd.exe**.

<img width="1628" height="667" alt="image" src="https://github.com/user-attachments/assets/bc2a4a74-a78e-47ca-95af-f8597595886a" />


---

## Initiating Processes
The first event at `12:51:17 PM UTC` was initiated by **powershell.exe** with the command
`"cmd.exe" /c net use`. This checks for mapped network drives and active network share
connections, revealing what network storage locations are accessible from the host.

The second event at `12:51:18 PM UTC` was initiated by **powershell.exe** with the command
`"cmd.exe" /c wmic logicaldisk get name,freespace,size`. This queries all local logical
drives returning their drive letters, total size, and available free space — giving the
attacker a complete picture of local storage capacity and potential staging locations.

The third event at `12:51:18 PM UTC` was initiated by **cmd.exe** running
`wmic logicaldisk get name,freespace,size` directly, confirming the same local disk
enumeration through a slightly different call path.

Both `net use` and `wmic logicaldisk` are native Windows binaries requiring no additional
tools or downloads. Their execution within milliseconds of each other under the same account
is consistent with a scripted reconnaissance routine designed to quietly assess both local
and network storage surfaces before moving to data collection or exfiltration.

---
<br><br><br>
# Query 7: Network Reachability and Name Resolution Detection

A KQL query was executed against `DeviceProcessEvents` for the October 8–10, 2025 timeframe,
targeting intern-named devices for processes associated with network interface queries and
DNS resolution checks. The goal was to identify lightweight connectivity probes consistent
with an attacker confirming egress capability before attempting to move data off-host.

---

## Key Findings
The results confirm that **gab-intern-vm** was the affected device, under account **g4bri3lintern**.
Two network reconnaissance events were recorded within one second of each other at
`12:51 PM UTC on October 9, 2025`, both initiated by **cmd.exe** under a parent process of
**powershell.exe**.

<img width="1849" height="622" alt="image" src="https://github.com/user-attachments/assets/f84f2006-0f87-4665-a83f-c4edf9593257" />


---

## Initiating Process
The event at `12:51:31 PM UTC` was initiated by **cmd.exe** with the command `ipconfig /all`.
This is a native Windows command that returns a full dump of all network interface information
on the host, including IP addresses, subnet masks, default gateway, DNS server addresses, and
MAC addresses. Attackers use this to understand the complete network configuration of the
compromised host — identifying which interfaces are active, what DNS servers are in use, and
whether the machine has a viable path to the internet.

---
<br><br><br>
# Query 8: Runtime Application Inventory Detection
A KQL query was executed against `DeviceProcessEvents` for the October 1–20, 2025 timeframe,
targeting intern-named devices for processes associated with runtime process enumeration.
The goal was to identify attempts to inventory actively running applications on the host,
consistent with an attacker profiling the environment before taking further action.

---

## Key Findings
The results confirm that **gab-intern-vm** was the affected device, under account **g4bri3lintern**.
A single runtime inventory event was recorded at `12:51:57 PM UTC on October 9, 2025`,
initiated by **cmd.exe** under a parent process of **powershell.exe** with parent ID **8824**.

<img width="1925" height="590" alt="image" src="https://github.com/user-attachments/assets/3fc82d51-b785-4a2a-b0b2-709ffa7e390b" />

---

## Initiating Process
The event was driven by **cmd.exe** with the command `tasklist /v`. `tasklist` is a native
Windows binary that lists all currently running processes on the host. The `/v` flag enables
verbose output, returning additional details for each process including the session name,
session number, memory usage, running status, the username that owns the process, and the
window title. This gives the attacker a complete picture of everything actively running on
the machine — far more detail than a standard process list.

The parent process chain of **powershell.exe** spawning **cmd.exe** to run `tasklist /v`
is consistent with scripted execution rather than manual activity, and aligns with the
same parent process observed across all previous reconnaissance commands on this device.

---
<br><br><br>
# Query 9: Privilege Surface Check
A KQL query was executed against `DeviceProcessEvents` for the October 1–20, 2025 timeframe,
targeting intern-named devices for processes associated with privilege and group membership
enumeration. The goal was to identify attempts by the attacker to understand what privileges
were available to them — informing whether to proceed as a standard user or seek elevation.

---

## Key Findings
The results confirm that **gab-intern-vm** was the affected device, under account **g4bri3lintern**.
Multiple privilege enumeration events were recorded across two separate bursts on
`October 9, 2025` — the first at `12:52 PM UTC` and the second at `12:54 PM UTC`.
All activity was traced back to a parent process of **RuntimeBroker.exe** with parent ID **6844**.

<img width="1761" height="623" alt="image" src="https://github.com/user-attachments/assets/99c8526c-1b85-4bb0-8e1b-12c0b68324df" />


---

## Initiating Process
The very first event was recorded at `10/9/2025, 12:52:14.313 PM UTC`, initiated by
**powershell.exe** with the command `"cmd.exe" /c whoami /groups`. This was spawned by
**RuntimeBroker.exe** — a notable finding as RuntimeBroker.exe is a legitimate Windows
process not expected to spawn PowerShell or command line activity, making this a strong
indicator of process injection or abuse.

Each privilege check followed a consistent two-step pattern executed in rapid succession:

The first step used **powershell.exe** calling `"cmd.exe" /c whoami /groups` to enumerate
all group memberships assigned to the current user token — revealing what Active Directory
or local groups the attacker had access to.

The second step used **cmd.exe** running `whoami /groups` directly, followed immediately
by `whoami /priv` — enumerating all privileges assigned to the current session token such
as `SeDebugPrivilege`, `SeImpersonatePrivilege`, or other elevated rights that could be
abused for privilege escalation.

This two-step pattern repeated twice across the session, suggesting the attacker was
confirming results or running the checks from different execution contexts to ensure
accuracy.

---
<br><br><br>
# Query 10: Proof-of-Access & Egress Validation
A KQL query was executed against `DeviceNetworkEvents` for the October 9, 2025 timeframe,
targeting intern-named devices for outbound network connections initiated by processes
associated with the attacker's known parent process chain. The goal was to identify the
first outbound destination contacted as proof of egress reachability.

---

## Key Findings
The results confirm that **gab-intern-vm** was the affected device. A single outbound
connection was recorded at `12:55:05 PM UTC on October 9, 2025`, initiated by
**powershell.exe** under the parent process **RuntimeBroker.exe** — the same suspicious
process chain observed consistently throughout this investigation.

<img width="1612" height="515" alt="image" src="https://github.com/user-attachments/assets/5a1dded3-d39c-463d-b4da-291dbdaf6511" />


---

## Initiating Process
The connection was driven by **powershell.exe** with the command `"powershell.exe"`,
spawned by **RuntimeBroker.exe**. The destination contacted was `www.msftconnecttest.com`
at IP `23.218.182.182` over port `80`.

`www.msftconnecttest.com` is a legitimate Microsoft connectivity test domain that Windows
uses to verify internet access. Attackers abuse this domain intentionally because outbound
connections to it appear completely normal and are unlikely to trigger alerts — making it
an ideal destination to quietly validate that the compromised host has a working outbound
internet connection before attempting to move data off the machine.

The use of **RuntimeBroker.exe** as the parent process is again highly suspicious here.
RuntimeBroker.exe is a legitimate Windows system process that manages UWP app permissions
and should never be spawning PowerShell processes making outbound network connections.
Its repeated appearance as the parent process throughout this investigation strongly
suggests it was compromised or abused as a means of masking malicious activity within
normal system process behavior.

---
<br><br><br>
# Query 11: Bundling and Staging Artifacts
A KQL query was executed against `DeviceFileEvents` for the October 1–20, 2025 timeframe,
targeting intern-named devices for zip file creation events initiated by the attacker's
known process chain. The goal was to identify consolidation of gathered artifacts into a
single package in preparation for exfiltration.

---

## Key Findings
The results confirm that **gab-intern-vm** was the affected device, under account **g4bri3lintern**.
A single staging event was recorded at `12:58:17 PM UTC on October 9, 2025`, initiated by
**powershell.exe** under the parent process **RuntimeBroker.exe** — consistent with the
same malicious process chain observed throughout this investigation.

<img width="2249" height="470" alt="image" src="https://github.com/user-attachments/assets/ee70a569-b8f2-43f1-b318-3c851c8aea46" />


---

## Initiating Process
The event was driven by **powershell.exe** spawned by **RuntimeBroker.exe** under account
**g4bri3lintern**. The file created was `ReconArtifacts.zip` at the path
`C:\Users\Public\ReconArtifacts.zip`.

`C:\Users\Public\` is a deliberate staging choice — it is a world-readable directory
accessible to all users on the system, making it an ideal location for temporarily storing
data before exfiltration. The filename `ReconArtifacts.zip` strongly suggests the attacker
deliberately packaged the results of their reconnaissance activity — including output from
session enumeration, privilege checks, network queries, and system discovery — into a
single archive for transfer off the host.

The use of **RuntimeBroker.exe** as the parent process is again consistent with all prior
attacker activity, confirming this file creation event is part of the same attack chain
rather than legitimate system activity.

---
<br><br><br>
# Query 12: Outbound Transfer Attempt (Simulated)
A KQL query was executed against `DeviceNetworkEvents` for the October 9, 2025 timeframe,
targeting intern-named devices for outbound network connections initiated by the attacker's
known process chain via `RuntimeBroker.exe`. The goal was to identify outbound transfer
attempts or egress validation activity following the staging of `ReconArtifacts.zip`.

---

## Key Findings
The results confirm that **gab-intern-vm** was the affected device. Three outbound connections
were identified initiated by **powershell.exe** under the parent process **RuntimeBroker.exe**,
occurring between `12:55 PM and 1:00 AM UTC on October 9, 2025`. All three connections
followed the same process chain observed consistently throughout this investigation.

<img width="2345" height="729" alt="image" src="https://github.com/user-attachments/assets/4f47fc06-4d64-4385-8d05-29bb42ec81a2" />


---

## Connections Observed

The first connection at `12:55:05 PM UTC` was made to `www.msftconnecttest.com` at IP
`23.218.218.182` over port `80`. As noted in the previous query this is a Microsoft
connectivity test domain used by the attacker to confirm outbound internet access was
available from the compromised host.

The second connection at `1:00:39 PM UTC` was made to `example.com` at IP `23.192.228.80`
over port `80`. `example.com` is a reserved IANA domain commonly used for testing HTTP
connectivity — its appearance here suggests the attacker was performing a secondary
reachability check, confirming basic outbound HTTP worked before attempting a real transfer.

The third and final connection at `1:00:40 PM UTC` was made to `httpbin.org` at IP
`100.29.147.161` over port `443`. This is the most significant finding. `httpbin.org` is
a legitimate HTTP testing service that accepts and echoes back any data sent to it.
Attackers abuse this service to simulate exfiltration — sending data to a trusted domain
that bypasses domain-based detection rules while confirming that outbound data transfers
are possible from the host. The use of port `443` indicates the transfer was encrypted,
further reducing its visibility to network monitoring tools.

---
<br><br><br>
# Query 13: Scheduled Re-Execution Persistence
A KQL query was executed against `DeviceEvents` for the October 5–15, 2025 timeframe,
targeting intern-named devices for scheduled task creation and deletion events. The goal
was to identify persistence mechanisms established by the attacker to ensure continued
access or re-execution of malicious activity after the initial compromise.

---

## Key Findings
The results confirm that **gab-intern-vm** was the affected device, under account **g4bri3lintern**.
Multiple scheduled task events were recorded between October 7–9, 2025, including both
legitimate system tasks and a highly suspicious task created at `1:01:28 PM UTC on
October 9, 2025` — directly following the attacker's outbound transfer attempts.

<img width="2385" height="1005" alt="image" src="https://github.com/user-attachments/assets/d4194be0-cf93-473b-81b0-632d8cd07970" />


---

## Key Event
The most significant finding is the `ScheduledTaskCreated` event at `10/9/2025, 1:01:28 PM UTC`
under account **g4bri3lintern**. The task name was `SupportToolUpdater` with a
`LogonTrigger` set to execute starting `2025-10-09T13:01:00` with the action pointing to
**powershell.exe**. This task was designed to fire automatically every time the user
**g4bri3lintern** logged on — ensuring the attacker's PowerShell payload would re-execute
persistently without any further manual interaction.

The task name `SupportToolUpdater` is deliberately chosen to appear legitimate — mimicking
the naming convention of real Windows update or support tools to avoid suspicion during
casual review of scheduled tasks.

---
<br><br><br>
# Query 14: Planted Explanation Artifact Detection
A KQL query was executed against `DeviceFileEvents` for the October 9, 2025 timeframe,
targeting intern-named devices for file creation and modification events containing the
keyword "support" in the filename. The goal was to identify a narrative artifact planted
by the attacker to justify or explain away the suspicious activity observed throughout
this investigation.

---

## Key Findings
The results confirm that **gab-intern-vm** was the affected device, under account **g4bri3lintern**.
Four related file events were recorded between `12:58 PM and 1:03 PM UTC on October 9, 2025`,
all tied to the same cover story naming convention the attacker used consistently throughout
the attack chain.

<img width="2173" height="928" alt="image" src="https://github.com/user-attachments/assets/4b3cecaf-6f37-44ff-9276-aba89fa170c2" />


---

## Files Observed

The first file observed at `12:58:16 PM UTC` was `SupportTool.ps1` created at
`C:\Users\Public\RemoteAssistB...` — a PowerShell script using the same "Support" naming
theme seen across the scheduled task `SupportToolUpdater` and registry key
`RemoteAssistUpdater`, suggesting this was the underlying script driving the attacker's
persistent execution.

The second file `SupportChat_log.lnk` was created at `1:02:41 PM UTC` at
`C:\Users\gab-intern-vm\AppData...`. This is a Windows shortcut file automatically
generated by Windows when a file is opened — its presence is forensic proof that the
attacker physically opened the `SupportChat_log.txt` file, consistent with the hint
that "the actor opened it for some reason."

The third file `SupportChat_log.txt` was created at `1:03:11 PM UTC` at
`C:\Users\g4bri3lintern\Downloads\SupportChat_log.txt` via **Explorer.exe**. This is
the planted explanation artifact — a fake support chat log designed to make the
attacker's activity appear to be a legitimate IT support session.

The fourth and fifth events at `1:03:20 PM UTC` show `SupportChat_log.txt` being
modified twice by **Notepad.exe** — confirming the attacker opened and edited the
file directly, likely adding content to strengthen the cover story.

---
