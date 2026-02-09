# Detecting Remcos registry values with Sysmon

[Remcos variants](https://shadowshell.io/remcos) sets different registry values for persistence. We can detect the creation of these values by watching the `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` registry key.

We can use the following simple [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) config for this purpose:

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

Register and start `sysmon`:

```
> sysmon64.exe -accepteula -i sysmonconfig.xml
```

Add a registry value:

```
> Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Rmc" -Value "remcos.exe"
```

Check the `sysmon` logs:

```
> Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=12 or EventID=13 or EventID=14]]" -MaxEvents 5 | Format-List
TimeCreated  : 2/9/2026 9:10:05 PM
ProviderName : Microsoft-Windows-Sysmon
Id           : 13
Message      : Registry value set:
               RuleName: -
               EventType: SetValue
               UtcTime: 2026-02-09 20:10:05.546
               ProcessGuid: {d2b54b40-f1e3-6989-430c-0c0000003800}
               ProcessId: 47960
               Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
               TargetObject: HKU\S-1-5-21-2185766489-2577382833-530242202-2112\Software\Microsoft\Windows\CurrentVersion\Run\Rmc
               Details: remcos.exe
               User: HIGHTEC\agemes
```

Then, we can filter the logs via Sigma. The record types and fields can be found [here](https://github.com/trustedsec/SysmonCommunityGuide/blob/master/Build/Sysmon.md). Alternatively, the config schema can be printed via `sysmon64 -s > sysmon_schema.xml`. In this case, we filter for the `TargetObject` and `Details` fields.

```yml
title: Remcos RAT registry persistence
logsource:
  category: registry_set
  product: windows
detection:
  selection_path:
    TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Run\'
  selection_remcos:
    Details|contains:
      - "remcos"
  condition: selection_path and selection_remcos
```

The Sigma rule can be verified via [Chainsaw](https://github.com/WithSecureLabs/chainsaw).

```
> wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\Users\agemes\tmp\sysmon.evtx
> chainsaw.exe hunt C:\Users\agemes\tmp\sysmon.evtx -s remcos.yml --mapping C:\Users\agemes\git-repos\chainsaw\mappings\sigma-event-logs-all.yml

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Loading detection rules from: remcos.yml
[+] Loaded 1 detection rules
[+] Loading forensic artefacts from: C:\Users\agemes\tmp\sysmon.evtx (extensions: .evtx, .evt)
[+] Loaded 1 forensic artefacts (62.1 MiB)
[+] Current Artifact: C:\Users\agemes\tmp\sysmon.evtx
[+] Hunting [========================================] 1/1 - [00:00:01]
[+] Group: Sigma
┌─────────────────────┬───────────────────────────────────┬───────┬──────────────────────────┬──────────┬───────────┬───────────────────────┬────────────────────────────────┐
│      timestamp      │            detections             │ count │  Event.System.Provider   │ Event ID │ Record ID │       Computer        │           Event Data           │
├─────────────────────┼───────────────────────────────────┼───────┼──────────────────────────┼──────────┼───────────┼───────────────────────┼────────────────────────────────┤
│ 2026-02-09 20:06:30 │ + Remcos RAT registry persistence │ 1     │ Microsoft-Windows-Sysmon │ 13       │ 95515     │ HTNB-3006.hightec.htc │ Image: C:\Windows\System32\Win │
│                     │                                   │       │                          │          │           │                       │ dowsPowerShell\v1.0\powershell │
│                     │                                   │       │                          │          │           │                       │ .exe                           │
│                     │                                   │       │                          │          │           │                       │ TargetObject: HKU\S-1-5-21-218 │
│                     │                                   │       │                          │          │           │                       │ 5766489-2577382833-530242202-2 │
│                     │                                   │       │                          │          │           │                       │ 112\Software\Microsoft\Windows │
│                     │                                   │       │                          │          │           │                       │ \CurrentVersion\Run\Rmc        │
│                     │                                   │       │                          │          │           │                       │ RuleName: '-'                  │
│                     │                                   │       │                          │          │           │                       │ EventType: SetValue            │
│                     │                                   │       │                          │          │           │                       │ ProcessId: 47960               │
│                     │                                   │       │                          │          │           │                       │ ProcessGuid: D2B54B40-F1E3-698 │
│                     │                                   │       │                          │          │           │                       │ 9-430C-0C0000003800            │
│                     │                                   │       │                          │          │           │                       │ User: HIGHTEC\agemes           │
│                     │                                   │       │                          │          │           │                       │ UtcTime: 2026-02-09 20:06:30.8 │
│                     │                                   │       │                          │          │           │                       │ 28                             │
│                     │                                   │       │                          │          │           │                       │ Details: remcos.exe            │
├─────────────────────┼───────────────────────────────────┼───────┼──────────────────────────┼──────────┼───────────┼───────────────────────┼────────────────────────────────┤
│ 2026-02-09 20:10:05 │ + Remcos RAT registry persistence │ 1     │ Microsoft-Windows-Sysmon │ 13       │ 96317     │ HTNB-3006.hightec.htc │ Image: C:\Windows\System32\Win │
│                     │                                   │       │                          │          │           │                       │ dowsPowerShell\v1.0\powershell │
│                     │                                   │       │                          │          │           │                       │ .exe                           │
│                     │                                   │       │                          │          │           │                       │ TargetObject: HKU\S-1-5-21-218 │
│                     │                                   │       │                          │          │           │                       │ 5766489-2577382833-530242202-2 │
│                     │                                   │       │                          │          │           │                       │ 112\Software\Microsoft\Windows │
│                     │                                   │       │                          │          │           │                       │ \CurrentVersion\Run\Rmc        │
│                     │                                   │       │                          │          │           │                       │ RuleName: '-'                  │
│                     │                                   │       │                          │          │           │                       │ EventType: SetValue            │
│                     │                                   │       │                          │          │           │                       │ ProcessId: 47960               │
│                     │                                   │       │                          │          │           │                       │ ProcessGuid: D2B54B40-F1E3-698 │
│                     │                                   │       │                          │          │           │                       │ 9-430C-0C0000003800            │
│                     │                                   │       │                          │          │           │                       │ User: HIGHTEC\agemes           │
│                     │                                   │       │                          │          │           │                       │ UtcTime: 2026-02-09 20:10:05.5 │
│                     │                                   │       │                          │          │           │                       │ 46                             │
│                     │                                   │       │                          │          │           │                       │ Details: remcos.exe            │
└─────────────────────┴───────────────────────────────────┴───────┴──────────────────────────┴──────────┴───────────┴───────────────────────┴────────────────────────────────┘

[+] 2 Detections found on 2 documents
```