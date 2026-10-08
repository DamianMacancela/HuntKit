HuntKit
=======

*a toolkit to manage and hunt Windows persistence mechanisms*

**HuntKit** allows you to create, snapshot, and compare Windows persistence vectors (Run Keys, Scheduled Tasks, WMI event subscriptions). Useful for understanding how persistence works, testing EDRs, or analyzing system state drifts.

### Features
* **Inject / Clean:** Safely add or remove test persistence mechanisms.
* **Baselines:** Export the current state of critical Windows paths to JSON.
* **Drift Detection:** Compare the live system against a baseline to highlight modifications.

### Usage

```powershell
Import-Module .\HuntKit\HuntKit.psd1

# 1. Take a clean snapshot
Save-PersistenceBaseline -Path .\baseline.json

# 2. Simulate an attacker (e.g., Run Key)
Set-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name "EvilApp" -Value "calc.exe"

# 3. Hunt for drifts
Get-PersistenceDrift -BaselinePath .\baseline.json
```

### Supported Vectors
* Registry Run Keys (`HKCU` / `HKLM`)
* Scheduled Tasks
* WMI Event Subscriptions (Filters, Consumers, Bindings)

### License
MIT
