@{
    RootModule        = 'HuntKit.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '7f4a3c91-e2b6-4d8f-a1c9-3e7b2d0f5a8c'
    Author            = 'Damian Fabricio Macancela Caguana'
    CompanyName       = 'ZeroTrust Tech'
    Copyright         = '(c) 2026 Damian Fabricio Macancela Caguana. MIT License.'
    Description       = 'Threat Hunting toolkit for Windows: persistence collectors, script-block analysis, and ATT&CK-mapped baseline diffing.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Save-PersistenceBaseline',
        'Get-PersistenceDrift',
        'Find-SuspiciousScriptBlock',
        'Get-PersistenceSummary'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('DFIR', 'ThreatHunting', 'MITRE', 'ATT&CK', 'BlueTeam', 'Persistence', 'PowerShell', 'Security')
            LicenseUri   = 'https://github.com/DamianMacancela/HuntKit/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/DamianMacancela/HuntKit'
            ReleaseNotes = @'
## v0.1.0
- Run Keys collector (T1547.001) - HKLM + HKCU + WOW6432Node
- Scheduled Tasks collector (T1053.005)
- WMI Event Subscription collector (T1546.003)
- Baseline save/diff engine with SHA-256 integrity hash
- Script Block 4104 analysis with 5 detection rules (T1059/T1140/T1055)
- HTML drift report export
'@
        }
    }
}
