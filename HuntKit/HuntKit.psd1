@{
    RootModule        = 'HuntKit.psm1'
    ModuleVersion     = '0.2.0'
    GUID              = '7f4a3c91-e2b6-4d8f-a1c9-3e7b2d0f5a8c'
    Author            = 'Damian Fabricio Macancela Caguana'
    CompanyName       = 'ZeroTrust Tech'
    Copyright         = '(c) 2026 Damian Fabricio Macancela Caguana. MIT License.'
    Description       = 'Threat Hunting toolkit for Windows: persistence collectors (RunKey/Task/Service/WMI/Startup), SHA-256 baseline diffing, and ATT&CK-mapped script-block analysis with block reassembly and composite rules.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Get-PersistenceSnapshot',
        'Save-PersistenceBaseline',
        'Get-PersistenceDrift',
        'Compare-PersistenceSnapshot',
        'Test-ScriptBlockText',
        'Find-SuspiciousScriptBlock',
        'Export-HuntReport'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @(
                'DFIR','ThreatHunting','MITRE','ATT&CK','BlueTeam',
                'Persistence','PowerShell','Security','IncidentResponse','WindowsSecurity'
            )
            LicenseUri   = 'https://github.com/DamianMacancela/HuntKit/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/DamianMacancela/HuntKit'
            ReleaseNotes = @'
## v0.2.0 - Arquitectura corregida y ampliada
### Nuevos
- Colector Get-ServicePersistence (T1543.003)
- Colector Get-StartupFolderPersistence con SHA-256 en Extra (T1547.001)
- Funcion pura Compare-PersistenceSnapshot (diff O(n) por hashtable)
- Reensamblado de script blocks fragmentados en Find-SuspiciousScriptBlock
- Regla compuesta SB100: Download + IEX = cradle (High)
- 6 reglas nuevas: SB005-SB011 (AMSI, Defender, reflection, Win32 API, mimikatz, char-code)
- Export-HuntReport con HtmlEncode en todos los valores (anti-XSS)
- Soporte de baseline v1.0 y v2.0 en Get-PersistenceDrift
- Test-IsAdmin con aviso no fatal

### Corregido
- ConvertTo-Json -InputObject en lugar de pipeline (evita serializar array como objeto)
- -LiteralPath en todos los cmdlets de registro y filesystem
- Exclusion exacta de propiedades PS* en RunKey collector
- Manejo correcto de acciones COM en ScheduledTask collector

## v0.1.0 - Initial Release
'@
        }
    }
}
