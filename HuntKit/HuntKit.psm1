#Requires -Version 5.1
<#
.SYNOPSIS
    HuntKit – Módulo de Threat Hunting para Windows.
.DESCRIPTION
    Recolectores de persistencia, análisis de bloques de script (4104) y
    motor de drift de baseline alineado con MITRE ATT&CK.
    Diseñado para blue-teamers y analistas DFIR.
.NOTES
    Autor  : Damian Fabricio Macancela Caguana
    Versión: 0.1.0
    Licencia: MIT
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Constantes ATT&CK ──────────────────────────────────────────────────

$script:TechniqueMap = @{
    RunKey           = 'T1547.001'
    ScheduledTask    = 'T1053.005'
    WMISubscription  = 'T1546.003'
    SuspiciousScript = 'T1059.001'
}

#endregion

#region ── Helpers internos ───────────────────────────────────────────────────

function Get-RunKeys {
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param()

    $items = [System.Collections.Generic.List[PSCustomObject]]::new()

    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )

    foreach ($path in $paths) {
        if (-not (Test-Path $path)) { continue }
        try {
            $key = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($null -eq $key) { continue }
            $key.PSObject.Properties |
                Where-Object { $_.Name -notlike 'PS*' } |
                ForEach-Object {
                    $items.Add([PSCustomObject]@{
                        Type      = 'RunKey'
                        Technique = $script:TechniqueMap['RunKey']
                        Source    = $path
                        Name      = $_.Name
                        Value     = $_.Value
                        Hash      = (Get-StringHash $_.Value)
                    })
                }
        }
        catch { Write-Warning "RunKey [$path]: $_" }
    }
    return $items
}

function Get-ScheduledTaskItems {
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param()

    $items = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach ($task in $tasks) {
            $action = ($task.Actions | ForEach-Object {
                if ($_.CimClass.CimClassName -eq 'MSFT_TaskExecAction') {
                    "$($_.Execute) $($_.Arguments)"
                }
            }) -join '; '

            $items.Add([PSCustomObject]@{
                Type      = 'ScheduledTask'
                Technique = $script:TechniqueMap['ScheduledTask']
                Source    = "\$($task.TaskPath)$($task.TaskName)"
                Name      = $task.TaskName
                Value     = $action
                Hash      = (Get-StringHash $action)
            })
        }
    }
    catch { Write-Warning "ScheduledTask: $_" }

    return $items
}

function Get-WMISubscriptions {
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param()

    $items = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $filters   = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter   -ErrorAction SilentlyContinue
        $consumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer  -ErrorAction SilentlyContinue
        $bindings  = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue

        foreach ($binding in $bindings) {
            $filterName   = ($filters   | Where-Object { $_.Name -eq $binding.Filter.Name }).Name
            $consumerName = ($consumers | Where-Object { $_.Name -eq $binding.Consumer.Name }).Name
            $val = "Filter=$filterName; Consumer=$consumerName"

            $items.Add([PSCustomObject]@{
                Type      = 'WMISubscription'
                Technique = $script:TechniqueMap['WMISubscription']
                Source    = 'root\subscription'
                Name      = "$filterName -> $consumerName"
                Value     = $val
                Hash      = (Get-StringHash $val)
            })
        }
    }
    catch { Write-Warning "WMISubscription: $_" }

    return $items
}

function Get-StringHash {
    param([string]$InputString)
    $sha   = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
    [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLower()
}

#endregion

#region ── Reglas Script-Block (EID 4104) ─────────────────────────────────────

$script:ScriptBlockRules = @(
    @{
        Id          = 'SB001'
        Technique   = 'T1059.001'
        Description = 'Invocacion dinamica con IEX / Invoke-Expression'
        Pattern     = [regex]::new(
            '(?i)(invoke-expression|iex)\s*[\(\$]',
            [System.Text.RegularExpressions.RegexOptions]::Compiled
        )
        Severity    = 'High'
    },
    @{
        Id          = 'SB002'
        Technique   = 'T1140'
        Description = 'Decodificacion Base64 seguida de ejecucion'
        Pattern     = [regex]::new(
            '(?i)FromBase64String.{0,80}(invoke|iex|\|\s*\.)',
            [System.Text.RegularExpressions.RegexOptions]::Compiled
        )
        Severity    = 'High'
    },
    @{
        Id          = 'SB003'
        Technique   = 'T1059.001'
        Description = 'Descarga remota via Net.WebClient o Invoke-WebRequest'
        Pattern     = [regex]::new(
            '(?i)(Net\.WebClient|Invoke-WebRequest|wget|curl).{0,50}(DownloadString|DownloadFile)',
            [System.Text.RegularExpressions.RegexOptions]::Compiled
        )
        Severity    = 'Medium'
    },
    @{
        Id          = 'SB004'
        Technique   = 'T1059.001'
        Description = 'Ofuscacion por concatenacion o tick-escaping'
        Pattern     = [regex]::new(
            '(?i)(` [a-z]){3,}|(\w+"[ ]*\+[ ]*"\w+){3,}|(-[Jj][Oo][Ii][Nn])',
            [System.Text.RegularExpressions.RegexOptions]::Compiled
        )
        Severity    = 'Medium'
    },
    @{
        Id          = 'SB005'
        Technique   = 'T1055'
        Description = 'Inyeccion de proceso: VirtualAlloc/CreateThread via reflection'
        Pattern     = [regex]::new(
            '(?i)(VirtualAlloc|CreateThread|WriteProcessMemory|NtCreateThread)',
            [System.Text.RegularExpressions.RegexOptions]::Compiled
        )
        Severity    = 'Critical'
    }
)

#endregion

#region ── Funciones exportadas ───────────────────────────────────────────────

function Save-PersistenceBaseline {
<#
.SYNOPSIS
    Guarda un snapshot de todos los mecanismos de persistencia conocidos.
.DESCRIPTION
    Recolecta Run Keys, Tareas Programadas y Subscripciones WMI y los
    serializa en un archivo JSON con hash de integridad SHA-256.
.PARAMETER Path
    Ruta de salida del archivo baseline (default: baseline.json).
.EXAMPLE
    Save-PersistenceBaseline -Path .\baseline.json
.NOTES
    ATT&CK cubierto: T1547.001, T1053.005, T1546.003
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Position = 0)]
        [string]$Path = '.\baseline.json'
    )

    if ($PSCmdlet.ShouldProcess($Path, 'Guardar baseline de persistencia')) {

        $allItems = [System.Collections.Generic.List[PSCustomObject]]::new()

        Write-Verbose 'Recolectando Run Keys...'
        Get-RunKeys | ForEach-Object { $allItems.Add($_) }

        Write-Verbose 'Recolectando Tareas Programadas...'
        Get-ScheduledTaskItems | ForEach-Object { $allItems.Add($_) }

        Write-Verbose 'Recolectando Subscripciones WMI...'
        Get-WMISubscriptions | ForEach-Object { $allItems.Add($_) }

        $baseline = @{
            Version      = '1.0'
            CapturedAt   = (Get-Date -Format 'o')
            ComputerName = $env:COMPUTERNAME
            ItemCount    = $allItems.Count
            Items        = $allItems
        }

        # Calcular hash de integridad sobre el contenido
        $json = $baseline | ConvertTo-Json -Depth 6
        $integrityHash = Get-StringHash $json
        $baseline['IntegrityHash'] = $integrityHash

        $finalJson = $baseline | ConvertTo-Json -Depth 6
        [System.IO.File]::WriteAllText(
            [System.IO.Path]::GetFullPath($Path),
            $finalJson,
            [System.Text.Encoding]::UTF8
        )

        Write-Host "[+] Baseline guardado: $Path  ($($allItems.Count) items)" -ForegroundColor Green
    }
}

function Get-PersistenceDrift {
<#
.SYNOPSIS
    Compara el estado actual de persistencia con un baseline previo.
.DESCRIPTION
    Detecta entradas Added/Removed en Run Keys, Tareas y WMI comparando
    hashes SHA-256. Cada cambio es etiquetado con la tecnica ATT&CK.
.PARAMETER BaselinePath
    Ruta del archivo baseline generado por Save-PersistenceBaseline.
.PARAMETER OutputPath
    (Opcional) Exporta un reporte HTML a esta ruta.
.EXAMPLE
    Get-PersistenceDrift -BaselinePath .\baseline.json
.EXAMPLE
    Get-PersistenceDrift -BaselinePath .\baseline.json -OutputPath .\report.html
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateScript({ Test-Path $_ })]
        [string]$BaselinePath,

        [Parameter()]
        [string]$OutputPath
    )

    $baselineJson = Get-Content -Path $BaselinePath -Raw -Encoding UTF8
    $baseline     = $baselineJson | ConvertFrom-Json

    Write-Verbose "Baseline de: $($baseline.CapturedAt) en $($baseline.ComputerName)"

    # Estado actual
    $currentItems = [System.Collections.Generic.List[PSCustomObject]]::new()
    Get-RunKeys           | ForEach-Object { $currentItems.Add($_) }
    Get-ScheduledTaskItems | ForEach-Object { $currentItems.Add($_) }
    Get-WMISubscriptions  | ForEach-Object { $currentItems.Add($_) }

    # Indexar por hash
    $baselineHashes = @{}
    foreach ($item in $baseline.Items) { $baselineHashes[$item.Hash] = $item }

    $currentHashes = @{}
    foreach ($item in $currentItems) { $currentHashes[$item.Hash] = $item }

    $driftItems = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($hash in $currentHashes.Keys) {
        if (-not $baselineHashes.ContainsKey($hash)) {
            $item = $currentHashes[$hash]
            $driftItems.Add([PSCustomObject]@{
                ChangeType = 'Added'
                Technique  = $item.Technique
                Type       = $item.Type
                Source     = $item.Source
                Name       = $item.Name
                Value      = $item.Value
                Hash       = $hash
                DetectedAt = (Get-Date -Format 'o')
            })
        }
    }

    foreach ($hash in $baselineHashes.Keys) {
        if (-not $currentHashes.ContainsKey($hash)) {
            $item = $baselineHashes[$hash]
            $driftItems.Add([PSCustomObject]@{
                ChangeType = 'Removed'
                Technique  = $item.Technique
                Type       = $item.Type
                Source     = $item.Source
                Name       = $item.Name
                Value      = $item.Value
                Hash       = $hash
                DetectedAt = (Get-Date -Format 'o')
            })
        }
    }

    if ($driftItems.Count -eq 0) {
        Write-Host '[OK] Sin cambios detectados en mecanismos de persistencia.' -ForegroundColor Green
    }
    else {
        $driftItems | ForEach-Object {
            $color = if ($_.ChangeType -eq 'Added') { 'Red' } else { 'Yellow' }
            Write-Host "[$($_.ChangeType)] $($_.Type) | $($_.Technique) | $($_.Name)" -ForegroundColor $color
            Write-Host "    Source : $($_.Source)"
            Write-Host "    Value  : $($_.Value)"
            Write-Host ''
        }
    }

    if ($OutputPath) {
        Export-DriftHtmlReport -DriftItems $driftItems -OutputPath $OutputPath
    }

    return $driftItems
}

function Find-SuspiciousScriptBlock {
<#
.SYNOPSIS
    Analiza eventos EID 4104 en busca de tecnicas ofensivas conocidas.
.DESCRIPTION
    Aplica reglas regex sobre el texto de script blocks capturados por
    PowerShell Script Block Logging, clasificando cada coincidencia con
    severidad y tecnica ATT&CK correspondiente.
.PARAMETER Since
    Filtrar eventos desde esta fecha/hora (default: ultimas 24 horas).
.PARAMETER ComputerName
    Equipo remoto a consultar (default: local).
.PARAMETER EvtxPath
    Ruta a un archivo .evtx exportado (util para analisis offline o tests).
.PARAMETER MinSeverity
    Severidad minima a reportar: Low | Medium | High | Critical (default: Medium).
.EXAMPLE
    Find-SuspiciousScriptBlock -Since (Get-Date).AddHours(-6)
.EXAMPLE
    Find-SuspiciousScriptBlock -EvtxPath .\tests\data\sample.evtx -Since (Get-Date).AddYears(-5)
#>
    [CmdletBinding(DefaultParameterSetName = 'Live')]
    param(
        [Parameter()]
        [datetime]$Since = (Get-Date).AddHours(-24),

        [Parameter(ParameterSetName = 'Live')]
        [string]$ComputerName = $env:COMPUTERNAME,

        [Parameter(ParameterSetName = 'Offline', Mandatory)]
        [ValidateScript({ Test-Path $_ })]
        [string]$EvtxPath,

        [Parameter()]
        [ValidateSet('Low', 'Medium', 'High', 'Critical')]
        [string]$MinSeverity = 'Medium'
    )

    $severityOrder = @{ Low = 0; Medium = 1; High = 2; Critical = 3 }
    $minLevel      = $severityOrder[$MinSeverity]

    try {
        if ($PSCmdlet.ParameterSetName -eq 'Offline') {
            $events = Get-WinEvent -FilterHashtable @{ Path = $EvtxPath; Id = 4104 } `
                        -ErrorAction SilentlyContinue |
                      Where-Object { $_.TimeCreated -ge $Since }
        }
        else {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = 'Microsoft-Windows-PowerShell/Operational'
                Id        = 4104
                StartTime = $Since
            } -ComputerName $ComputerName -ErrorAction SilentlyContinue
        }
    }
    catch {
        if ($_.Exception.Message -match 'No events were found') {
            Write-Warning 'Sin eventos 4104. Verifica Script Block Logging (Paso 2 de la guia).'
            return [System.Collections.Generic.List[PSCustomObject]]::new()
        }
        throw
    }

    if (-not $events) {
        Write-Warning 'Sin eventos 4104 en el rango especificado.'
        return [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($event in $events) {
        $text = $event.Message
        if ([string]::IsNullOrWhiteSpace($text)) { continue }

        foreach ($rule in $script:ScriptBlockRules) {
            if ($severityOrder[$rule.Severity] -lt $minLevel) { continue }
            if (-not $rule.Pattern.IsMatch($text)) { continue }

            $match   = $rule.Pattern.Match($text)
            $start   = [Math]::Max(0, $match.Index - 40)
            $length  = [Math]::Min(200, $text.Length - $start)
            $excerpt = $text.Substring($start, $length).Trim() -replace '\r?\n', ' '

            $findings.Add([PSCustomObject]@{
                TimeCreated = $event.TimeCreated
                RuleId      = $rule.Id
                Severity    = $rule.Severity
                Technique   = $rule.Technique
                Description = $rule.Description
                EventId     = $event.Id
                Excerpt     = $excerpt
            })
        }
    }

    if ($findings.Count -eq 0) {
        Write-Host '[OK] Sin script blocks sospechosos en el periodo analizado.' -ForegroundColor Green
    }
    else {
        $findings | Sort-Object Severity, TimeCreated | ForEach-Object {
            $color = switch ($_.Severity) {
                'Critical' { 'Red'     }
                'High'     { 'Magenta' }
                'Medium'   { 'Yellow'  }
                default    { 'Cyan'    }
            }
            Write-Host "[$($_.Severity)] $($_.RuleId) | $($_.Technique) | $($_.Description)" -ForegroundColor $color
            Write-Host "    Time   : $($_.TimeCreated)"
            Write-Host "    Excerpt: $($_.Excerpt)"
            Write-Host ''
        }
    }

    return $findings
}

function Get-PersistenceSummary {
<#
.SYNOPSIS
    Resumen rapido del estado de persistencia del sistema (sin baseline).
.DESCRIPTION
    Util para triage inicial sin necesidad de un baseline previo.
.EXAMPLE
    Get-PersistenceSummary | Format-Table -AutoSize
#>
    [CmdletBinding()]
    param()

    $all = [System.Collections.Generic.List[PSCustomObject]]::new()
    Get-RunKeys            | ForEach-Object { $all.Add($_) }
    Get-ScheduledTaskItems | ForEach-Object { $all.Add($_) }
    Get-WMISubscriptions   | ForEach-Object { $all.Add($_) }

    Write-Host "[i] $($all.Count) items de persistencia encontrados en $env:COMPUTERNAME" -ForegroundColor Cyan
    return $all
}

#endregion

#region ── Exportacion HTML ───────────────────────────────────────────────────

function Export-DriftHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $DriftItems,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $rows = @($DriftItems) | ForEach-Object {
        $badgeColor = if ($_.ChangeType -eq 'Added') { '#e53e3e' } else { '#d69e2e' }
        $rowColor   = if ($_.ChangeType -eq 'Added') { '#fff5f5' } else { '#fffff0' }
        @"
<tr style="background:$rowColor">
  <td><span style="background:$badgeColor;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">$($_.ChangeType)</span></td>
  <td><code>$($_.Technique)</code></td>
  <td>$($_.Type)</td>
  <td>$($_.Name)</td>
  <td style="font-size:11px;color:#4a5568">$($_.Source)</td>
  <td style="font-size:11px;word-break:break-all;max-width:300px">$($_.Value)</td>
</tr>
"@
    }

    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $count     = @($DriftItems).Count

    $html = @"
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>HuntKit - Persistence Drift Report</title>
  <style>
    body { font-family: 'Segoe UI', sans-serif; background:#f7fafc; color:#2d3748; margin:0; padding:24px }
    h1   { color:#1a202c; font-size:22px; border-bottom:2px solid #e2e8f0; padding-bottom:8px }
    .meta{ font-size:13px; color:#718096; margin-bottom:20px }
    table{ border-collapse:collapse; width:100%; background:#fff; border-radius:8px;
           box-shadow:0 1px 3px rgba(0,0,0,.12) }
    th   { background:#2d3748; color:#fff; padding:10px 14px; text-align:left; font-size:13px }
    td   { padding:9px 14px; border-bottom:1px solid #e2e8f0; font-size:13px; vertical-align:top }
    tr:last-child td { border-bottom:none }
    .empty { text-align:center; padding:40px; color:#48bb78; font-size:16px }
    footer { font-size:11px; color:#a0aec0; margin-top:16px; text-align:right }
  </style>
</head>
<body>
  <h1>HuntKit - Persistence Drift Report</h1>
  <div class="meta">Generado: $generated | Host: $($env:COMPUTERNAME) | Cambios: $count</div>
"@

    if ($count -eq 0) {
        $html += '<div class="empty">Sin cambios en mecanismos de persistencia</div>'
    }
    else {
        $html += @"
  <table>
    <thead>
      <tr><th>Cambio</th><th>ATT&amp;CK</th><th>Tipo</th><th>Nombre</th><th>Fuente</th><th>Valor</th></tr>
    </thead>
    <tbody>
      $($rows -join "`n")
    </tbody>
  </table>
"@
    }

    $html += @"
  <footer>HuntKit v0.1.0 - Damian Fabricio Macancela Caguana - MIT License</footer>
</body>
</html>
"@

    [System.IO.File]::WriteAllText(
        [System.IO.Path]::GetFullPath($OutputPath),
        $html,
        [System.Text.Encoding]::UTF8
    )
    Write-Host "[+] Reporte HTML: $OutputPath" -ForegroundColor Green
}

#endregion

Export-ModuleMember -Function `
    Save-PersistenceBaseline, `
    Get-PersistenceDrift, `
    Find-SuspiciousScriptBlock, `
    Get-PersistenceSummary
