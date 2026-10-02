# HuntKit

> Módulo PowerShell de Threat Hunting para Windows — Persistencia · Script-Block · MITRE ATT&CK

[![CI](https://github.com/DamianMacancela/HuntKit/actions/workflows/ci.yml/badge.svg)](https://github.com/DamianMacancela/HuntKit/actions)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)](https://github.com/PowerShell/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows)](https://www.microsoft.com/windows)

---

## El Problema

En la respuesta a incidentes y el threat hunting, las preguntas más urgentes son simples pero difíciles de responder rápidamente:

- **¿Qué mecanismo de persistencia nuevo apareció entre ayer y hoy?**
- **¿Alguien ejecutó un script PowerShell codificado en Base64 en las últimas 6 horas?**
- **¿Hay una suscripción WMI que no estaba hace 20 minutos?**

Las herramientas genéricas responden con listas de 300 líneas. HuntKit responde con **diffs**.

El enfoque es baseline + comparación de hashes SHA-256: capturas el estado "bueno" del sistema, y detectas cualquier desvío en tiempo real. Cada cambio aparece etiquetado con su técnica ATT&CK correspondiente.

---

## Mapeo ATT&CK

| Técnica | ID | Colector / Regla | Fuente de Telemetría |
|---|---|---|---|
| Boot/Logon Autostart – Registry Run Keys | **T1547.001** | `Get-RunKeys` | Registry (HKLM + HKCU) |
| Scheduled Task/Job | **T1053.005** | `Get-ScheduledTaskItems` | Scheduled Tasks |
| Event Triggered Execution – WMI | **T1546.003** | `Get-WMISubscriptions` | WMI `root\subscription` |
| Command & Scripting – PowerShell | **T1059.001** | Reglas SB001, SB003, SB004 | EID 4104 |
| Deobfuscate/Decode Files (Base64) | **T1140** | Regla SB002 | EID 4104 |
| Process Injection | **T1055** | Regla SB005 | EID 4104 |

---

## Instalación

```powershell
# Desde el directorio del repo
Import-Module .\HuntKit\HuntKit.psd1 -Force

# Verificar funciones disponibles
Get-Command -Module HuntKit
```

**Requisito para análisis de eventos 4104** — Ejecutar **una sola vez** como Administrador:

```powershell
$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item $k -Force | Out-Null
Set-ItemProperty $k EnableScriptBlockLogging 1 -Type DWord
```

---

## Uso

### 1. Guardar un baseline

```powershell
Save-PersistenceBaseline -Path .\baseline.json -Verbose
```

```
VERBOSE: Recolectando Run Keys...
VERBOSE: Recolectando Tareas Programadas...
VERBOSE: Recolectando Subscripciones WMI...
[+] Baseline guardado: .\baseline.json  (142 items)
```

### 2. Detectar drift (ejemplo real, sanitizado)

```powershell
# Simular persistencia nueva
Set-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' TestEntry 'notepad.exe'

Get-PersistenceDrift -BaselinePath .\baseline.json
```

```
[Added] RunKey | T1547.001 | TestEntry
    Source : HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    Value  : notepad.exe
```

### 3. Exportar reporte HTML

```powershell
Get-PersistenceDrift -BaselinePath .\baseline.json -OutputPath .\report.html
```

### 4. Analizar Script Blocks (últimas 6 horas)

```powershell
Find-SuspiciousScriptBlock -Since (Get-Date).AddHours(-6) -MinSeverity High
```

```
[High] SB001 | T1059.001 | Invocacion dinamica con IEX / Invoke-Expression
    Time   : 02/10/2026 17:30:14
    Excerpt: ...IEX((New-Object Net.WebClient).DownloadString('http://...'))...

[Critical] SB005 | T1055 | Inyeccion de proceso: VirtualAlloc/CreateThread via reflection
    Time   : 02/10/2026 17:31:02
    Excerpt: ...$addr = [Kernel32]::VirtualAlloc(0, $buf.Length, 0x3000, 0x40)...
```

### 5. Triage rápido (sin baseline)

```powershell
Get-PersistenceSummary | Format-Table Type, Technique, Name, Value -AutoSize
```

---

## Falsos Positivos Conocidos

Parte de construir una herramienta honesta es documentar cuándo **no** debes alertar:

| Caso | Por qué aparece | Cómo distinguirlo |
|---|---|---|
| Adobe Acrobat Update en Run Keys | Adobe instala y remueve entradas en cada actualización | Verificar firma del ejecutable con `Get-AuthenticodeSignature` |
| Tareas del sistema `\Microsoft\Windows\*` | Windows crea centenares de tareas legítimas | Filtrar por `Source -notlike '\Microsoft\*'` para primeros análisis |
| IEX en scripts de módulos legítimos | PSReadLine, Chocolatey y otros usan IEX internamente | Correlacionar con la ruta del script en el evento 4103 |
| WMI `root\subscription` vacía | Normal en la mayoría de sistemas sin software de gestión | La ausencia de suscripciones es la condición segura |

---

## Limitaciones (honestidad ante reclutadores)

- **Script Block Logging es desactivable** por el propio atacante con derechos de admin. Un atacante que llegue primero puede deshabilitarlo.
- **El baseline puede manipularse** si el atacante tiene acceso de escritura al JSON. Mitigación: almacenarlo en un share de solo lectura o verificar el `IntegrityHash`.
- **HKCU es parcial**: solo captura el usuario actual. Otros usuarios del sistema no están cubiertos sin sesión activa.
- **WMI offline** (sistemas sin WMI funcional) devolverá advertencia y continuará.
- **Las reglas 4104 son bypaseables** por concatenación avanzada, variables de entorno, o uso de COM. Esta es la razón de incluir regla SB004 como capa adicional.

---

## Tests y Calidad

```powershell
# Instalar dependencias
Install-Module Pester           -MinimumVersion 5.5.0 -Scope CurrentUser -Force -SkipPublisherCheck
Install-Module PSScriptAnalyzer -MinimumVersion 1.21  -Scope CurrentUser -Force

# Ejecutar tests
Invoke-Pester .\tests -CI

# Lint
Invoke-ScriptAnalyzer .\HuntKit -Recurse
```

Los tests cubren:
- Hash SHA-256: determinismo, unicidad, longitud.
- Baseline: serialización JSON válida, detección de Run Key real añadida.
- Reglas SB001–SB005: verdaderos positivos, falsos positivos controlados, filtrado por severidad.
- Reporte HTML: generación y contenido mínimo.

---

## Estructura del Proyecto

```
HuntKit/
├── HuntKit/
│   ├── HuntKit.psm1      # Módulo principal
│   └── HuntKit.psd1      # Manifiesto (versión, tags, autor)
├── tests/
│   ├── HuntKit.Tests.ps1 # Suite Pester v5
│   └── data/             # Archivos .evtx sintéticos para tests offline
├── .github/
│   └── workflows/
│       └── ci.yml        # PSScriptAnalyzer + Pester en windows-latest
├── .gitignore            # baseline.json, *.html, *.evtx nunca al repo
├── LICENSE               # MIT
├── SECURITY.md           # Política de divulgación responsable
└── README.md
```

---

## Próximas mejoras (roadmap)

| Mejora | Señal que demuestra |
|---|---|
| `Get-AuthenticodeSignature` + hash del binario | Triage real, no solo enumeración |
| Correlación EID 7045/4698 con el drift | Entendimiento de telemetría complementaria |
| Exportar reglas a formato Sigma | Interoperabilidad con SIEM (Splunk, Elastic) |
| Casos de evasión en tests (concatenación, tick-escaping) | Pensamiento adversarial documentado |
| Baseline firmado con GPG | Conciencia de integridad de evidencia |

---

## Autor

**Damian Fabricio Macancela Caguana**  
Estudiante de Ciberseguridad (ITSA) y Derecho (UTPL) | Azuay, Ecuador

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/damian-fabricio-macancela-b0a24b3b5)
[![Web](https://img.shields.io/badge/Blog-000000?style=flat-square&logo=github&logoColor=white)](https://damianmacancela.github.io)

---

*Este módulo se desarrolló como parte de mi formación práctica en threat hunting y análisis DFIR. Toda prueba documentada se realizó en entorno de laboratorio controlado.*

**Disclaimer:** HuntKit es exclusivamente para uso ético en sistemas sobre los que tienes autorización expresa. El uso en sistemas sin autorización puede constituir un delito.
