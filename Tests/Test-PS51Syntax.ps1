#Requires -Version 5.1
<#
.SYNOPSIS
    Parses every .ps1/.psm1/.psd1 file in the suite with the PowerShell parser and checks the module loads.
    Run this in Windows PowerShell 5.1 (powershell.exe) to confirm 5.1 compatibility. No API calls are made.
.EXAMPLE
    powershell.exe -NoProfile -File .\Tests\Test-PS51Syntax.ps1
#>
$root = Split-Path -Parent $PSScriptRoot
$failed = 0
Write-Host ("PowerShell {0} ({1})" -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition)

# -Include is unreliable with -LiteralPath in 5.1 (it returns folders and other files), so filter by extension.
$files = Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object { @('.ps1', '.psm1', '.psd1') -contains $_.Extension.ToLowerInvariant() }
foreach ($file in $files) {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors -and $errors.Count -gt 0) {
        $failed++
        foreach ($e in $errors) {
            Write-Host ("FAIL {0}:{1} {2}" -f $file.Name, $e.Extent.StartLineNumber, $e.Message) -ForegroundColor Red
        }
    } else {
        Write-Host ("OK   {0}" -f $file.FullName.Substring($root.Length + 1)) -ForegroundColor Green
    }
}

try {
    $manifest = Test-ModuleManifest -Path (Join-Path $root 'IdiraPCloud\IdiraPCloud.psd1') -ErrorAction Stop
    Import-Module (Join-Path $root 'IdiraPCloud\IdiraPCloud.psd1') -Force -ErrorAction Stop
    $exported = @(Get-Command -Module IdiraPCloud)
    Write-Host ("Module {0} {1} loaded with {2} commands." -f $manifest.Name, $manifest.Version, $exported.Count) -ForegroundColor Green
} catch {
    $failed++
    Write-Host ("FAIL module load: {0}" -f $_.Exception.Message) -ForegroundColor Red
}

if ($failed -gt 0) { Write-Host "$failed problem(s) found." -ForegroundColor Red; exit 1 }
Write-Host 'All files parsed and the module loaded.' -ForegroundColor Green
