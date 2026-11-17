#Requires -Version 5.1
# IdiraPCloud - PowerShell 5.1 wrapper for Idira (formerly CyberArk) Privilege Cloud REST APIs.

$moduleRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

foreach ($folder in @('Private', 'Public')) {
    $dir = Join-Path $moduleRoot $folder
    if (Test-Path -LiteralPath $dir) {
        foreach ($file in (Get-ChildItem -LiteralPath $dir -Filter '*.ps1' | Sort-Object Name)) {
            . $file.FullName
        }
    }
}

Initialize-PCloudTls
