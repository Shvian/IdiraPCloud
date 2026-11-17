#Requires -Version 5.1
# Clearing the PowerShell window after a log out or an idle sign-out, so no privileged data stays behind.

# Global variables that existed when the module loaded. Only variables created after that are removed.
$script:PCloudGlobalBaseline = @{}
foreach ($v in @(Get-Variable -Scope Global -ErrorAction SilentlyContinue)) { $script:PCloudGlobalBaseline[$v.Name] = $true }

function Clear-PCloudPowerShellSession {
    <#
    .SYNOPSIS
        Clears data a Privilege Cloud session may have left in this PowerShell window.
    .DESCRIPTION
        Runs on log out and on the idle sign-out. It:
          - removes the global variables created since the module loaded (for example results saved
            from Get-PCloudAccount), disposing any SecureString first; the module's own PCloud* switches stay
          - clears $Error, which can hold API responses
          - clears the command history (Get-History and the PSReadLine in-memory history)
          - clears the screen and, in Windows Terminal, its scrollback
          - runs garbage collection so released objects are freed
        It does not touch the PSReadLine history file on disk, the clipboard (Get-AccountPassword clears what
        it copies), files the scripts wrote (CSVs, Logs), or a transcript started with -Log.
    .PARAMETER KeepScreen
        Leaves the screen and scrollback as they are.
    .EXAMPLE
        Clear-PCloudPowerShellSession
    #>
    [CmdletBinding()]
    param([switch]$KeepScreen)
    $removed = 0
    foreach ($v in @(Get-Variable -Scope Global -ErrorAction SilentlyContinue)) {
        if ($script:PCloudGlobalBaseline.ContainsKey($v.Name)) { continue }
        if ($v.Name -like 'PCloud*') { continue }
        if ($v.Options -band [System.Management.Automation.ScopedItemOptions]::Constant) { continue }
        try {
            if ($v.Value -is [System.Security.SecureString]) { $v.Value.Dispose() }
            Remove-Variable -Name $v.Name -Scope Global -Force -ErrorAction Stop
            $removed++
        } catch { }
    }
    try { $global:Error.Clear() } catch { }
    try { Clear-History -ErrorAction SilentlyContinue } catch { }
    try {
        if (Get-Module -Name PSReadLine) { [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory() }
    } catch { }
    if (-not $KeepScreen) {
        try { Clear-Host } catch { }
        # Windows Terminal keeps scrollback after Clear-Host; ESC[3J clears it. The classic console has none left.
        if ($env:WT_SESSION -and $Host.Name -eq 'ConsoleHost') {
            try { [Console]::Write([string][char]27 + '[3J') } catch { }
        }
    }
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    [System.GC]::Collect()
    Write-Verbose ('PowerShell session cleared: {0} global variable(s) removed, history, errors and screen cleared.' -f $removed)
}

function Disconnect-PCloudSession {
    <#
    .SYNOPSIS
        Logs out: signs out of Privilege Cloud (tokens disposed) and clears this PowerShell window's
        session data with Clear-PCloudPowerShellSession.
    .EXAMPLE
        Disconnect-PCloudSession
    #>
    [CmdletBinding()]
    param([switch]$KeepScreen)
    Remove-PCloudSession -ClearPowerShellSession -KeepScreen:$KeepScreen
    Write-Host 'Logged out. The tokens and the data from this session were cleared from PowerShell.' -ForegroundColor Yellow
}
