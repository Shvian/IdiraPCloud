#Requires -Version 5.1
# Idle sign-out: the session is removed (tokens disposed) after a period with no API call and no user input.
#   - Every API call counts as activity, and so does every key typed at a script prompt (_Common.ps1).
#   - A background timer signs out at the PowerShell prompt too, after a script has finished.
#   - The next API call after the limit also signs out, as a backstop when the timer could not run.
# Default 15 minutes; Set-PCloudIdleTimeout -Minutes 0 turns it off for the current window.

$script:PCloudIdle = @{
    Minutes      = 15
    LastActivity = [DateTime]::UtcNow
    SignedOut    = $false
    Timer        = $null
    SourceId     = 'IdiraPCloud.IdleTimer'
}

function Register-PCloudActivity {
    <#
    .SYNOPSIS
        Records user or script activity, which restarts the idle sign-out countdown.
    #>
    [CmdletBinding()]
    param()
    $script:PCloudIdle.LastActivity = [DateTime]::UtcNow
}

function Get-PCloudIdleSecondsLeft {
    <#
    .SYNOPSIS
        Seconds left before the idle sign-out. $null when there is no session or the timeout is off;
        -1 when the session was just signed out for inactivity.
    #>
    [CmdletBinding()]
    param()
    if ($script:PCloudIdle.SignedOut -and $null -eq $script:PCloudSession) { return -1 }
    if ($null -eq $script:PCloudSession -or $script:PCloudIdle.Minutes -le 0) { return $null }
    return [Math]::Max(0, ($script:PCloudIdle.Minutes * 60) - ([DateTime]::UtcNow - $script:PCloudIdle.LastActivity).TotalSeconds)
}

function Invoke-PCloudIdleCheck {
    <#
    .SYNOPSIS
        Signs out if the session has been idle past the limit. Returns $true when it signed out.
    #>
    [CmdletBinding()]
    param()
    if ($null -eq $script:PCloudSession -or $script:PCloudIdle.Minutes -le 0) { return $false }
    $idle = ([DateTime]::UtcNow - $script:PCloudIdle.LastActivity).TotalSeconds
    if ($idle -lt ($script:PCloudIdle.Minutes * 60)) { return $false }
    Remove-PCloudSession
    $script:PCloudIdle.SignedOut = $true
    Write-Host ''
    Write-Host ('Signed out of Privilege Cloud after {0} minutes of inactivity. The tokens were cleared from memory; sign in again to continue.' -f $script:PCloudIdle.Minutes) -ForegroundColor Yellow
    return $true
}

function Start-PCloudIdleTimer {
    # Checks every 30 seconds. Runs while PowerShell is waiting at its prompt, and between script statements.
    if ($script:PCloudIdle.Minutes -le 0) { return }
    if ($null -ne $script:PCloudIdle.Timer) { return }
    try {
        Stop-PCloudIdleTimer
        $t = New-Object System.Timers.Timer 30000
        $t.AutoReset = $true
        $null = Register-ObjectEvent -InputObject $t -EventName Elapsed -SourceIdentifier $script:PCloudIdle.SourceId -Action {
            $m = Get-Module IdiraPCloud | Select-Object -First 1
            if ($m) { $null = & $m { Invoke-PCloudIdleCheck } }
        }
        $t.Start()
        $script:PCloudIdle.Timer = $t
    } catch {
        Write-Verbose ('Idle timer not started ({0}); the idle limit is still enforced on the next call or prompt.' -f $_.Exception.Message)
    }
}

function Stop-PCloudIdleTimer {
    $id = $script:PCloudIdle.SourceId
    try { Unregister-Event -SourceIdentifier $id -ErrorAction SilentlyContinue } catch { }
    try { Get-Job -Name $id -ErrorAction SilentlyContinue | Remove-Job -Force -ErrorAction SilentlyContinue } catch { }
    if ($null -ne $script:PCloudIdle.Timer) {
        try { $script:PCloudIdle.Timer.Stop(); $script:PCloudIdle.Timer.Dispose() } catch { }
        $script:PCloudIdle.Timer = $null
    }
}

function Set-PCloudIdleTimeout {
    <#
    .SYNOPSIS
        Sets the idle sign-out limit for this PowerShell window (default 15 minutes; 0 turns it off).
    .EXAMPLE
        Set-PCloudIdleTimeout -Minutes 10
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateRange(0, 1440)][int]$Minutes)
    $script:PCloudIdle.Minutes = $Minutes
    Register-PCloudActivity
    if ($Minutes -le 0) { Stop-PCloudIdleTimer }
    elseif ($null -ne $script:PCloudSession) { Start-PCloudIdleTimer }
}

function Get-PCloudIdleTimeout {
    <#
    .SYNOPSIS
        The idle sign-out limit in minutes (0 = off) and the time left for the current session.
    #>
    [CmdletBinding()]
    param()
    $left = Get-PCloudIdleSecondsLeft
    [pscustomobject]@{
        Minutes     = $script:PCloudIdle.Minutes
        SecondsLeft = $(if ($null -eq $left) { $null } else { [Math]::Max(0, [int]$left) })
        TimerActive = ($null -ne $script:PCloudIdle.Timer)
    }
}
