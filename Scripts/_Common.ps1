#Requires -Version 5.1
# Shared by the task scripts: loads the module and connects if no session exists yet.

$modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'IdiraPCloud\IdiraPCloud.psd1'
Import-Module $modulePath -Force:$false -ErrorAction Stop -Verbose:$false

# -Verbose on a script (or on Start-IdiraPCloud.ps1) traces every API call the module sends, with
# tokens, cookies and credentials redacted. Without -Verbose the trace is switched off again.
Set-PCloudApiTrace -Enabled ($VerbosePreference -eq [System.Management.Automation.ActionPreference]::Continue)

# ------------------------------------------------------------------ output folder
# Every file the scripts write (CSV results, reports, JSON, platform packages) defaults to the CSVs folder
# in the main IdiraPCloud folder. A bare file name goes there too; a path with a folder in it is used as given.
$script:PCloudOutputFolder = Join-Path (Split-Path -Parent $PSScriptRoot) 'CSVs'
$script:PCloudLogFolder = Join-Path (Split-Path -Parent $PSScriptRoot) 'Logs'

function Get-PCloudSecureFolder {
    # A folder in the main IdiraPCloud folder (CSVs, Logs), created on first use. New folders are limited to
    # the current user, SYSTEM and Administrators, since what goes in them describes privileged access.
    param([string]$Name)
    $dir = Join-Path (Split-Path -Parent $PSScriptRoot) $Name
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $dir -Force
        try {
            $acl = New-Object System.Security.AccessControl.DirectorySecurity
            $acl.SetAccessRuleProtection($true, $false)
            $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
            $prop = [System.Security.AccessControl.PropagationFlags]::None
            $allow = [System.Security.AccessControl.AccessControlType]::Allow
            $full = [System.Security.AccessControl.FileSystemRights]::FullControl
            $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            foreach ($sid in @($me, (New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'), (New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'))) {
                $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $full, $inherit, $prop, $allow)))
            }
            Set-Acl -LiteralPath $dir -AclObject $acl
        } catch { Write-Verbose ('Could not restrict {0}: {1}' -f $dir, $_.Exception.Message) }
    }
    return $dir
}

function Get-PCloudOutputFolder {
    return (Get-PCloudSecureFolder -Name 'CSVs')
}

function Resolve-PCloudOutputPath {
    # Blank -> '' ; bare file name -> CSVs folder ; anything with a folder -> full path as given.
    param([string]$Path)
    if (-not $Path) { return '' }
    $p = $Path.Trim().Trim('"')
    if ($p -notmatch '[\\/]' -and $p -notmatch '^[A-Za-z]:') { return (Join-Path (Get-PCloudOutputFolder) $p) }
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p)
}

function New-PCloudOutputFile {
    # A timestamped file name in the CSVs folder.
    param([string]$Name, [string]$Extension = 'csv')
    return (Join-Path (Get-PCloudOutputFolder) ('PCloud-{0}-{1:yyyyMMdd-HHmmss}.{2}' -f $Name, (Get-Date), $Extension))
}

# ------------------------------------------------------------------ -Log
function Invoke-PCloudLogged {
    <#
        -Log on any script: runs the script again inside a PowerShell transcript and stops the transcript when
        it ends, however it ends (Q, an error, Ctrl+C or the idle sign-out). The log goes to
        Logs\IdiraPCloud-<script>-<timestamp>.log in the main IdiraPCloud folder, or to -LogPath (a bare file
        name also goes to Logs). Scripts started from Start-IdiraPCloud.ps1 are recorded in the same log.
        The transcript records what is shown on screen and what you type at normal prompts. Masked prompts
        (passwords, MFA codes) are not recorded, tokens never appear, and the -Verbose API trace is redacted.
    #>
    param([string]$ScriptPath, [hashtable]$Bound, [string]$Path)
    $name = [System.IO.Path]::GetFileNameWithoutExtension($ScriptPath)
    if ($Path) {
        $p = $Path.Trim().Trim('"')
        if ($p -notmatch '[\\/]' -and $p -notmatch '^[A-Za-z]:') { $file = Join-Path (Get-PCloudSecureFolder -Name 'Logs') $p }
        else { $file = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p) }
    } else {
        $file = Join-Path (Get-PCloudSecureFolder -Name 'Logs') ('IdiraPCloud-{0}-{1:yyyyMMdd-HHmmss}.log' -f $name, (Get-Date))
    }
    $started = $false
    try {
        $null = Start-Transcript -LiteralPath $file -Append -ErrorAction Stop
        $started = $true
        Write-Host ('Logging this session to {0}' -f $file) -ForegroundColor DarkGray
    } catch {
        Write-Warning ('Could not start the log ({0}). Continuing without it.' -f $_.Exception.Message)
    }
    $global:PCloudLogActive = $true
    try {
        & $ScriptPath @Bound
    } finally {
        $global:PCloudLogActive = $false
        if ($started) {
            try { $null = Stop-Transcript } catch { }
            Write-Host ('Log saved to {0}' -f $file) -ForegroundColor DarkGray
        }
    }
}

function Test-PCloudSessionUsable {
    # A session is usable if it exists, has not been idle past the limit, and either renews itself or
    # its token has not expired.
    $null = Invoke-PCloudIdleCheck
    $s = Get-PCloudSession
    if (-not $s) { return $false }
    if ($s.CanRefresh) { return $true }
    if ($null -ne $s.ExpiresAt -and $s.ExpiresAt -le (Get-Date)) {
        Write-Warning 'The current session token has expired.'
        return $false
    }
    return $true
}

function Connect-PCloudIfNeeded {
    <#
        Reuses an active session. Otherwise prompts for whatever is missing:
        the sign-in method, the subdomain (via New-PCloudSession), and the credential or MFA steps.
    #>
    param(
        [string]$IdentityUrl,
        [string]$Subdomain,
        [string]$PCloudUrl,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$AuthMethod
    )
    if (Test-PCloudSessionUsable) {
        Write-Verbose ('Using the existing session for {0}' -f (Get-PCloudSession).PCloudUrl)
        return
    }

    Write-Host 'No active Privilege Cloud session. Please sign in.' -ForegroundColor Yellow
    if (-not $AuthMethod) {
        Write-Host '  1) Interactive - your Identity user, with MFA'
        Write-Host '  2) Service user - OAuth2 client credentials'
        while (-not $AuthMethod) {
            $choice = Read-Host 'Choose sign-in method [1]'
            if (-not $choice -or $choice -eq '1') { $AuthMethod = 'Interactive' }
            elseif ($choice -eq '2') { $AuthMethod = 'ServiceUser' }
            else { Write-Host 'Enter 1 or 2.' }
        }
    }

    $p = @{ AuthMethod = $AuthMethod }
    if ($IdentityUrl) { $p['IdentityUrl'] = $IdentityUrl }
    if ($Credential) { $p['Credential'] = $Credential }
    if ($PCloudUrl) { $p['PCloudUrl'] = $PCloudUrl }
    if ($Subdomain) { $p['Subdomain'] = $Subdomain }
    # New-PCloudSession prompts for the subdomain if missing, then for the credential (ServiceUser)
    # or the user name and each MFA step (Interactive).
    New-PCloudSession @p
}

function Test-PCloudTimedInput {
    # Timed prompts need a real console; ISE, VS Code and redirected input use the normal Read-Host.
    if ($Host.Name -ne 'ConsoleHost') { return $false }
    try { if ([Console]::IsInputRedirected) { return $false } } catch { return $false }
    return $true
}

function Read-Host {
    <#
        Replaces Read-Host for the task scripts so that waiting at a prompt counts toward the idle sign-out
        (Set-PCloudIdleTimeout, default 15 minutes). Each key typed is activity. When the limit passes with no
        input, the session is signed out (tokens disposed) and the running script stops. Under Start-IdiraPCloud.ps1
        you land back on the main menu, which asks you to sign in again when you pick an area.
        Masked prompts (-AsSecureString) and prompts with no session to protect use the built-in Read-Host.
    #>
    [CmdletBinding()]
    param([Parameter(Position = 0, ValueFromRemainingArguments = $true)][object]$Prompt, [switch]$AsSecureString)
    $text = ''
    if ($null -ne $Prompt) { $text = (@($Prompt) | ForEach-Object { [string]$_ }) -join ' ' }
    $left = Get-PCloudIdleSecondsLeft
    # Already past the limit with a session still loaded: sign out and stop before showing the prompt.
    if ($null -ne $left -and $left -eq 0) { $null = Invoke-PCloudIdleCheck; exit }
    # No session to protect (none yet, or already signed out with -1): a normal prompt, so sign-in works.
    if ($AsSecureString -or $null -eq $left -or $left -lt 0 -or -not (Test-PCloudTimedInput)) {
        $p = @{}
        if ($text) { $p['Prompt'] = $text }
        if ($AsSecureString) { $p['AsSecureString'] = $true }
        $r = Microsoft.PowerShell.Utility\Read-Host @p
        Register-PCloudActivity
        return $r
    }
    if ($text) { Write-Host ('{0}: ' -f $text) -NoNewline }
    $sb = New-Object System.Text.StringBuilder
    while ($true) {
        if ([Console]::KeyAvailable) {
            $k = [Console]::ReadKey($true)
            Register-PCloudActivity
            if ($k.Key -eq [ConsoleKey]::Enter) { Write-Host ''; return $sb.ToString() }
            if ($k.Key -eq [ConsoleKey]::Backspace) {
                if ($sb.Length -gt 0) { $sb.Length = $sb.Length - 1; Write-Host ([string][char]8 + ' ' + [string][char]8) -NoNewline }
                continue
            }
            if ($k.KeyChar -and -not [char]::IsControl($k.KeyChar)) { [void]$sb.Append($k.KeyChar); Write-Host $k.KeyChar -NoNewline }
            continue
        }
        $left = Get-PCloudIdleSecondsLeft
        if ($null -ne $left -and $left -le 0) {
            # Signed out here, or already by the background timer (-1). Stop the script either way.
            $null = Invoke-PCloudIdleCheck
            Write-Host ''
            exit
        }
        Start-Sleep -Milliseconds 100
    }
}
