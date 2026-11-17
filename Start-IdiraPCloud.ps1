#Requires -Version 5.1
<#
.SYNOPSIS
    Main entry point for the IdiraPCloud tools: sign in once, then choose what to work on.
.DESCRIPTION
    Opens a menu of the management areas (safes, accounts, platforms, PSM assignment, applications, Master Policy,
    system health, and a Reports menu with the account inventory and safe members reports). Each one opens its own menu; pressing Q there brings you back here.
    The sign-in is shared, so you are only asked once, and the token renews itself in the background.
    A failure in any area shows the error and returns you to this menu.
.EXAMPLE
    .\Start-IdiraPCloud.ps1
.EXAMPLE
    .\Start-IdiraPCloud.ps1 -Subdomain acme -AuthMethod Interactive
#>
[CmdletBinding()]
param(
    [string]$IdentityUrl,
    [string]$Subdomain,
    [string]$PCloudUrl,
    [System.Management.Automation.PSCredential]$Credential,
    [ValidateSet('ServiceUser', 'Interactive')][string]$AuthMethod,

    # -Log records the run (screen output and what you type at normal prompts) to Logs\ in the IdiraPCloud folder.
    [switch]$Log,
    [string]$LogPath
)

$scripts = Join-Path $PSScriptRoot 'Scripts'
. (Join-Path $scripts '_Common.ps1')
if ($Log -and -not $global:PCloudLogActive) { Invoke-PCloudLogged -ScriptPath $PSCommandPath -Bound $PSBoundParameters -Path $LogPath; return }

$areas = @(
    [pscustomobject]@{ Name = 'Safes'; Text = 'safes, safe members, permissions, managing CPM'; Script = 'Manage-Safes.ps1' },
    [pscustomobject]@{ Name = 'Accounts'; Text = 'find, add, update, link, delete, CPM actions, retrieve a password'; Script = 'Manage-Accounts.ps1' },
    [pscustomobject]@{ Name = 'Platforms'; Text = 'list, details, activate, deactivate, duplicate, export, import'; Script = 'Manage-Platforms.ps1' },
    [pscustomobject]@{ Name = 'PSM assignment'; Text = 'PSM servers and connectors per platform'; Script = 'Manage-PlatformPSM.ps1' },
    [pscustomobject]@{ Name = 'Applications'; Text = 'Credential Provider apps, authentication methods, safe access'; Script = 'Manage-Applications.ps1' },
    [pscustomobject]@{ Name = 'Master Policy'; Text = 'view, rotation intervals and exceptions, update intervals'; Script = 'Manage-MasterPolicy.ps1' },
    [pscustomobject]@{ Name = 'System health'; Text = 'component status (CPM, PSM, connectors)'; Script = 'Get-SystemHealth.ps1' },
    [pscustomobject]@{ Name = 'Reports'; Text = 'account inventory, safe members (to CSV)'; Script = '' }
)

$reports = @(
    [pscustomobject]@{ Name = 'Account inventory report'; Text = 'every account with CPM status, to CSV'; Script = 'Export-AccountInventory.ps1' },
    [pscustomobject]@{ Name = 'Safe members report'; Text = 'every safe member and permission, to CSV'; Script = 'Export-SafeMembersReport.ps1' }
)

function Invoke-AreaScript {
    # Runs one area's script. A failure is shown and the caller's menu comes back.
    param($Area)
    try {
        # Make sure the session is still usable (signs in again only if it can't be renewed).
        Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod
        & (Join-Path $scripts $Area.Script)
    } catch {
        Write-Host ''
        Write-Host ('{0} failed: {1}' -f $Area.Name, $_.Exception.Message) -ForegroundColor Red
        Write-Host 'Returning to the menu.' -ForegroundColor Yellow
    }
}

function Invoke-ReportsMenu {
    while ($true) {
        Write-Host ''
        Write-Host '-------------------- Reports --------------------' -ForegroundColor Cyan
        for ($i = 0; $i -lt $reports.Count; $i++) { Write-Host ('  {0}) {1,-25} {2}' -f ($i + 1), $reports[$i].Name, $reports[$i].Text) }
        Write-Host '  Q) Back to the main menu'
        $c = (Read-Host ('Enter 1-{0} or Q' -f $reports.Count)).Trim()
        if (-not $c -or $c -match '^(?i)(q|b)$') { return }
        $n = 0
        if (-not ([int]::TryParse($c, [ref]$n) -and $n -ge 1 -and $n -le $reports.Count)) { Write-Host 'Invalid choice.' -ForegroundColor Yellow; continue }
        Invoke-AreaScript -Area $reports[$n - 1]
    }
}

Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod

while ($true) {
    $s = Get-PCloudSession
    Write-Host ''
    Write-Host '==================== Idira Privilege Cloud ====================' -ForegroundColor Cyan
    if ($s) {
        $who = $s.User
        if (-not $who) { $who = $s.AuthMethod }
        Write-Host ('  {0}  |  signed in as {1}' -f $s.PCloudUrl, $who) -ForegroundColor DarkGray
    }
    for ($i = 0; $i -lt $areas.Count; $i++) { Write-Host ('  {0}) {1,-25} {2}' -f ($i + 1), $areas[$i].Name, $areas[$i].Text) }
    Write-Host '  S) Session details'
    Write-Host '  L) Log out (sign out, clear this PowerShell session, stay in the menu)'
    Write-Host '  X) Log out and quit'
    Write-Host '  Q) Quit (keep the session for this PowerShell window)'
    $c = (Read-Host ('Enter 1-{0}, S, L, X or Q' -f $areas.Count)).Trim()
    if ($c -match '^(?i)q$') { break }
    if ($c -match '^(?i)l$') { Disconnect-PCloudSession; continue }
    if ($c -match '^(?i)x$') { Disconnect-PCloudSession; break }
    if ($c -match '^(?i)s$') { Get-PCloudSession | Format-List | Out-String | Write-Host; continue }
    $n = 0
    if (-not ([int]::TryParse($c, [ref]$n) -and $n -ge 1 -and $n -le $areas.Count)) { Write-Host 'Invalid choice.' -ForegroundColor Yellow; continue }

    $area = $areas[$n - 1]
    if ($area.Name -eq 'Reports') { Invoke-ReportsMenu } else { Invoke-AreaScript -Area $area }
}
