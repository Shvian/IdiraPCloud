#Requires -Version 5.1
<#
.SYNOPSIS
    Shows Privilege Cloud component health (CPM, PSM, Credential Providers, PTA): the summary per component
    type, then every individual component with its user, version, IP, logon state and last logon.
    Disconnected components are highlighted. -SummaryOnly skips the per-component details.
.EXAMPLE
    .\Get-SystemHealth.ps1
.EXAMPLE
    .\Get-SystemHealth.ps1 -OutputPath .\health.csv
.EXAMPLE
    .\Get-SystemHealth.ps1 -SummaryOnly
#>
[CmdletBinding()]
param(
    [switch]$SummaryOnly,
    # Kept for compatibility: details are now shown by default.
    [switch]$Detailed,
    [string]$OutputPath,
    [string]$IdentityUrl,
    [string]$Subdomain,
    [string]$PCloudUrl,
    [System.Management.Automation.PSCredential]$Credential,
    [ValidateSet('ServiceUser', 'Interactive')][string]$AuthMethod,

    # -Log records the run (screen output and what you type at normal prompts) to Logs\ in the IdiraPCloud folder.
    [switch]$Log,
    [string]$LogPath
)

. (Join-Path $PSScriptRoot '_Common.ps1')
if ($Log -and -not $global:PCloudLogActive) { Invoke-PCloudLogged -ScriptPath $PSCommandPath -Bound $PSBoundParameters -Path $LogPath; return }
if ($OutputPath) { $OutputPath = Resolve-PCloudOutputPath $OutputPath }
Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod

$summary = @(Get-PCloudSystemHealth)
Write-Host ''
Write-Host 'Component summary:'
$summary | Select-Object ComponentID, ComponentName, ConnectedComponentCount, DisconnectedComponentCount | Format-Table -AutoSize | Out-String | Write-Host

if (-not $SummaryOnly) {
    $details = foreach ($c in $summary) {
        if (-not $c.ComponentID) { continue }
        try {
            foreach ($d in @(Get-PCloudSystemHealth -ComponentId $c.ComponentID)) {
                [pscustomobject]@{
                    ComponentType    = $c.ComponentID
                    ComponentName    = $c.ComponentName
                    Status           = $(if ($d.IsLoggedOn) { 'Online' } else { 'OFFLINE' })
                    ComponentUserName = $d.ComponentUserName
                    ComponentVersion = $d.ComponentVersion
                    IP               = $d.IP
                    IsLoggedOn       = $d.IsLoggedOn
                    LastLogonDate    = ConvertFrom-PCloudUnixTime $d.LastLogonDate
                }
            }
        } catch {
            Write-Warning ("{0}: {1}" -f $c.ComponentID, $_.Exception.Message)
        }
    }
    $details = @($details)
    Write-Host 'Component details:'
    if ($details.Count -eq 0) { Write-Host '  No component details returned.' }
    else { $details | Sort-Object ComponentType, ComponentUserName | Format-Table ComponentType, ComponentUserName, Status, ComponentVersion, IP, LastLogonDate -AutoSize | Out-String | Write-Host }
    $down = @($details | Where-Object { -not $_.IsLoggedOn })
    if ($down.Count -gt 0) {
        Write-Warning ("{0} component(s) are not logged on:" -f $down.Count)
        foreach ($x in $down) { Write-Host ('  {0}  {1}  (last logon {2})' -f $x.ComponentType, $x.ComponentUserName, $x.LastLogonDate) -ForegroundColor Red }
    } else {
        Write-Host ('All {0} component(s) are online.' -f $details.Count) -ForegroundColor Green
    }
    if ($OutputPath) {
        $details | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Host "Details written to $OutputPath"
    }
} elseif ($OutputPath) {
    $summary | Select-Object ComponentID, ComponentName, ConnectedComponentCount, DisconnectedComponentCount | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "Summary written to $OutputPath"
}
