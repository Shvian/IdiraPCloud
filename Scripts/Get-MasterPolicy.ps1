#Requires -Version 5.1
<#
.SYNOPSIS
    Shows the Privilege Cloud Master Policy (read only), with optional CSV or JSON export.
.DESCRIPTION
    Shows the Privilege Cloud master policy (Gen 3 master rotation policy: verify and change intervals,
    exception counts, created/updated by and when) as Setting/Value rows. Nothing is changed.
    Use Manage-MasterPolicy.ps1 to list platform exceptions or change the intervals.
    When run without -ExportCsv, -OutputPath, -JsonPath or -NoPrompt you are asked whether to save the
    result. Prompts for sign-in if there is no active session.
.EXAMPLE
    .\Get-MasterPolicy.ps1
.EXAMPLE
    .\Get-MasterPolicy.ps1 -ExportCsv
.EXAMPLE
    .\Get-MasterPolicy.ps1 -OutputPath .\master-policy.csv -JsonPath .\master-policy.json
.EXAMPLE
    $policy = .\Get-MasterPolicy.ps1 -PassThru -NoPrompt
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$ExportCsv,
    [string]$JsonPath,
    [string]$Filter,
    [switch]$PassThru,
    [switch]$NoPrompt,

    # Connection (optional; prompts if there is no active session)
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
. (Join-Path $PSScriptRoot '_Menu.ps1')
Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod

$policy = Get-PCloudMasterPolicy
if ($null -eq $policy) { throw 'The Master Policy request returned nothing.' }

$rows = @(ConvertTo-PCloudFlatSetting -InputObject $policy)
if ($Filter) { $rows = @($rows | Where-Object { $_.Setting -like "*$Filter*" }) }

$rows | Format-Table Setting, Value -AutoSize -Wrap | Out-String | Write-Host
Write-Host ('{0} Master Policy setting(s).' -f $rows.Count)

$interactive = -not $NoPrompt -and -not $ExportCsv -and -not $OutputPath -and -not $JsonPath -and -not $PassThru
if ($interactive) {
    $OutputPath = Read-OutputChoice -Action 'MasterPolicy'
    if (Read-YesNo 'Also save the full policy as JSON?') {
        $j = Read-Host 'JSON file path (leave blank for an automatic name)'
        if ($j) { $JsonPath = $j.Trim('"') } else { $JsonPath = New-OutputPath -Action 'MasterPolicy' -Extension 'json' }
    }
}
if ($ExportCsv -and -not $OutputPath) { $OutputPath = New-OutputPath -Action 'MasterPolicy' }

Save-Results -Rows $rows -Path $OutputPath
if ($JsonPath) {
    $full = Resolve-PCloudOutputPath $JsonPath
    $json = ConvertTo-Json -InputObject $policy -Depth 20
    [System.IO.File]::WriteAllText($full, $json, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ('Master Policy JSON written to {0}' -f $full)
}
if ($PassThru) { return $policy }
