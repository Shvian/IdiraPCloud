#Requires -Version 5.1
<#
.SYNOPSIS
    Exports an account inventory (with CPM status) to CSV.
.DESCRIPTION
    One row per account with safe, platform, address, user, CPM management state, last
    status and the last modified / last verified / last reconciled times.
.EXAMPLE
    .\Export-AccountInventory.ps1 -OutputPath .\inventory.csv
.EXAMPLE
    .\Export-AccountInventory.ps1 -SafeName 'Linux-Root' -OutputPath .\linux.csv -FailedOnly
#>
[CmdletBinding()]
param(
    # Default: CSVs\PCloud-AccountInventory-<timestamp>.csv in the IdiraPCloud folder. A bare file name also goes there.
    [string]$OutputPath,
    [string]$SafeName,
    [string]$Search,
    [switch]$FailedOnly,
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
if ($OutputPath) { $OutputPath = Resolve-PCloudOutputPath $OutputPath } else { $OutputPath = New-PCloudOutputFile -Name 'AccountInventory' }
Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod

$p = @{}
if ($SafeName) { $p['SafeName'] = $SafeName }
if ($Search) { $p['Search'] = $Search }

$rows = foreach ($a in (Get-PCloudAccount @p)) {
    $sm = $a.secretManagement
    $status = $null; $auto = $null; $reason = $null; $lastMod = $null; $lastVerify = $null; $lastRecon = $null; $statusTime = $null
    if ($sm) {
        $status = $sm.status
        $auto = $sm.automaticManagementEnabled
        $reason = $sm.manualManagementReason
        $lastMod = ConvertFrom-PCloudUnixTime $sm.lastModifiedTime
        $lastVerify = ConvertFrom-PCloudUnixTime $sm.lastVerifiedTime
        $lastRecon = ConvertFrom-PCloudUnixTime $sm.lastReconciledTime
    }
    if ($FailedOnly -and $status -ne 'failure') { continue }
    [pscustomobject]@{
        Id                   = $a.id
        Name                 = $a.name
        SafeName             = $a.safeName
        PlatformId           = $a.platformId
        Address              = $a.address
        UserName             = $a.userName
        SecretType           = $a.secretType
        AutomaticManagement  = $auto
        ManualReason         = $reason
        CPMStatus            = $status
        LastModified         = $lastMod
        LastVerified         = $lastVerify
        LastReconciled       = $lastRecon
        Created              = ConvertFrom-PCloudUnixTime $a.createdTime
        CategoryModified     = ConvertFrom-PCloudUnixTime $a.categoryModificationTime
    }
}

$rows = @($rows)
$rows | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host ("Exported {0} account(s) to {1}" -f $rows.Count, (Resolve-Path -LiteralPath $OutputPath))
