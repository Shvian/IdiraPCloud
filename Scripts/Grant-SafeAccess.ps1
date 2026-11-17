#Requires -Version 5.1
<#
.SYNOPSIS
    Grants (or updates) a user, group or role's access to one or more safes using a permission preset.
.DESCRIPTION
    If the member already exists on a safe, its permissions are replaced with the preset
    (unless -SkipExisting). Use -Revoke to remove the member instead. Supports -WhatIf.
    Presets: ConnectOnly, ReadOnly, Approver, AccountsManager, Full (see Get-PCloudSafePermissionSet).
.EXAMPLE
    .\Grant-SafeAccess.ps1 -SafeName 'Linux-Root','Linux-App' -MemberName 'unix-admins' -MemberType Group -Preset AccountsManager
.EXAMPLE
    .\Grant-SafeAccess.ps1 -SafeSearch 'Prod' -MemberName 'jdoe@acme.com' -Preset ReadOnly -ExpirationDate (Get-Date).AddDays(7)
.EXAMPLE
    .\Grant-SafeAccess.ps1 -SafeName 'Linux-Root' -MemberName 'jdoe@acme.com' -Revoke
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string[]]$SafeName,
    [string]$SafeSearch,
    [Parameter(Mandatory = $true)][string]$MemberName,
    [ValidateSet('Auto', 'User', 'Group', 'Role')][string]$MemberType = 'Auto',
    [ValidateSet('ConnectOnly', 'ReadOnly', 'Approver', 'AccountsManager', 'Full')][string]$Preset = 'ReadOnly',
    [hashtable]$Override,
    [string]$SearchIn,
    [datetime]$ExpirationDate,
    [switch]$SkipExisting,
    [switch]$Revoke,
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
Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod

$targets = @()
if ($SafeName) { $targets += $SafeName }
if ($SafeSearch) { $targets += @(Get-PCloudSafe -Search $SafeSearch | ForEach-Object { $_.safeName }) }
$targets = @($targets | Sort-Object -Unique)
if ($targets.Count -eq 0) { throw 'No safes selected. Use -SafeName or -SafeSearch.' }

$perm = Get-PCloudSafePermissionSet -Preset $Preset -Override $Override

$results = foreach ($safe in $targets) {
    $outcome = $null
    $msg = $null
    try {
        $existing = $null
        try { $existing = Get-PCloudSafeMember -SafeName $safe -MemberName $MemberName } catch { $existing = $null }

        if ($Revoke) {
            if (-not $existing) { $outcome = 'Not a member' }
            elseif ($PSCmdlet.ShouldProcess("$MemberName on $safe", 'Remove member')) {
                Remove-PCloudSafeMember -SafeName $safe -MemberName $MemberName -Confirm:$false
                $outcome = 'Removed'
            } else { $outcome = 'WhatIf' }
        } elseif ($existing) {
            if ($SkipExisting) { $outcome = 'Skipped (exists)' }
            elseif ($PSCmdlet.ShouldProcess("$MemberName on $safe", "Set permissions ($Preset)")) {
                $sp = @{ SafeName = $safe; MemberName = $MemberName; Permission = $perm; Confirm = $false }
                if ($PSBoundParameters.ContainsKey('ExpirationDate')) { $sp['ExpirationDate'] = $ExpirationDate }
                Set-PCloudSafeMember @sp | Out-Null
                $outcome = 'Updated'
            } else { $outcome = 'WhatIf' }
        } else {
            if ($PSCmdlet.ShouldProcess("$MemberName on $safe", "Add member ($Preset)")) {
                $ap = @{ SafeName = $safe; MemberName = $MemberName; MemberType = $MemberType; Permission = $perm; Confirm = $false }
                if ($SearchIn) { $ap['SearchIn'] = $SearchIn }
                if ($PSBoundParameters.ContainsKey('ExpirationDate')) { $ap['ExpirationDate'] = $ExpirationDate }
                Add-PCloudSafeMember @ap | Out-Null
                $outcome = 'Added'
            } else { $outcome = 'WhatIf' }
        }
    } catch {
        $outcome = 'Failed'
        $msg = $_.Exception.Message
        Write-Warning "$safe : $msg"
    }
    [pscustomobject]@{ SafeName = $safe; MemberName = $MemberName; Preset = $Preset; Result = $outcome; Message = $msg }
}

@($results) | Format-Table -AutoSize
