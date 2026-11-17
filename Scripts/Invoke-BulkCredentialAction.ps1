#Requires -Version 5.1
<#
.SYNOPSIS
    Submits CPM Change, Verify or Reconcile for many accounts at once.
.DESCRIPTION
    Select accounts by safe, search text, explicit IDs, or only those whose last CPM status
    is "failure". Each account is marked for the action; the CPM processes it on its next cycle.
    Supports -WhatIf and -Confirm.
.EXAMPLE
    .\Invoke-BulkCredentialAction.ps1 -Action Verify -SafeName 'Linux-Root' -WhatIf
.EXAMPLE
    .\Invoke-BulkCredentialAction.ps1 -Action Reconcile -SafeName 'Win-Servers' -FailedOnly
.EXAMPLE
    .\Invoke-BulkCredentialAction.ps1 -Action Change -AccountId 12_34,12_35
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Change', 'Verify', 'Reconcile')][string]$Action,
    [string]$SafeName,
    [string]$Search,
    [string[]]$AccountId,
    [switch]$FailedOnly,
    [int]$DelayMilliseconds = 200,
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

if (-not $SafeName -and -not $Search -and -not $AccountId) {
    throw 'Select accounts with -SafeName, -Search or -AccountId.'
}

if ($AccountId) {
    $accounts = @($AccountId | ForEach-Object { Get-PCloudAccount -Id $_ })
} else {
    $p = @{}
    if ($SafeName) { $p['SafeName'] = $SafeName }
    if ($Search) { $p['Search'] = $Search }
    $accounts = @(Get-PCloudAccount @p)
}
if ($FailedOnly) {
    $accounts = @($accounts | Where-Object { $_.secretManagement -and $_.secretManagement.status -eq 'failure' })
}
Write-Host ("{0} account(s) selected for {1}." -f $accounts.Count, $Action)

$results = foreach ($a in $accounts) {
    $label = '{0} ({1}@{2}, safe {3})' -f $a.id, $a.userName, $a.address, $a.safeName
    if (-not $PSCmdlet.ShouldProcess($label, $Action)) { continue }
    $ok = $true
    $msg = $null
    try {
        switch ($Action) {
            'Change' { Invoke-PCloudAccountChange -Id $a.id -Confirm:$false | Out-Null }
            'Verify' { Invoke-PCloudAccountVerify -Id $a.id -Confirm:$false | Out-Null }
            'Reconcile' { Invoke-PCloudAccountReconcile -Id $a.id -Confirm:$false | Out-Null }
        }
    } catch {
        $ok = $false
        $msg = $_.Exception.Message
        Write-Warning "$label : $msg"
    }
    [pscustomobject]@{ AccountId = $a.id; UserName = $a.userName; Address = $a.address; SafeName = $a.safeName; Action = $Action; Submitted = $ok; Message = $msg }
    if ($DelayMilliseconds -gt 0) { Start-Sleep -Milliseconds $DelayMilliseconds }
}

$results = @($results)
$results | Format-Table AccountId, UserName, Address, SafeName, Submitted, Message -AutoSize
Write-Host ("Submitted: {0}  Failed: {1}" -f @($results | Where-Object { $_.Submitted }).Count, @($results | Where-Object { -not $_.Submitted }).Count)
