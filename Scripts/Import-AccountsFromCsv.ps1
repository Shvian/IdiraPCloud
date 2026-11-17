#Requires -Version 5.1
<#
.SYNOPSIS
    Bulk-onboards accounts into Privilege Cloud from a CSV file.
.DESCRIPTION
    Required CSV columns: SafeName, PlatformId, UserName
    Optional columns:     Address, Name, SecretType, AutomaticManagement (true/false),
                          ManualManagementReason, RemoteMachines (semicolon separated),
                          plus any column prefixed with "prop_" which becomes a platform account
                          property (prop_LogonDomain -> LogonDomain, prop_Port -> Port).

    Secrets are never read from the CSV by default:
      (default)               Accounts are created without a secret; let the CPM reconcile them.
      -PromptForPasswords     No longer used: CSV onboarding never asks for passwords. Add an account
                              one at a time in Manage-Accounts.ps1 to type its password.
      -AllowPlainTextPasswordColumn
                              Reads a Password column. Plain-text passwords in files are a security
                              risk; use only if unavoidable and delete the file securely afterwards.
    If the CSV contains a non-empty Password column and -AllowPlainTextPasswordColumn is not set,
    the script stops before making any change.
    Writes a results CSV (never containing secrets) next to the input file. Supports -WhatIf.
.EXAMPLE
    .\Import-AccountsFromCsv.ps1 -Path .\accounts.csv -Subdomain acme
.EXAMPLE
    .\Import-AccountsFromCsv.ps1 -Path .\accounts.csv -SkipExisting
.EXAMPLE
    .\Import-AccountsFromCsv.ps1 -Path .\accounts.csv -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string]$ResultPath,
    [switch]$SkipExisting,
    [switch]$PromptForPasswords,
    [switch]$AllowPlainTextPasswordColumn,
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

$rows = @(Import-Csv -LiteralPath $Path)

$hasPasswordValues = @($rows | Where-Object { ($_.PSObject.Properties.Name -contains 'Password') -and $_.Password }).Count -gt 0
if ($hasPasswordValues -and -not $AllowPlainTextPasswordColumn) {
    throw ('{0} contains plain-text passwords. Remove the Password column and let the CPM reconcile, or pass -AllowPlainTextPasswordColumn if you accept the risk.' -f $Path)
}
if ($PromptForPasswords) {
    Write-Warning 'CSV onboarding does not ask for passwords. -PromptForPasswords is ignored; the accounts are created empty for the CPM to reconcile.'
}
if (-not $ResultPath) {
    $ResultPath = Join-Path (Get-PCloudOutputFolder) ('{0}-results-{1:yyyyMMdd-HHmmss}.csv' -f [System.IO.Path]::GetFileNameWithoutExtension($Path), (Get-Date))
} else { $ResultPath = Resolve-PCloudOutputPath $ResultPath }

$results = New-Object System.Collections.Generic.List[object]
$i = 0
foreach ($row in $rows) {
    $i++
    Write-Progress -Activity 'Onboarding accounts' -Status ("{0} of {1}: {2}@{3}" -f $i, $rows.Count, $row.UserName, $row.Address) -PercentComplete (($i / [Math]::Max($rows.Count, 1)) * 100)

    $status = 'Created'
    $accountId = $null
    $message = $null
    try {
        if (-not $row.SafeName -or -not $row.PlatformId -or -not $row.UserName) {
            throw 'Missing SafeName, PlatformId or UserName.'
        }

        if ($SkipExisting) {
            $search = (@($row.UserName, $row.Address) | Where-Object { $_ }) -join ' '
            $existing = @(Get-PCloudAccount -SafeName $row.SafeName -Search $search | Where-Object {
                    $_.userName -eq $row.UserName -and ([string]$_.address) -eq ([string]$row.Address)
                })
            if ($existing.Count -gt 0) {
                $results.Add([pscustomobject]@{ Row = $i; SafeName = $row.SafeName; UserName = $row.UserName; Address = $row.Address; Status = 'Skipped (exists)'; AccountId = $existing[0].id; Message = $null })
                continue
            }
        }

        $p = @{
            SafeName   = $row.SafeName
            PlatformId = $row.PlatformId
            UserName   = $row.UserName
        }
        if ($row.Address) { $p['Address'] = $row.Address }
        if ($row.Name) { $p['Name'] = $row.Name }
        if ($row.SecretType) { $p['SecretType'] = $row.SecretType }
        if ($AllowPlainTextPasswordColumn -and $row.Password) {
            $p['Secret'] = ConvertTo-SecureString -String $row.Password -AsPlainText -Force
            $row.Password = $null
        }
        if ($row.AutomaticManagement -and $row.AutomaticManagement -match '^(?i)(false|0|no)$') {
            $p['DisableAutomaticManagement'] = $true
            if ($row.ManualManagementReason) { $p['ManualManagementReason'] = $row.ManualManagementReason }
        }
        if ($row.RemoteMachines) {
            $p['RemoteMachines'] = @($row.RemoteMachines -split ';' | Where-Object { $_ })
            $p['AccessRestrictedToRemoteMachines'] = $true
        }
        $props = @{}
        foreach ($col in $row.PSObject.Properties) {
            if ($col.Name -like 'prop_*' -and $col.Value) { $props[$col.Name.Substring(5)] = $col.Value }
        }
        if ($props.Count -gt 0) { $p['PlatformAccountProperties'] = $props }

        if ($PSCmdlet.ShouldProcess(("{0}@{1} -> {2}" -f $row.UserName, $row.Address, $row.SafeName), 'Onboard account')) {
            $new = New-PCloudAccount @p -Confirm:$false
            $accountId = $new.id
        } else {
            $status = 'WhatIf'
        }
    } catch {
        $status = 'Failed'
        $message = $_.Exception.Message
        Write-Warning ("Row {0} ({1}@{2}): {3}" -f $i, $row.UserName, $row.Address, $message)
    }
    $results.Add([pscustomobject]@{ Row = $i; SafeName = $row.SafeName; UserName = $row.UserName; Address = $row.Address; Status = $status; AccountId = $accountId; Message = $message })
}
Write-Progress -Activity 'Onboarding accounts' -Completed

$results | Export-Csv -LiteralPath $ResultPath -NoTypeInformation -Encoding UTF8
$results | Group-Object Status | Select-Object Name, Count | Format-Table -AutoSize | Out-String | Write-Host
Write-Host "Results written to $ResultPath"
if ($hasPasswordValues) {
    Write-Warning ("{0} contains plain-text passwords. Delete it securely now (for example: cipher /w, or a secure-delete tool), and empty the Recycle Bin." -f $Path)
}
