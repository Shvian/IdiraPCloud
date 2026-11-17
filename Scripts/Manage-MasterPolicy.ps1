#Requires -Version 5.1
<#
.SYNOPSIS
    Privilege Cloud master policy (the Gen 3 master rotation policy): view it, list platform exceptions,
    and update the verify and change intervals.
.DESCRIPTION
    Actions:
      GetRotationPolicy      The master rotation policy (GET /api/platforms/master-rotation-policy): verify and
                             change intervals in days, exception counts, and who changed it and when.
      GetRotationExceptions  Platforms whose intervals differ from the master rotation policy
                             (GET /api/platforms/master-rotation-policy/exceptions).
      UpdateRotationPolicy   Change the verify and/or change interval (PATCH). Values are days, 1-365, or "none"
                             to clear the interval (sent as null). With no values given, a menu shows the current
                             intervals; if the update fails, the failing change is dropped and the menu returns
                             with the rest still pending.

    Run without -Action to pick from a menu. Prompts for sign-in if there is no active session.
    The menu loops until you choose Q; any failure returns you to the menu. Updates support -WhatIf.
    CSV export for the Get actions: -ExportCsv or -OutputPath <file>, or answer the prompt in the menu.
.EXAMPLE
    .\Manage-MasterPolicy.ps1
.EXAMPLE
    .\Manage-MasterPolicy.ps1 -Action GetRotationPolicy
.EXAMPLE
    .\Manage-MasterPolicy.ps1 -Action UpdateRotationPolicy -ChangeInterval 90 -VerifyInterval 7
.EXAMPLE
    .\Manage-MasterPolicy.ps1 -Action GetRotationExceptions -ExportCsv
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ArgumentCompleter({ param($c, $p, $w) 'GetRotationPolicy', 'GetRotationExceptions', 'UpdateRotationPolicy', 'GetMasterPolicy' | Where-Object { $_ -like "$w*" } })]
    [string]$Action,
    [string]$OutputPath,
    [switch]$ExportCsv,
    # Days 1-365, or 'none' to clear (null).
    [string]$VerifyInterval,
    [string]$ChangeInterval,

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

$actions = @('GetRotationPolicy', 'GetRotationExceptions', 'UpdateRotationPolicy')
$actionHelp = @{
    GetRotationPolicy     = 'verify and change intervals, exception counts'
    GetRotationExceptions = 'platforms with their own intervals'
    UpdateRotationPolicy  = 'change the verify and/or change interval'
}
$readActions = @('GetRotationPolicy', 'GetRotationExceptions')
if ($Action -eq 'GetMasterPolicy') { $Action = 'GetRotationPolicy' }
if ($Action) {
    $m = @($actions | Where-Object { $_ -eq $Action })
    if ($m.Count -eq 0) { throw ("-Action must be one of: {0}" -f ($actions -join ', ')) }
    $Action = $m[0]
}
$ScriptCmdlet = $PSCmdlet

function ConvertTo-IntervalValue {
    # 'none' -> @{ IsNull = $true }; 1-365 -> @{ Days = n }. Throws on anything else.
    param([string]$Value, [string]$Name)
    $v = ([string]$Value).Trim()
    if ($v -match '^(?i)(none|null|clear|off)$') { return @{ IsNull = $true; Days = $null } }
    $n = 0
    if ([int]::TryParse($v, [ref]$n) -and $n -ge 1 -and $n -le 365) { return @{ IsNull = $false; Days = $n } }
    throw ("{0} must be a number of days from 1 to 365, or 'none'." -f $Name)
}

function Format-Interval {
    param($Days)
    if ($null -eq $Days -or [string]$Days -eq '') { return '(none)' }
    return ('{0} day(s)' -f $Days)
}

function Format-RotationRow {
    param($P)
    [pscustomobject]@{
        VerifyInterval                = Get-NestedValue $P 'verifyInterval'
        ChangeInterval                = Get-NestedValue $P 'changeInterval'
        VerifyIntervalExceptionsCount = Get-NestedValue $P 'verifyIntervalExceptionsCount'
        ChangeIntervalExceptionsCount = Get-NestedValue $P 'changeIntervalExceptionsCount'
        UpdatedAt                     = Get-NestedValue $P 'updatedAt'
        UpdatedBy                     = Get-NestedValue $P 'updatedBy'
        CreatedAt                     = Get-NestedValue $P 'createdAt'
        CreatedBy                     = Get-NestedValue $P 'createdBy'
    }
}

function Show-RotationPolicy {
    param($P)
    $r = Format-RotationRow $P
    Write-Host ''
    Write-Host 'Master rotation policy:'
    Write-Host ('  Verify interval:  {0}   ({1} platform exception(s))' -f (Format-Interval $r.VerifyInterval), $r.VerifyIntervalExceptionsCount)
    Write-Host ('  Change interval:  {0}   ({1} platform exception(s))' -f (Format-Interval $r.ChangeInterval), $r.ChangeIntervalExceptionsCount)
    if ($r.UpdatedAt -or $r.UpdatedBy) { Write-Host ('  Last updated:     {0} by {1}' -f $r.UpdatedAt, $r.UpdatedBy) }
    if ($r.CreatedAt -or $r.CreatedBy) { Write-Host ('  Created:          {0} by {1}' -f $r.CreatedAt, $r.CreatedBy) }
    return $r
}

function Invoke-RotationUpdate {
    # Sends the pending changes. $Changes keys: verifyInterval / changeInterval, values @{ IsNull; Days }.
    param([System.Collections.IDictionary]$Changes)
    $p = @{ Confirm = $false }
    foreach ($k in $Changes.Keys) {
        $v = $Changes[$k].Value
        if ($k -eq 'verifyInterval') { if ($v.IsNull) { $p['ClearVerifyInterval'] = $true } else { $p['VerifyInterval'] = $v.Days } }
        if ($k -eq 'changeInterval') { if ($v.IsNull) { $p['ClearChangeInterval'] = $true } else { $p['ChangeInterval'] = $v.Days } }
    }
    return (Set-PCloudMasterRotationPolicy @p)
}

function Add-IntervalChange {
    param([System.Collections.IDictionary]$Changes, [string]$Key, [hashtable]$Value)
    $label = 'Verify interval'
    if ($Key -eq 'changeInterval') { $label = 'Change interval' }
    $d = Format-Interval $Value.Days
    $Changes[$Key] = New-PendingChange -Label $label -Value $Value -Display $d -Hint ('(?i){0}|{1}' -f $Key, ($label -replace ' ', '.?'))
}

function Invoke-RotationMenu {
    $current = Get-PCloudMasterRotationPolicy
    $changes = [ordered]@{}
    $lastError = $null
    while ($true) {
        $r = Format-RotationRow $current
        Write-Host ''
        if ($lastError) { Write-Host ('Last attempt failed: {0}' -f $lastError) -ForegroundColor Red }
        Write-Host 'Update the master rotation policy - choose a setting to change:'
        $rows = @(@('1', 'Verify interval', 'verifyInterval', $r.VerifyInterval), @('2', 'Change interval', 'changeInterval', $r.ChangeInterval))
        foreach ($row in $rows) {
            $pend = ''
            if ($changes.Contains($row[2])) { $pend = ' -> {0}' -f $changes[$row[2]].Display }
            Write-Host ('  {0}) {1,-16} current: {2}{3}' -f $row[0], $row[1], (Format-Interval $row[3]), $pend)
        }
        Write-Host '  A) Apply changes'
        Write-Host '  Q) Back without changes'
        $choice = (Read-Host 'Choice').Trim()
        switch -Regex ($choice) {
            '^(1|2)$' {
                $key = 'verifyInterval'
                if ($choice -eq '2') { $key = 'changeInterval' }
                $raw = (Read-Host 'Days (1-365), "none" to clear the interval, or leave blank to keep').Trim()
                if (-not $raw) { break }
                try { $val = ConvertTo-IntervalValue -Value $raw -Name 'Interval' } catch { Write-Host ('  {0}' -f $_.Exception.Message) -ForegroundColor Red; break }
                $cur = Get-NestedValue $current $key
                if (($val.IsNull -and $null -eq $cur) -or (-not $val.IsNull -and [string]$cur -eq [string]$val.Days)) { Write-Host '  That is already the current value.'; $changes.Remove($key); break }
                if ($val.IsNull) { Write-Warning 'Clearing the interval means the master policy no longer sets one for platforms without an exception.' }
                Add-IntervalChange -Changes $changes -Key $key -Value $val
            }
            '^(?i)a$' {
                if ($changes.Count -eq 0) { Write-Host 'No changes selected yet.'; break }
                Write-Host ''
                Write-Host 'Changes to apply:'
                Write-PendingChanges $changes
                Write-Host 'This affects every platform that does not have its own exception.' -ForegroundColor Yellow
                if (-not (Read-YesNo 'Apply these changes?')) { break }
                if (-not $ScriptCmdlet.ShouldProcess('master rotation policy', 'UpdateRotationPolicy')) { Write-Host 'WhatIf: no changes sent.'; return }
                try {
                    $res = Invoke-RotationUpdate -Changes $changes
                    Write-Host 'Master rotation policy updated.' -ForegroundColor Green
                    if ($res) { $null = Show-RotationPolicy $res }
                    return
                } catch {
                    $err = $_.Exception.Message
                    $lastError = $err
                    Write-Warning ('Update failed: {0}' -f $err)
                    $failed = Select-FailedChange -Changes $changes -Message $err
                    if ($failed) {
                        Write-Host ("Removed '{0}' from the pending changes. The other change is still pending." -f $changes[$failed].Label) -ForegroundColor Yellow
                        $changes.Remove($failed)
                    }
                    try { $current = Get-PCloudMasterRotationPolicy } catch { }
                }
            }
            '^(?i)q$' { Write-Host 'No changes made.'; return }
            default { Write-Host 'Choose 1, 2, A or Q.' }
        }
    }
}

function Invoke-PolicyAction {
    switch ($Action) {
        'GetRotationPolicy' {
            $row = Show-RotationPolicy (Get-PCloudMasterRotationPolicy)
            Save-Results -Rows @($row) -Path $OutputPath
        }
        'GetRotationExceptions' {
            $policy = $null
            try { $policy = Get-PCloudMasterRotationPolicy } catch { }
            $names = @{}
            try { foreach ($p in @(Get-AllTargetPlatforms)) { $names[[string]$p.PlatformID] = [string]$p.Name } } catch { }
            $rows = @()
            foreach ($e in @(Get-PCloudMasterRotationPolicyException)) {
                $rows += [pscustomobject]@{
                    PlatformId           = $e.PlatformId
                    PlatformName         = $names[[string]$e.PlatformId]
                    VerifyInterval       = $e.VerifyInterval
                    ChangeInterval       = $e.ChangeInterval
                    MasterVerifyInterval = Get-NestedValue $policy 'verifyInterval'
                    MasterChangeInterval = Get-NestedValue $policy 'changeInterval'
                }
            }
            if ($rows.Count -eq 0) { Write-Host 'No platforms have rotation exceptions.' }
            else { $rows | Format-Table PlatformId, PlatformName, VerifyInterval, ChangeInterval, MasterVerifyInterval, MasterChangeInterval -AutoSize | Out-String | Write-Host }
            Write-Host ('{0} exception(s).' -f $rows.Count)
            Save-Results -Rows $rows -Path $OutputPath
        }
        'UpdateRotationPolicy' {
            if (-not $VerifyInterval -and -not $ChangeInterval) { Invoke-RotationMenu; return }
            $changes = [ordered]@{}
            if ($VerifyInterval) { Add-IntervalChange -Changes $changes -Key 'verifyInterval' -Value (ConvertTo-IntervalValue -Value $VerifyInterval -Name 'VerifyInterval') }
            if ($ChangeInterval) { Add-IntervalChange -Changes $changes -Key 'changeInterval' -Value (ConvertTo-IntervalValue -Value $ChangeInterval -Name 'ChangeInterval') }
            if ($ScriptCmdlet.ShouldProcess('master rotation policy', ('UpdateRotationPolicy ({0})' -f ((@($changes.Keys | ForEach-Object { '{0}={1}' -f $_, $changes[$_].Display })) -join ', ')))) {
                $res = Invoke-RotationUpdate -Changes $changes
                Write-Host 'Master rotation policy updated.' -ForegroundColor Green
                if ($res) { $null = Show-RotationPolicy $res }
            }
        }
    }
}

# ---------- Non-interactive: -Action given.
if ($Action) {
    if ($ExportCsv -and -not $OutputPath) { $OutputPath = New-OutputPath -Action $Action }
    Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod
    Invoke-PolicyAction
    return
}

# ---------- Menu mode: loops until Q. Any failure returns to the menu.
Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod
$original = @{ OutputPath = $OutputPath; ExportCsv = [bool]$ExportCsv; VerifyInterval = $VerifyInterval; ChangeInterval = $ChangeInterval }
while ($true) {
    foreach ($k in $original.Keys) { Set-Variable -Name $k -Value $original[$k] -Scope Script }
    $Action = $null
    $Action = Read-MainMenu -Title 'Master Policy - choose an action:' -Actions $actions -Descriptions $actionHelp
    if (-not $Action) { break }
    try {
        if (($readActions -contains $Action) -and -not $OutputPath -and -not $ExportCsv) { $OutputPath = Read-OutputChoice -Action $Action }
        if ($ExportCsv -and -not $OutputPath) { $OutputPath = New-OutputPath -Action $Action }
        Invoke-PolicyAction
    } catch {
        Write-Host ''
        Write-Host ('{0} failed: {1}' -f $Action, $_.Exception.Message) -ForegroundColor Red
        Write-Host 'Returning to the menu.' -ForegroundColor Yellow
    }
}
