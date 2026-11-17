#Requires -Version 5.1
<#
.SYNOPSIS
    Safe management for Idira Privilege Cloud: get safes, get safe details, add or update safes,
    and add or update safe members. Each action works on one item or on every row of a CSV.
.DESCRIPTION
    Actions:
      GetSafes          List safes. With nothing specified, returns every safe.
                        Single: -SafeName (exact) or -Search.  CSV columns: SafeName and/or Search
                        (a row with both blank also returns every safe).
      GetSafeDetails    Full safe settings plus account and member counts and names.
                        Single: -SafeName.  CSV column: SafeName.
      GetSafeMembers    One row per safe member with every permission as a true/false column, plus the
                        matching preset (Full, AccountsManager, Approver, ReadOnly, ConnectOnly, None),
                        or 'Custom (closest preset +added -removed)' when it does not match exactly.
                        With nothing specified, covers every safe. Single: -SafeName [-MemberName].
                        CSV columns: SafeName [, MemberName]. -IncludePredefinedUsers adds built-in users.
      AddSafe           Create safes.
                        CSV columns: SafeName, Description, ManagingCPM, Location,
                        NumberOfDaysRetention, NumberOfVersionsRetention, AutoPurgeEnabled
      UpdateSafe        Change safe settings. Blank values are left unchanged. For a single safe with no
                        settings given, a menu shows the current values and lets you pick what to change;
                        if the update fails, the failing setting is dropped and the menu returns with
                        the rest still pending. OLAC is intentionally not offered (being deprecated).
                        Managing CPM opens a submenu: pick a CPM from System Health, no managing CPM, or
                        read-only CPM access (list + retrieve + no confirmation) so a CPM can use a linked
                        logon/reconcile account stored in this safe without managing the safe.
                        CSV columns: SafeName, NewSafeName, Description, ManagingCPM, Location,
                        NumberOfDaysRetention, NumberOfVersionsRetention
      AddSafeMember     Add users, groups or roles to safes with a preset and optional per-permission overrides.
                        MemberType: User, Group, Role or Auto/blank (detects Identity roles and users).
                        CSV columns: SafeName, MemberName, MemberType, SearchIn, Preset, ExpirationDate,
                        IsReadOnly, plus any permission name as a column (true/false).
      UpdateSafeMember  Change a member's permissions. With a Preset the permissions are replaced by the
                        preset (plus overrides); without one the member's current permissions are kept and
                        only the permission columns you fill in change.
                        CSV columns: same as AddSafeMember (MemberType/SearchIn are ignored).

    Permission column names: useAccounts, retrieveAccounts, listAccounts, addAccounts,
    updateAccountContent, updateAccountProperties, initiateCPMAccountManagementOperations,
    specifyNextAccountContent, renameAccounts, deleteAccounts, unlockAccounts, manageSafe,
    manageSafeMembers, backupSafe, viewAuditLog, viewSafeMembers, accessWithoutConfirmation,
    createFolders, deleteFolders, moveAccountsAndFolders, requestsAuthorizationLevel1,
    requestsAuthorizationLevel2.
    Presets: None, ConnectOnly, ReadOnly, Approver, AccountsManager, Full.
    Booleans accept true/false, yes/no, 1/0. Dates accept anything [datetime] parses (e.g. 2026-12-31).

    Run without -Action to pick from a menu. Prompts for sign-in if there is no active session.
    Menu mode loops until you choose Q: invalid safe names or CSV paths are asked again, and any
    failure returns you to the previous prompt or the main menu instead of ending the script.
    Write actions support -WhatIf.
    CSV export: -ExportCsv saves the results to CSVs\PCloud-<Action>-<timestamp>.csv in the IdiraPCloud folder, or -OutputPath <file>
    picks the file. From the menu you are asked whether to save GetSafes, GetSafeDetails and
    GetSafeMembers results. Exports contain no secrets but do describe privileged access, so keep
    them in a folder only you can read.
.EXAMPLE
    .\Manage-Safes.ps1
.EXAMPLE
    .\Manage-Safes.ps1 -Action GetSafes
    # every safe
.EXAMPLE
    .\Manage-Safes.ps1 -Action GetSafes -ExportCsv
.EXAMPLE
    .\Manage-Safes.ps1 -Action GetSafeMembers -ExportCsv
    # every member of every safe, with permissions and preset
.EXAMPLE
    .\Manage-Safes.ps1 -Action GetSafeMembers -SafeName 'Linux-Root' -OutputPath .\linux-root-members.csv
.EXAMPLE
    .\Manage-Safes.ps1 -Action GetSafes -Search 'Prod'
.EXAMPLE
    .\Manage-Safes.ps1 -Action GetSafeDetails -CsvPath .\samples\safes-names.csv -OutputPath .\details.csv
.EXAMPLE
    .\Manage-Safes.ps1 -Action AddSafe -SafeName 'Linux-Root' -Description 'Root accounts' -ManagingCPM 'PasswordManager' -NumberOfDaysRetention 7
.EXAMPLE
    .\Manage-Safes.ps1 -Action AddSafe -CsvPath .\samples\safes-add.csv -WhatIf
.EXAMPLE
    .\Manage-Safes.ps1 -Action UpdateSafe -SafeName 'Linux-Root' -ManagingCPM 'PasswordManager1' -RemoveOldCPM
.EXAMPLE
    .\Manage-Safes.ps1 -Action AddSafeMember -SafeName 'Linux-Root' -MemberName 'unix-admins' -MemberType Group -Preset AccountsManager
.EXAMPLE
    .\Manage-Safes.ps1 -Action UpdateSafeMember -SafeName 'Linux-Root' -MemberName 'jdoe@acme.com' -Permission @{ retrieveAccounts = $false }
.EXAMPLE
    .\Manage-Safes.ps1 -Action UpdateSafeMember -CsvPath .\samples\safe-members-update.csv
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Validated below rather than with [ValidateSet()]: the menu loop reassigns these variables, and a
    # ValidateSet attribute would reject the blank values used to reset them between passes.
    [ArgumentCompleter({ param($c, $p, $w) 'GetSafes', 'GetSafeDetails', 'GetSafeMembers', 'AddSafe', 'UpdateSafe', 'AddSafeMember', 'UpdateSafeMember' | Where-Object { $_ -like "$w*" } })]
    [string]$Action,

    [string]$CsvPath,
    [string]$OutputPath,
    [switch]$ExportCsv,
    [switch]$IncludePredefinedUsers,

    # Safe (single mode)
    [string]$SafeName,
    [string]$Search,
    [string]$NewSafeName,
    [string]$Description,
    [string]$ManagingCPM,
    [string]$Location,
    [int]$NumberOfDaysRetention = 0,
    [int]$NumberOfVersionsRetention = 0,
    [switch]$AutoPurgeEnabled,
    # UpdateSafe with -ManagingCPM: also remove any other CPM that is still a safe member with CPM management
    # permissions (an earlier managing CPM). CPMs with read-only access are left alone.
    [switch]$RemoveOldCPM,

    # Safe member (single mode)
    [string]$MemberName,
    [ValidateSet('Auto', 'User', 'Group', 'Role')][string]$MemberType = 'Auto',
    [string]$SearchIn,
    [ArgumentCompleter({ param($c, $p, $w) 'None', 'ConnectOnly', 'ReadOnly', 'Approver', 'AccountsManager', 'Full' | Where-Object { $_ -like "$w*" } })]
    [string]$Preset,
    [hashtable]$Permission,
    [datetime]$ExpirationDate,
    [ValidateSet('true', 'false')][string]$IsReadOnly,

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
# Shared prompts (partial safe-name search, pick lists). Functions defined below with the same names take precedence.
. (Join-Path $PSScriptRoot '_Menu.ps1')

$validActions = @('GetSafes', 'GetSafeDetails', 'GetSafeMembers', 'AddSafe', 'UpdateSafe', 'AddSafeMember', 'UpdateSafeMember')
$validPresets = @('None', 'ConnectOnly', 'ReadOnly', 'Approver', 'AccountsManager', 'Full')
if ($Action) {
    $m = @($validActions | Where-Object { $_ -eq $Action })
    if ($m.Count -eq 0) { throw ("-Action must be one of: {0}" -f ($validActions -join ', ')) }
    $Action = $m[0]
}
if ($Preset) {
    $m = @($validPresets | Where-Object { $_ -eq $Preset })
    if ($m.Count -eq 0) { throw ("-Preset must be one of: {0}" -f ($validPresets -join ', ')) }
    $Preset = $m[0]
}

# ------------------------------------------------------------------ helpers

function ConvertTo-OptionalBool {
    param($Value, [string]$Name)
    if ($null -eq $Value) { return $null }
    $v = ([string]$Value).Trim()
    if ($v -eq '') { return $null }
    if ($v -match '^(?i)(true|yes|y|1)$') { return $true }
    if ($v -match '^(?i)(false|no|n|0)$') { return $false }
    throw "Value '$v' for $Name is not true/false."
}

function ConvertTo-OptionalInt {
    param($Value, [string]$Name)
    if ($null -eq $Value) { return 0 }
    $v = ([string]$Value).Trim()
    if ($v -eq '') { return 0 }
    $n = 0
    if (-not [int]::TryParse($v, [ref]$n)) { throw "Value '$v' for $Name is not a whole number." }
    return $n
}

function Get-RowValue {
    param($Row, [string]$Name)
    $prop = $Row.PSObject.Properties | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if ($null -eq $prop -or $null -eq $prop.Value) { return '' }
    return ([string]$prop.Value).Trim()
}

function Get-PermissionOverrides {
    # Reads permission columns from a row (or the -Permission hashtable). Blank cells are ignored.
    param($Row)
    $names = @((Get-PCloudSafePermissionSet -Preset None).Keys)
    $o = @{}
    if ($Row -is [System.Collections.IDictionary]) {
        foreach ($k in $Row.Keys) {
            $match = $names | Where-Object { $_ -eq $k } | Select-Object -First 1
            if (-not $match) { throw "Unknown permission '$k'." }
            $o[[string]$match] = [bool]$Row[$k]
        }
        return $o
    }
    foreach ($n in $names) {
        $raw = Get-RowValue $Row $n
        $b = ConvertTo-OptionalBool $raw $n
        if ($null -ne $b) { $o[$n] = $b }
    }
    return $o
}

function New-ResultRow {
    param([int]$Row, [string]$Safe, [string]$Member, [string]$Status, [string]$Message)
    [pscustomobject]@{ Row = $Row; Action = $Action; SafeName = $Safe; MemberName = $Member; Status = $Status; Message = $Message }
}

function Format-SafeRow {
    param($Safe)
    $creator = $null
    if ($Safe.creator) { $creator = $Safe.creator.name }
    [pscustomobject]@{
        SafeName                  = $Safe.safeName
        SafeNumber                = $Safe.safeNumber
        Description               = $Safe.description
        Location                  = $Safe.location
        ManagingCPM               = $Safe.managingCPM
        NumberOfDaysRetention     = $Safe.numberOfDaysRetention
        NumberOfVersionsRetention = $Safe.numberOfVersionsRetention
        OLACEnabled               = $Safe.olacEnabled
        AutoPurgeEnabled          = $Safe.autoPurgeEnabled
        Creator                   = $creator
        Created                   = ConvertFrom-PCloudUnixTime $Safe.creationTime
        LastModified              = ConvertFrom-PCloudUnixTime $Safe.lastModificationTime
    }
}

# ------------------------------------------------------------------ actions (one item each)

function Invoke-GetSafes {
    param([string]$Name, [string]$Text)
    if ($Name) { return (Format-SafeRow (Get-PCloudSafe -SafeName $Name)) }
    $p = @{}
    if ($Text) { $p['Search'] = $Text }
    foreach ($s in (Get-PCloudSafe @p)) { Format-SafeRow $s }
}

function Invoke-GetSafeDetails {
    param([Parameter(Mandatory = $true)][string]$Name)
    $safe = Get-PCloudSafe -SafeName $Name -IncludeAccounts
    $members = @(Get-PCloudSafeMember -SafeName $Name)
    $accounts = @()
    if ($safe.PSObject.Properties.Name -contains 'accounts' -and $safe.accounts) { $accounts = @($safe.accounts) }
    $row = Format-SafeRow $safe
    $row | Add-Member -NotePropertyName AccountCount -NotePropertyValue $accounts.Count
    $row | Add-Member -NotePropertyName Accounts -NotePropertyValue ((@($accounts | ForEach-Object { $_.name })) -join '; ')
    $row | Add-Member -NotePropertyName MemberCount -NotePropertyValue $members.Count
    $row | Add-Member -NotePropertyName Members -NotePropertyValue ((@($members | ForEach-Object { '{0} ({1})' -f $_.memberName, (Resolve-PCloudSafeMemberType -MemberName $_.memberName -ReportedType $_.memberType).MemberType })) -join '; ')
    return $row
}

function Invoke-GetSafeMembers {
    param([Parameter(Mandatory = $true)][string]$Name, [string]$Member)
    $mp = @{ SafeName = $Name }
    if ($IncludePredefinedUsers) { $mp['IncludePredefinedUsers'] = $true }
    if ($Member) {
        $members = @(Get-PCloudSafeMember -SafeName $Name -MemberName $Member)
    } else {
        $members = @(Get-PCloudSafeMember @mp)
    }
    $permNames = @((Get-PCloudSafePermissionSet -Preset None).Keys)
    foreach ($m in $members) {
        $match = Get-PCloudSafePermissionPreset -Permissions $m.permissions
        # The API can report Identity roles as 'Group'; check the name against Identity.
        $resolved = Resolve-PCloudSafeMemberType -MemberName $m.memberName -ReportedType $m.memberType
        $row = [ordered]@{
            SafeName       = $Name
            MemberName     = $m.memberName
            MemberType     = $resolved.MemberType
            ApiMemberType  = $m.memberType
            TypeSource     = $resolved.Source
            Preset         = $match.Label
            ClosestPreset  = $match.ClosestPreset
            IsExactMatch   = $match.IsExactMatch
            IsPredefined   = $m.isPredefinedUser
            IsReadOnly     = $m.isReadOnly
            ExpirationDate = ConvertFrom-PCloudUnixTime $m.membershipExpirationDate
        }
        foreach ($n in $permNames) {
            $v = $false
            if ($m.permissions -and ($m.permissions.PSObject.Properties.Name -contains $n)) { $v = [bool]$m.permissions.$n }
            $row[$n] = $v
        }
        [pscustomobject]$row
    }
}

function Invoke-AddSafe {
    param([hashtable]$Spec)
    $p = @{ SafeName = $Spec.SafeName; Confirm = $false }
    foreach ($k in @('Description', 'ManagingCPM', 'Location')) { if ($Spec[$k]) { $p[$k] = $Spec[$k] } }
    if ($Spec.NumberOfDaysRetention -gt 0) { $p['NumberOfDaysRetention'] = $Spec.NumberOfDaysRetention }
    if ($Spec.NumberOfVersionsRetention -gt 0) { $p['NumberOfVersionsRetention'] = $Spec.NumberOfVersionsRetention }
    if ($Spec.AutoPurgeEnabled -eq $true) { $p['AutoPurgeEnabled'] = $true }
    New-PCloudSafe @p | Out-Null
}

function Get-CpmUsers {
    # CPM vault users from System Health; falls back to the CPMs already used by safes.
    if ($null -ne $script:cpmCache) { return $script:cpmCache }
    $list = @()
    try {
        $list = @(Get-PCloudSystemHealth -ComponentId CPM | Where-Object { $_.ComponentUserName } | ForEach-Object {
                $state = 'offline'
                if ($_.IsLoggedOn) { $state = 'online' }
                [pscustomobject]@{ Name = [string]$_.ComponentUserName; Status = $state }
            })
    } catch {
        Write-Verbose ('Could not read CPMs from System Health: {0}' -f $_.Exception.Message)
    }
    if ($list.Count -eq 0) {
        Write-Host 'Reading CPM names from existing safes (System Health was not available)...'
        try {
            $list = @(Get-PCloudSafe | Where-Object { $_.managingCPM } | Select-Object -ExpandProperty managingCPM |
                Sort-Object -Unique | ForEach-Object { [pscustomobject]@{ Name = [string]$_; Status = 'in use' } })
        } catch {
            Write-Verbose ('Could not read safes: {0}' -f $_.Exception.Message)
        }
    }
    $script:cpmCache = @($list | Sort-Object Name -Unique)
    return $script:cpmCache
}

function Get-OtherCpmMembers {
    # Known CPM users, other than the managing CPM, that are members of a safe.
    # Manages = the member still holds CPM management permissions (as a former managing CPM does);
    # a CPM added for read-only access to linked accounts does not.
    param([string]$SafeName, [string]$ManagingCpm, [string[]]$Extra)
    $names = @(@(Get-CpmUsers | ForEach-Object { $_.Name }) + @($Extra) | Where-Object { $_ } | Sort-Object -Unique)
    $found = @()
    foreach ($n in $names) {
        if ($n -eq $ManagingCpm) { continue }
        $m = $null
        try { $m = Get-PCloudSafeMember -SafeName $SafeName -MemberName $n } catch { continue }
        if ($null -eq $m) { continue }
        $manages = $false
        foreach ($perm in @('initiateCPMAccountManagementOperations', 'updateAccountContent', 'specifyNextAccountContent')) {
            if ((Get-NestedValue $m ('permissions.{0}' -f $perm)) -eq $true) { $manages = $true }
        }
        $found += [pscustomobject]@{ Name = $n; Manages = $manages }
    }
    return $found
}

function Confirm-ManagingCpmChange {
    # After a managing CPM change: reads the safe back to check what Privilege Cloud now reports, then looks
    # for other CPMs that are still safe members with management permissions. The update adds the new CPM to
    # the members but does not remove an earlier one, and the portal can go on showing that earlier CPM.
    # Returns a note for the results ('' = nothing to say).
    param([string]$SafeName, [string]$OldCpm, [string]$NewCpm, [switch]$Interactive)
    $now = $null
    try { $now = [string](Get-PCloudSafe -SafeName $SafeName).managingCPM }
    catch { return ('Could not read the safe back to check the managing CPM: {0}' -f $_.Exception.Message) }
    if ($now -ne $NewCpm) {
        $msg = "Privilege Cloud accepted the update but still reports managing CPM '{0}' (asked for '{1}')." -f $now, $NewCpm
        Write-Warning $msg
        return $msg
    }
    $shown = $now
    if (-not $shown) { $shown = '(none)' }
    Write-Host ("  Checked: Privilege Cloud now reports managing CPM '{0}' for safe '{1}'." -f $shown, $SafeName)

    $left = @()
    try { $left = @(Get-OtherCpmMembers -SafeName $SafeName -ManagingCpm $now -Extra @($OldCpm) | Where-Object { $_.Manages } | ForEach-Object { $_.Name }) }
    catch { return ('Could not check the safe members for other CPMs: {0}' -f $_.Exception.Message) }
    if ($left.Count -eq 0) { return '' }
    $list = $left -join ', '
    $remove = [bool]$RemoveOldCPM
    if (-not $remove -and $Interactive) {
        Write-Host ("  Still a member of this safe with CPM management permissions: {0}" -f $list) -ForegroundColor Yellow
        Write-Host '  The portal can keep showing an earlier CPM as the assigned CPM while it is still a member.' -ForegroundColor Yellow
        $remove = Read-YesNo ("  Remove {0} from the safe members?" -f $list)
    }
    if (-not $remove) {
        $msg = 'Other CPM still a safe member with management permissions: {0} (remove with -RemoveOldCPM or from the Managing CPM menu; the portal may show it as the assigned CPM until then)' -f $list
        if (-not $Interactive) { Write-Warning ('{0}: {1}' -f $SafeName, $msg) }
        return $msg
    }
    $notes = @()
    foreach ($n in $left) {
        try {
            Remove-PCloudSafeMember -SafeName $SafeName -MemberName $n -Confirm:$false
            Write-Host ("  Earlier CPM '{0}' removed from the safe members." -f $n) -ForegroundColor Green
            $notes += ("Earlier CPM '{0}' removed from the safe members" -f $n)
        } catch {
            $msg = "Earlier CPM '{0}' could not be removed from the safe members: {1}" -f $n, $_.Exception.Message
            Write-Warning $msg
            $notes += $msg
        }
    }
    return ($notes -join '; ')
}

function Invoke-UpdateSafe {
    param([hashtable]$Spec, [switch]$Interactive)
    $script:lastUpdateNote = ''
    $p = @{ SafeName = $Spec.SafeName; Confirm = $false }
    foreach ($k in @('NewSafeName', 'Description', 'ManagingCPM', 'Location')) { if ($Spec[$k]) { $p[$k] = $Spec[$k] } }
    # '(none)' means: no managing CPM (accounts in the safe are not managed).
    if ($p['ManagingCPM'] -eq '(none)') { $p['ManagingCPM'] = '' }
    if ($Spec.NumberOfDaysRetention -gt 0) { $p['NumberOfDaysRetention'] = $Spec.NumberOfDaysRetention }
    if ($Spec.NumberOfVersionsRetention -gt 0) { $p['NumberOfVersionsRetention'] = $Spec.NumberOfVersionsRetention }
    if ($p.Count -le 2) { throw 'Nothing to update. Fill in at least one setting.' }
    $cpmChange = $p.ContainsKey('ManagingCPM')
    $oldCpm = ''
    if ($cpmChange) { try { $oldCpm = [string](Get-PCloudSafe -SafeName $Spec.SafeName).managingCPM } catch { } }
    Set-PCloudSafe @p | Out-Null
    if ($cpmChange) {
        $name = $Spec.SafeName
        if ($p['NewSafeName']) { $name = $p['NewSafeName'] }
        $script:lastUpdateNote = Confirm-ManagingCpmChange -SafeName $name -OldCpm $oldCpm -NewCpm ([string]$p['ManagingCPM']) -Interactive:$Interactive
    }
}

function Invoke-AddSafeMember {
    param([hashtable]$Spec)
    $presetName = $Spec.Preset
    if (-not $presetName) { $presetName = 'ReadOnly' }
    $perm = Get-PCloudSafePermissionSet -Preset $presetName -Override $Spec.Overrides
    $p = @{ SafeName = $Spec.SafeName; MemberName = $Spec.MemberName; Permission = $perm; Confirm = $false }
    if ($Spec.MemberType) { $p['MemberType'] = $Spec.MemberType }
    if ($Spec.SearchIn) { $p['SearchIn'] = $Spec.SearchIn }
    if ($null -ne $Spec.ExpirationDate) { $p['ExpirationDate'] = $Spec.ExpirationDate }
    if ($Spec.IsReadOnly -eq $true) { $p['IsReadOnly'] = $true }
    Add-PCloudSafeMember @p | Out-Null
}

function Invoke-UpdateSafeMember {
    param([hashtable]$Spec)
    $current = Get-PCloudSafeMember -SafeName $Spec.SafeName -MemberName $Spec.MemberName

    if ($Spec.Preset) {
        $perm = Get-PCloudSafePermissionSet -Preset $Spec.Preset -Override $Spec.Overrides
    } else {
        if ($Spec.Overrides.Count -eq 0 -and $null -eq $Spec.ExpirationDate -and $null -eq $Spec.IsReadOnly) {
            throw 'Nothing to update. Give a Preset, permission values, ExpirationDate or IsReadOnly.'
        }
        # Start from the member's current permissions and apply only the values given.
        $perm = Get-PCloudSafePermissionSet -Preset None
        foreach ($n in @($perm.Keys)) {
            if ($current.permissions -and ($current.permissions.PSObject.Properties.Name -contains $n)) {
                $perm[$n] = [bool]$current.permissions.$n
            }
        }
        foreach ($k in $Spec.Overrides.Keys) { $perm[$k] = [bool]$Spec.Overrides[$k] }
        if ($perm['requestsAuthorizationLevel1'] -and $perm['requestsAuthorizationLevel2']) {
            throw 'requestsAuthorizationLevel1 and requestsAuthorizationLevel2 cannot both be true.'
        }
    }

    $readOnly = [bool]$current.isReadOnly
    if ($null -ne $Spec.IsReadOnly) { $readOnly = [bool]$Spec.IsReadOnly }

    $p = @{ SafeName = $Spec.SafeName; MemberName = $Spec.MemberName; Permission = $perm; IsReadOnly = $readOnly; Confirm = $false }
    if ($null -ne $Spec.ExpirationDate) {
        $p['ExpirationDate'] = $Spec.ExpirationDate
    } else {
        # Keep the existing expiration date, if any.
        $existing = ConvertFrom-PCloudUnixTime $current.membershipExpirationDate
        if ($null -ne $existing) { $p['ExpirationDate'] = $existing }
    }
    Set-PCloudSafeMember @p | Out-Null
}

# ------------------------------------------------------------------ build work items

function ConvertTo-Spec {
    # Builds a normalized hashtable from a CSV row, or from the script's single-mode parameters when $Row is $null.
    param($Row, [int]$Index)
    if ($null -ne $Row) {
        $exp = $null
        $expRaw = Get-RowValue $Row 'ExpirationDate'
        if ($expRaw) {
            $d = [datetime]::MinValue
            if (-not [datetime]::TryParse($expRaw, [ref]$d)) { throw "ExpirationDate '$expRaw' is not a date." }
            $exp = $d
        }
        return @{
            Index                     = $Index
            SafeName                  = Get-RowValue $Row 'SafeName'
            Search                    = Get-RowValue $Row 'Search'
            NewSafeName               = Get-RowValue $Row 'NewSafeName'
            Description               = Get-RowValue $Row 'Description'
            ManagingCPM               = Get-RowValue $Row 'ManagingCPM'
            Location                  = Get-RowValue $Row 'Location'
            NumberOfDaysRetention     = ConvertTo-OptionalInt (Get-RowValue $Row 'NumberOfDaysRetention') 'NumberOfDaysRetention'
            NumberOfVersionsRetention = ConvertTo-OptionalInt (Get-RowValue $Row 'NumberOfVersionsRetention') 'NumberOfVersionsRetention'
            AutoPurgeEnabled          = ConvertTo-OptionalBool (Get-RowValue $Row 'AutoPurgeEnabled') 'AutoPurgeEnabled'
            MemberName                = Get-RowValue $Row 'MemberName'
            MemberType                = Get-RowValue $Row 'MemberType'
            SearchIn                  = Get-RowValue $Row 'SearchIn'
            Preset                    = Get-RowValue $Row 'Preset'
            ExpirationDate            = $exp
            IsReadOnly                = ConvertTo-OptionalBool (Get-RowValue $Row 'IsReadOnly') 'IsReadOnly'
            Overrides                 = Get-PermissionOverrides $Row
        }
    }
    $ov = @{}
    if ($Permission) { $ov = Get-PermissionOverrides $Permission }
    $expDate = $null
    if ($PSBoundParameters_Main.ContainsKey('ExpirationDate')) { $expDate = $ExpirationDate }
    $autoPurge = $null
    if ($AutoPurgeEnabled) { $autoPurge = $true }
    return @{
        Index                     = 1
        SafeName                  = $SafeName
        Search                    = $Search
        NewSafeName               = $NewSafeName
        Description               = $Description
        ManagingCPM               = $ManagingCPM
        Location                  = $Location
        NumberOfDaysRetention     = $NumberOfDaysRetention
        NumberOfVersionsRetention = $NumberOfVersionsRetention
        AutoPurgeEnabled          = $autoPurge
        MemberName                = $MemberName
        MemberType                = $MemberType
        SearchIn                  = $SearchIn
        Preset                    = $Preset
        ExpirationDate            = $expDate
        IsReadOnly                = ConvertTo-OptionalBool $IsReadOnly 'IsReadOnly'
        Overrides                 = $ov
    }
}

# ------------------------------------------------------------------ main

$PSBoundParameters_Main = $PSBoundParameters
$ScriptCmdlet = $PSCmdlet
$script:cpmCache = $null

$actions = @('GetSafes', 'GetSafeDetails', 'GetSafeMembers', 'AddSafe', 'UpdateSafe', 'AddSafeMember', 'UpdateSafeMember')
$readActions = @('GetSafes', 'GetSafeDetails', 'GetSafeMembers')

function Invoke-SafeAction {
    # Runs the selected action once. In menu mode, errors are caught by the caller and the user
    # is returned to the main menu instead of the script exiting.
    # Single-safe update with no settings given: let the user pick what to change from a menu.
    # The update is applied from the menu itself. If it fails, the setting that caused it is removed
    # and the menu comes back with the remaining changes still pending.
    $updateParams = @('NewSafeName', 'Description', 'ManagingCPM', 'Location', 'NumberOfDaysRetention', 'NumberOfVersionsRetention')
    $hasUpdateValues = @($updateParams | Where-Object { $PSBoundParameters_Main.ContainsKey($_) }).Count -gt 0
    if ($Action -eq 'UpdateSafe' -and -not $CsvPath -and -not $hasUpdateValues) {
        $current = Get-PCloudSafe -SafeName $SafeName
        $changes = [ordered]@{}
        $lastError = $null

        $labels = @{
            NewSafeName               = 'Safe name'
            Description               = 'Description'
            ManagingCPM               = 'Managing CPM'
            Location                  = 'Location'
            NumberOfDaysRetention     = 'Retention (days)'
            NumberOfVersionsRetention = 'Retention (versions)'
            ReadOnlyCPMs              = 'Read-only CPM access'
            RemoveCPMs                = 'Remove CPM from the safe members'
        }
        # Words in an API error that point at a specific setting.
        $errorHints = [ordered]@{
            NumberOfDaysRetention     = '(?i)numberOfDaysRetention|retention.*day|day.*retention'
            NumberOfVersionsRetention = '(?i)numberOfVersionsRetention|retention.*version|version.*retention'
            ManagingCPM               = '(?i)managingCPM|\bCPM\b'
            Location                  = '(?i)\blocation\b'
            Description               = '(?i)description'
            NewSafeName               = '(?i)safeName|safe name|already exists|\bname\b'
        }

        # Read-only CPM access: lets a CPM retrieve a linked (logon/reconcile) account stored in this safe
        # without managing the safe's accounts.
        $cpmReadOnlyPermissions = Get-PCloudSafePermissionSet -Preset None -Override @{
            listAccounts = $true; retrieveAccounts = $true; accessWithoutConfirmation = $true
        }

        function Read-CpmChoice {
            # Lets the user pick one or more CPMs from the list; returns the names.
            param([string]$Prompt, [switch]$Multiple)
            $cpms = @(Get-CpmUsers)
            if ($cpms.Count -eq 0) {
                Write-Warning 'No CPM users found. Type the CPM user name instead.'
                $v = Read-Host 'CPM user name'
                if ($v) { return @($v) }
                return @()
            }
            for ($i = 0; $i -lt $cpms.Count; $i++) { Write-Host ('    {0}) {1} ({2})' -f ($i + 1), $cpms[$i].Name, $cpms[$i].Status) }
            $raw = Read-Host $Prompt
            $picked = @()
            foreach ($part in ($raw -split '[,; ]+' | Where-Object { $_ })) {
                $n = 0
                if ([int]::TryParse($part, [ref]$n) -and $n -ge 1 -and $n -le $cpms.Count) { $picked += $cpms[$n - 1].Name }
                else { Write-Warning ("Ignored '{0}'." -f $part) }
                if (-not $Multiple -and $picked.Count -gt 0) { break }
            }
            return @($picked | Select-Object -Unique)
        }

        function Show-CpmMenu {
            $currentCpm = $current.managingCPM
            if (-not $currentCpm) { $currentCpm = '(none)' }
            $others = @(Get-OtherCpmMembers -SafeName $current.safeName -ManagingCpm $current.managingCPM)
            $otherLabel = { param($x) if ($x.Manages) { '{0} (has CPM management permissions)' -f $x.Name } else { '{0} (read-only access)' -f $x.Name } }
            while ($true) {
                $pendingManaging = ''
                if ($changes.Contains('ManagingCPM')) { $pendingManaging = ' -> {0}' -f $changes['ManagingCPM'] }
                $pendingRo = '(none pending)'
                if ($changes.Contains('ReadOnlyCPMs')) { $pendingRo = 'add ' + (@($changes['ReadOnlyCPMs']) -join ', ') }
                Write-Host ''
                Write-Host 'CPM settings:'
                Write-Host ('  Managing CPM:          {0}{1}' -f $currentCpm, $pendingManaging)
                Write-Host ('  Read-only CPM access:  {0}' -f $pendingRo)
                $otherText = '(none)'
                if ($others.Count -gt 0) { $otherText = (@($others | ForEach-Object { & $otherLabel $_ })) -join ', ' }
                $pendingRm = ''
                if ($changes.Contains('RemoveCPMs')) { $pendingRm = ' -> remove ' + (@($changes['RemoveCPMs']) -join ', ') }
                Write-Host ('  Other CPMs that are members of this safe:  {0}{1}' -f $otherText, $pendingRm)
                Write-Host '  1) Choose the managing CPM from the list'
                Write-Host '  2) No managing CPM (accounts in this safe are not managed)'
                Write-Host '  3) Add read-only CPM access (CPM can retrieve linked accounts here without managing the safe)'
                Write-Host '  4) Type a CPM user name'
                Write-Host '  5) Remove another CPM from the safe members (for example the previous managing CPM)'
                Write-Host '  C) Clear pending CPM changes'
                Write-Host '  B) Back'
                $c = (Read-Host 'Choice').Trim()
                switch -Regex ($c) {
                    '^1$' {
                        $pick = @(Read-CpmChoice -Prompt '  Managing CPM number')
                        if ($pick.Count -gt 0) {
                            if ($pick[0] -eq $current.managingCPM) { Write-Host 'That is already the managing CPM.' } else { $changes['ManagingCPM'] = $pick[0] }
                        }
                    }
                    '^2$' {
                        if (-not $current.managingCPM) { Write-Host 'The safe already has no managing CPM.' }
                        else {
                            Write-Warning 'Without a managing CPM, passwords in this safe will not be changed, verified or reconciled.'
                            if ((Read-Host 'Remove the managing CPM? (y/N)') -match '^(?i)y') { $changes['ManagingCPM'] = '(none)' }
                        }
                    }
                    '^3$' {
                        $picks = @(Read-CpmChoice -Prompt '  CPM number(s) for read-only access, comma separated' -Multiple)
                        $managing = $current.managingCPM
                        if ($changes.Contains('ManagingCPM')) { $managing = $changes['ManagingCPM'] }
                        $picks = @($picks | Where-Object {
                                if ($_ -eq $managing) { Write-Host ("{0} manages this safe and already has full access; skipped." -f $_); $false } else { $true }
                            })
                        if ($picks.Count -gt 0) {
                            $existing = @()
                            if ($changes.Contains('ReadOnlyCPMs')) { $existing = @($changes['ReadOnlyCPMs']) }
                            $changes['ReadOnlyCPMs'] = @($existing + $picks | Select-Object -Unique)
                            if ($changes.Contains('RemoveCPMs')) {
                                $left = @(@($changes['RemoveCPMs']) | Where-Object { $picks -notcontains $_ })
                                if ($left.Count -gt 0) { $changes['RemoveCPMs'] = $left } else { $changes.Remove('RemoveCPMs') }
                            }
                        }
                    }
                    '^4$' {
                        $v = Read-Host 'CPM user name'
                        if ($v) { $changes['ManagingCPM'] = $v }
                    }
                    '^5$' {
                        if ($others.Count -eq 0) { Write-Host 'No other CPM is a member of this safe.'; break }
                        $picks = Select-FromList -Items $others -Multiple -Title 'Remove which CPM(s) from the safe members' -Label $otherLabel
                        if ($null -eq $picks) { break }
                        $picks = @(@($picks) | ForEach-Object { [string]$_.Name } | Where-Object {
                                if ($changes.Contains('ManagingCPM') -and $_ -eq $changes['ManagingCPM']) { Write-Host ("{0} is the pending managing CPM; skipped." -f $_); $false }
                                elseif ($changes.Contains('ReadOnlyCPMs') -and (@($changes['ReadOnlyCPMs']) -contains $_)) { Write-Host ("{0} is pending read-only access; clear that first. Skipped." -f $_); $false }
                                else { $true }
                            })
                        if ($picks.Count -gt 0) {
                            $existing = @()
                            if ($changes.Contains('RemoveCPMs')) { $existing = @($changes['RemoveCPMs']) }
                            $changes['RemoveCPMs'] = @($existing + $picks | Select-Object -Unique)
                        }
                    }
                    '^(?i)c$' {
                        $changes.Remove('ManagingCPM')
                        $changes.Remove('ReadOnlyCPMs')
                        $changes.Remove('RemoveCPMs')
                    }
                    '^(?i)b$' { return }
                    default { Write-Host 'Choose 1-5, C or B.' }
                }
            }
        }

        function Show-SafeUpdateMenu {
            $retention = 'not set'
            if ($current.numberOfDaysRetention) { $retention = '{0} day(s)' -f $current.numberOfDaysRetention }
            elseif ($current.numberOfVersionsRetention) { $retention = '{0} version(s)' -f $current.numberOfVersionsRetention }
            $rows = @(
                @('1', 'Safe name', 'NewSafeName', $current.safeName),
                @('2', 'Description', 'Description', $current.description),
                @('3', 'Managing CPM', 'ManagingCPM', $current.managingCPM),
                @('4', 'Location', 'Location', $current.location),
                @('5', 'Retention', 'Retention', $retention)
            )
            Write-Host ''
            if ($lastError) {
                Write-Host ('Last attempt failed: {0}' -f $lastError) -ForegroundColor Red
            }
            Write-Host ("Update safe '{0}' - choose a setting to change:" -f $current.safeName)
            foreach ($r in $rows) {
                $pending = ''
                $key = $r[2]
                if ($key -eq 'Retention') {
                    if ($changes.Contains('NumberOfDaysRetention')) { $pending = ' -> {0} day(s)' -f $changes['NumberOfDaysRetention'] }
                    if ($changes.Contains('NumberOfVersionsRetention')) { $pending = ' -> {0} version(s)' -f $changes['NumberOfVersionsRetention'] }
                } elseif ($changes.Contains($key)) {
                    $pending = ' -> {0}' -f $changes[$key]
                }
                Write-Host ('  {0}) {1,-14} current: {2}{3}' -f $r[0], $r[1], $r[3], $pending)
                if ($key -eq 'ManagingCPM' -and $changes.Contains('ReadOnlyCPMs')) {
                    Write-Host ('     {0,-14}          + read-only access for {1}' -f '', (@($changes['ReadOnlyCPMs']) -join ', '))
                }
                if ($key -eq 'ManagingCPM' -and $changes.Contains('RemoveCPMs')) {
                    Write-Host ('     {0,-14}          - remove from the safe members: {1}' -f '', (@($changes['RemoveCPMs']) -join ', '))
                }
            }
            Write-Host '  A) Apply changes'
            Write-Host '  Q) Quit without changes'
        }

        function Select-FailedSetting {
            # Works out which pending setting the error refers to; asks if it cannot tell.
            param([string]$Message)
            $keys = @($changes.Keys | Where-Object { $_ -notin @('ReadOnlyCPMs', 'RemoveCPMs') })
            if ($keys.Count -eq 1) { return $keys[0] }
            $hits = @($errorHints.Keys | Where-Object { ($keys -contains $_) -and ($Message -match $errorHints[$_]) })
            if ($hits.Count -ge 1) { return $hits[0] }
            Write-Host 'Could not tell which setting caused the failure. Which one should be removed?'
            for ($i = 0; $i -lt $keys.Count; $i++) {
                Write-Host ('  {0}) {1} = {2}' -f ($i + 1), $labels[$keys[$i]], $changes[$keys[$i]])
            }
            Write-Host '  0) Keep them all'
            while ($true) {
                $c = Read-Host ('Enter 0-{0}' -f $keys.Count)
                $n = -1
                if ([int]::TryParse($c, [ref]$n) -and $n -ge 0 -and $n -le $keys.Count) {
                    if ($n -eq 0) { return $null }
                    return $keys[$n - 1]
                }
            }
        }

        $applied = $false
        while (-not $applied) {
            Show-SafeUpdateMenu
            $choice = (Read-Host 'Choice').Trim()
            switch -Regex ($choice) {
                '^1$' {
                    $v = Read-Host 'New safe name (1-28 characters)'
                    if ($v -and $v.Length -le 28) { $changes['NewSafeName'] = $v } elseif ($v) { Write-Warning 'Safe names are limited to 28 characters.' }
                }
                '^2$' {
                    $v = Read-Host 'New description'
                    if ($v) { $changes['Description'] = $v }
                }
                '^3$' { Show-CpmMenu }
                '^4$' {
                    $v = Read-Host 'Location (e.g. \ or \Folder)'
                    if ($v) { $changes['Location'] = $v }
                }
                '^5$' {
                    $t = (Read-Host 'Keep old versions by (D)ays or (V)ersions?').Trim()
                    $unit = 'versions'
                    if ($t -match '^(?i)d') { $unit = 'days' }
                    $nRaw = Read-Host ('Number of {0}' -f $unit)
                    $n = 0
                    if ([int]::TryParse($nRaw, [ref]$n) -and $n -gt 0) {
                        $changes.Remove('NumberOfDaysRetention')
                        $changes.Remove('NumberOfVersionsRetention')
                        if ($unit -eq 'days') { $changes['NumberOfDaysRetention'] = $n } else { $changes['NumberOfVersionsRetention'] = $n }
                    } else {
                        Write-Warning 'Enter a whole number greater than 0.'
                    }
                }
                '^(?i)a$' {
                    if ($changes.Count -eq 0) { Write-Host 'No changes selected yet.'; break }
                    Write-Host ''
                    Write-Host 'Changes to apply:'
                    foreach ($k in $changes.Keys) { Write-Host ('  {0} = {1}' -f $labels[$k], (@($changes[$k]) -join ', ')) }
                    $c = Read-Host 'Apply these changes? (y/N)'
                    if ($c -notmatch '^(?i)y') { break }

                    if (-not $ScriptCmdlet.ShouldProcess(('safe {0}' -f $current.safeName), 'UpdateSafe')) {
                        Write-Host 'WhatIf: no changes sent.'
                        return
                    }
                    $failures = @()
                    $appliedItems = @()

                    # 1. Safe settings (one PUT).
                    $safeKeys = @($changes.Keys | Where-Object { $_ -notin @('ReadOnlyCPMs', 'RemoveCPMs') })
                    $safeOk = $true
                    if ($safeKeys.Count -gt 0) {
                        $spec = @{ SafeName = $current.safeName; NumberOfDaysRetention = 0; NumberOfVersionsRetention = 0 }
                        foreach ($k in $safeKeys) { $spec[$k] = $changes[$k] }
                        try {
                            Invoke-UpdateSafe -Spec $spec -Interactive
                            if ($script:lastUpdateNote) { $appliedItems += $script:lastUpdateNote }
                            foreach ($k in $safeKeys) { $appliedItems += ('{0}={1}' -f $k, $changes[$k]); $changes.Remove($k) }
                            $newName = $current.safeName
                            if ($spec.NewSafeName) { $newName = $spec.NewSafeName }
                            Write-Host ("Safe settings updated for '{0}'." -f $newName) -ForegroundColor Green
                            try { $current = Get-PCloudSafe -SafeName $newName } catch { }
                        } catch {
                            $safeOk = $false
                            $err = $_.Exception.Message
                            $failures += $err
                            Write-Warning ('Safe update failed: {0}' -f $err)
                            $failed = Select-FailedSetting -Message $err
                            if ($failed) {
                                Write-Host ("Removed '{0}' from the pending changes. The other changes are still pending." -f $labels[$failed]) -ForegroundColor Yellow
                                $changes.Remove($failed)
                            }
                            try { $current = Get-PCloudSafe -SafeName $current.safeName } catch { }
                        }
                    }

                    # 2. Read-only CPM access (safe members). Skipped while the safe update is failing.
                    if ($safeOk -and $changes.Contains('ReadOnlyCPMs')) {
                        foreach ($cpm in @($changes['ReadOnlyCPMs'])) {
                            try {
                                $isMember = $false
                                try { $null = Get-PCloudSafeMember -SafeName $current.safeName -MemberName $cpm; $isMember = $true } catch { $isMember = $false }
                                if ($isMember) {
                                    Set-PCloudSafeMember -SafeName $current.safeName -MemberName $cpm -Permission $cpmReadOnlyPermissions -Confirm:$false | Out-Null
                                } else {
                                    Add-PCloudSafeMember -SafeName $current.safeName -MemberName $cpm -MemberType User -SearchIn 'Vault' -Permission $cpmReadOnlyPermissions -Confirm:$false | Out-Null
                                }
                                $appliedItems += ('ReadOnlyCPM={0}' -f $cpm)
                                Write-Host ("Read-only access granted to CPM '{0}'." -f $cpm) -ForegroundColor Green
                            } catch {
                                $err = $_.Exception.Message
                                $failures += ('{0}: {1}' -f $cpm, $err)
                                Write-Warning ("Read-only access for CPM '{0}' failed and was removed from the pending changes: {1}" -f $cpm, $err)
                            }
                        }
                        $changes.Remove('ReadOnlyCPMs')
                    }

                    # 3. Remove other CPMs from the safe members. Skipped while the safe update is failing.
                    if ($safeOk -and $changes.Contains('RemoveCPMs')) {
                        foreach ($cpm in @($changes['RemoveCPMs'])) {
                            if ($cpm -eq $current.managingCPM) {
                                Write-Warning ("'{0}' is now the managing CPM, so it was not removed." -f $cpm)
                                continue
                            }
                            try {
                                $gone = $false
                                try { $null = Get-PCloudSafeMember -SafeName $current.safeName -MemberName $cpm } catch { $gone = $true }
                                if (-not $gone) { Remove-PCloudSafeMember -SafeName $current.safeName -MemberName $cpm -Confirm:$false }
                                $appliedItems += ('RemovedCPM={0}' -f $cpm)
                                Write-Host ("CPM '{0}' removed from the safe members." -f $cpm) -ForegroundColor Green
                            } catch {
                                $err = $_.Exception.Message
                                $failures += ('{0}: {1}' -f $cpm, $err)
                                Write-Warning ("Removing CPM '{0}' from the safe members failed and was dropped from the pending changes: {1}" -f $cpm, $err)
                            }
                        }
                        $changes.Remove('RemoveCPMs')
                    }

                    if (($OutputPath -or $ExportCsv) -and $appliedItems.Count -gt 0) {
                        $out = $OutputPath
                        if (-not $out) { $out = New-PCloudOutputFile -Name 'UpdateSafe' }
                        $out = Resolve-PCloudOutputPath $out
                        New-ResultRow -Row 1 -Safe $current.safeName -Member $null -Status 'Success' -Message ($appliedItems -join '; ') |
                            Export-Csv -LiteralPath $out -NoTypeInformation -Encoding UTF8
                        Write-Host "Result written to $out"
                    }

                    if ($failures.Count -eq 0 -and $changes.Count -eq 0) {
                        $applied = $true
                        $lastError = $null
                        Write-Host ("Safe '{0}' updated." -f $current.safeName) -ForegroundColor Green
                    } else {
                        $lastError = $failures -join ' / '
                        if ($changes.Count -eq 0) {
                            Write-Host 'Nothing else is pending. Make more changes, or Q to finish.' -ForegroundColor Yellow
                        }
                    }
                }
                '^(?i)q$' {
                    Write-Host 'No changes made.'
                    return
                }
                default { Write-Host 'Choose 1-5, A or Q.' }
            }
        }
        # Applied from the menu; nothing left for the batch loop below.
        return
    }

    # Build the list of work items.
    $specs = New-Object System.Collections.Generic.List[object]
    $buildErrors = New-Object System.Collections.Generic.List[object]
    if ($CsvPath) {
        if (-not (Test-Path -LiteralPath $CsvPath)) { throw "CSV not found: $CsvPath" }
        $rows = @(Import-Csv -LiteralPath $CsvPath)
        if ($rows.Count -eq 0) { throw "CSV has no rows: $CsvPath" }
        $r = 0
        foreach ($row in $rows) {
            $r++
            try { $specs.Add((ConvertTo-Spec -Row $row -Index $r)) }
            catch { $buildErrors.Add((New-ResultRow -Row $r -Safe (Get-RowValue $row 'SafeName') -Member (Get-RowValue $row 'MemberName') -Status 'Failed' -Message $_.Exception.Message)) }
        }
    } else {
        $specs.Add((ConvertTo-Spec -Row $null -Index 1))
    }

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($b in $buildErrors) { $results.Add($b) }
    $isWrite = @('AddSafe', 'UpdateSafe', 'AddSafeMember', 'UpdateSafeMember') -contains $Action

    $i = 0
    foreach ($spec in $specs) {
        $i++
        Write-Progress -Activity $Action -Status ('{0} of {1}: {2} {3}' -f $i, $specs.Count, $spec.SafeName, $spec.MemberName) -PercentComplete (($i / [Math]::Max($specs.Count, 1)) * 100)
        try {
            switch ($Action) {
                'GetSafes' {
                    foreach ($s in @(Invoke-GetSafes -Name $spec.SafeName -Text $spec.Search)) { $results.Add($s) }
                }
                'GetSafeDetails' {
                    if (-not $spec.SafeName) { throw 'SafeName is required.' }
                    $results.Add((Invoke-GetSafeDetails -Name $spec.SafeName))
                }
                'GetSafeMembers' {
                    $names = @()
                    if ($spec.SafeName) { $names = @($spec.SafeName) } else { $names = @(Get-PCloudSafe | ForEach-Object { $_.safeName }) }
                    $k = 0
                    foreach ($n in $names) {
                        $k++
                        if ($names.Count -gt 1) {
                            Write-Progress -Id 1 -ParentId 0 -Activity 'Reading safe members' -Status $n -PercentComplete (($k / $names.Count) * 100)
                        }
                        try {
                            foreach ($m in @(Invoke-GetSafeMembers -Name $n -Member $spec.MemberName)) { $results.Add($m) }
                        } catch {
                            Write-Warning ('{0}: {1}' -f $n, $_.Exception.Message)
                        }
                    }
                    if ($names.Count -gt 1) { Write-Progress -Id 1 -Activity 'Reading safe members' -Completed }
                }
                default {
                    if (-not $spec.SafeName) { throw 'SafeName is required.' }
                    $member = $null
                    if ($Action -like '*Member') {
                        if (-not $spec.MemberName) { throw 'MemberName is required.' }
                        $member = $spec.MemberName
                        $target = '{0} on safe {1}' -f $spec.MemberName, $spec.SafeName
                    } else {
                        $target = 'safe {0}' -f $spec.SafeName
                    }
                    if ($ScriptCmdlet.ShouldProcess($target, $Action)) {
                        $script:lastUpdateNote = ''
                        switch ($Action) {
                            'AddSafe' { Invoke-AddSafe -Spec $spec }
                            'UpdateSafe' { Invoke-UpdateSafe -Spec $spec }
                            'AddSafeMember' { Invoke-AddSafeMember -Spec $spec }
                            'UpdateSafeMember' { Invoke-UpdateSafeMember -Spec $spec }
                        }
                        $note = ''
                        if ($Action -eq 'UpdateSafe') { $note = $script:lastUpdateNote }
                        $results.Add((New-ResultRow -Row $spec.Index -Safe $spec.SafeName -Member $member -Status 'Success' -Message $note))
                    } else {
                        $results.Add((New-ResultRow -Row $spec.Index -Safe $spec.SafeName -Member $member -Status 'WhatIf'))
                    }
                }
            }
        } catch {
            $msg = $_.Exception.Message
            Write-Warning ('Row {0} ({1} {2}): {3}' -f $spec.Index, $spec.SafeName, $spec.MemberName, $msg)
            if ($isWrite) {
                $results.Add((New-ResultRow -Row $spec.Index -Safe $spec.SafeName -Member $spec.MemberName -Status 'Failed' -Message $msg))
            }
        }
    }
    Write-Progress -Activity $Action -Completed

    if ($isWrite) {
        $results | Sort-Object Row | Format-Table Row, SafeName, MemberName, Status, Message -AutoSize -Wrap | Out-String | Write-Host
        $ok = @($results | Where-Object { $_.Status -eq 'Success' }).Count
        $bad = @($results | Where-Object { $_.Status -eq 'Failed' }).Count
        Write-Host ('{0}: {1} succeeded, {2} failed.' -f $Action, $ok, $bad)
    } elseif ($Action -eq 'GetSafeMembers') {
        $results | Format-Table SafeName, MemberName, MemberType, Preset, IsReadOnly, ExpirationDate -AutoSize -Wrap | Out-String | Write-Host
        if (@($results | Where-Object { $_.TypeSource -eq 'API' }).Count -gt 0 -and @($results | Where-Object { $_.TypeSource -eq 'Identity' }).Count -eq 0) {
            Write-Host 'Note: Identity roles could not be read with this sign-in, so member types are shown as the API reports them (roles may appear as Group).' -ForegroundColor Yellow
        }
        Write-Host ('{0} membership(s). Every individual permission is in the CSV export.' -f $results.Count)
    } elseif ($Action -eq 'GetSafeDetails' -and $results.Count -le 3 -and -not $OutputPath) {
        $results | Format-List
    } else {
        $results | Format-Table SafeName, Description, ManagingCPM, NumberOfDaysRetention, NumberOfVersionsRetention, OLACEnabled, Created -AutoSize
        Write-Host ('{0} safe(s).' -f $results.Count)
    }

    if ($OutputPath) {
        $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
        $results | Export-Csv -LiteralPath $full -NoTypeInformation -Encoding UTF8
        Write-Host ('{0} row(s) written to {1}' -f $results.Count, $full)
    }
}

function Read-ExistingFile {
    param([string]$Prompt)
    while ($true) {
        $f = Read-Host $Prompt
        if (-not $f) { return '' }
        if ($f -match '^(?i)b$') { return $null }
        $f = $f.Trim('"')
        if (Test-Path -LiteralPath $f -PathType Leaf) { return $f }
        Write-Host ("  File not found: {0}" -f $f) -ForegroundColor Red
    }
}

# ---------- Non-interactive: -Action given. Runs once; errors end the script as usual.
if ($Action) {
    if ($ExportCsv -and -not $OutputPath) {
        $OutputPath = New-PCloudOutputFile -Name $Action
    }
    if (-not $CsvPath) {
        if ($Action -ne 'GetSafes' -and $Action -ne 'GetSafeMembers' -and -not $SafeName) { $SafeName = Read-Host 'Safe name' }
        if (($Action -eq 'AddSafeMember' -or $Action -eq 'UpdateSafeMember') -and -not $MemberName) { $MemberName = Read-Host 'Member name' }
        if ($Action -eq 'AddSafeMember' -and -not $Preset -and -not $Permission) {
            $Preset = Read-Host 'Permission preset [ReadOnly] (None, ConnectOnly, ReadOnly, Approver, AccountsManager, Full)'
            if (-not $Preset) { $Preset = 'ReadOnly' }
            if ($validPresets -notcontains $Preset) { throw ("Preset must be one of: {0}" -f ($validPresets -join ', ')) }
        }
    }
    Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod
    Invoke-SafeAction
    return
}

# ---------- Menu mode: loops until Q. Any failure returns to the previous prompt or the main menu.
Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod

$original = @{
    CsvPath    = $CsvPath
    SafeName   = $SafeName
    MemberName = $MemberName
    Preset     = $Preset
    OutputPath = $OutputPath
    ExportCsv  = [bool]$ExportCsv
    MemberType = $MemberType
}

while ($true) {
    # Start every pass from the values the script was launched with.
    $CsvPath = $original.CsvPath
    $SafeName = $original.SafeName
    $MemberName = $original.MemberName
    $Preset = $original.Preset
    $OutputPath = $original.OutputPath
    $ExportCsv = $original.ExportCsv
    $MemberType = $original.MemberType
    $Action = $null

    Write-Host ''
    Write-Host 'Safe management - choose an action:'
    for ($i = 0; $i -lt $actions.Count; $i++) { Write-Host ('  {0}) {1}' -f ($i + 1), $actions[$i]) }
    Write-Host '  Q) Quit'
    $c = (Read-Host ('Enter 1-{0} or Q' -f $actions.Count)).Trim()
    if ($c -match '^(?i)q$') { break }
    $n = 0
    if (-not ([int]::TryParse($c, [ref]$n) -and $n -ge 1 -and $n -le $actions.Count)) {
        Write-Host 'Invalid choice.' -ForegroundColor Yellow
        continue
    }
    $Action = $actions[$n - 1]

    try {
        $back = $false

        # CSV or single item (GetSafes with nothing given lists every safe, so it skips this).
        if ($Action -ne 'GetSafes' -and -not $CsvPath -and -not $SafeName) {
            $f = Read-ExistingFile -Prompt 'CSV file path (leave blank for a single item, B to go back)'
            if ($null -eq $f) { $back = $true } elseif ($f) { $CsvPath = $f }
        }
        if ($back) { continue }

        if (($readActions -contains $Action) -and -not $OutputPath -and -not $ExportCsv) {
            $ans = Read-Host 'Save results to CSV? Enter a file path, Y for an automatic name, or leave blank to skip'
            if ($ans -match '^(?i)(y|yes)$') { $ExportCsv = $true } elseif ($ans) { $OutputPath = $ans }
        }
        if ($ExportCsv -and -not $OutputPath) {
            $OutputPath = New-PCloudOutputFile -Name $Action
        }

        if (-not $CsvPath) {
            switch ($Action) {
                'GetSafeMembers' {
                    if (-not $SafeName) {
                        $SafeName = (Read-Host 'Safe name or part of it (leave blank for every safe)').Trim()
                        if ($SafeName) {
                            $SafeName = Resolve-SafeChoice -Text $SafeName
                            if (-not $SafeName) { $SafeName = Read-ExistingSafeName }
                            if (-not $SafeName) { $back = $true }
                        }
                    }
                }
                'GetSafes' { }
                'AddSafe' {
                    if (-not $SafeName) {
                        $SafeName = Read-Host 'New safe name (leave blank to go back)'
                        if (-not $SafeName) { $back = $true }
                    }
                }
                default {
                    # Every other action works on an existing safe: check it before going further.
                    if (-not $SafeName) {
                        $SafeName = Read-ExistingSafeName
                        if (-not $SafeName) { $back = $true }
                    }
                }
            }
            if ($back) { continue }

            if (($Action -eq 'AddSafeMember' -or $Action -eq 'UpdateSafeMember') -and -not $MemberName) {
                $MemberName = Read-Host 'Member name (leave blank to go back)'
                if (-not $MemberName) { continue }
            }
            if ($Action -eq 'AddSafeMember' -and $MemberType -eq 'Auto') {
                $det = Resolve-PCloudSafeMemberType -MemberName $MemberName
                $how = 'from Identity'
                if ($det.Source -eq 'Guess') { $how = 'guessed from the name; Identity could not confirm it' }
                Write-Host ("Detected member type: {0} ({1})." -f $det.MemberType, $how)
                while ($true) {
                    $t = (Read-Host ('Press Enter to use {0}, or type User, Group or Role' -f $det.MemberType)).Trim()
                    if (-not $t) { $MemberType = $det.MemberType; break }
                    $hit = @('User', 'Group', 'Role') | Where-Object { $_ -eq $t }
                    if ($hit) { $MemberType = [string]$hit; break }
                    Write-Host '  Enter User, Group or Role.' -ForegroundColor Red
                }
            }
            if ($Action -eq 'AddSafeMember' -and -not $Preset -and -not $Permission) {
                while ($true) {
                    $Preset = Read-Host 'Permission preset [ReadOnly] (None, ConnectOnly, ReadOnly, Approver, AccountsManager, Full)'
                    if (-not $Preset) { $Preset = 'ReadOnly' }
                    if (@('None', 'ConnectOnly', 'ReadOnly', 'Approver', 'AccountsManager', 'Full') -contains $Preset) { break }
                    Write-Host '  Unknown preset.' -ForegroundColor Red
                }
            }
        }

        Invoke-SafeAction
    } catch {
        Write-Host ''
        Write-Host ('{0} failed: {1}' -f $Action, $_.Exception.Message) -ForegroundColor Red
        Write-Host 'Returning to the main menu.' -ForegroundColor Yellow
    }
}
