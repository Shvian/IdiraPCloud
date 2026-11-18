#Requires -Version 5.1
<#
.SYNOPSIS
    Account management for Idira Privilege Cloud: list, view, add, update and delete accounts, run
    CPM Change / Verify / Reconcile, and retrieve a password. Actions work on one account or on every
    row of a CSV, the same way as Manage-Safes.ps1.
.DESCRIPTION
    Actions:
      GetAccounts          List accounts. With nothing specified, returns every account you can see.
                           Single: -SafeName and/or -Search (any number of keywords; partial words match;
                           each keyword must appear in the ID, name, user, address, safe or platform).  CSV columns: SafeName, Search.
      GetAccountDetails    Every field of an account, including each platform property as a prop_<Name>
                           column. Single: -AccountId, or -SafeName -UserName [-Address].
                           CSV columns: AccountId, or SafeName, UserName, Address.
      AddAccount           Onboard accounts. From the menu you pick the safe and platform from lists, and
                           the password is asked with a masked prompt (or left empty for the CPM to reconcile).
                           CSV columns: SafeName, PlatformId, UserName, Address, Name, SecretType, Secret,
                           AutomaticManagement, ManualManagementReason, RemoteMachines (a;b), prop_<Name>.
                           CSV onboarding never asks for passwords. If the CSV has a Secret column (the
                           password or key; a Password column also works), each value becomes a SecureString
                           as it is read and the plain text is cleared. A row with no secret is still created,
                           without one, and the output notes it. Delete a CSV with passwords securely.
                           Passwords are only asked when adding one account at a time.
                           -PromptForPasswords applies to a single account without -CsvPath.
      UpdateAccount        Change name, address, user name, platform, platform properties and automatic
                           management. For a single account with no new values given, a menu shows the current
                           values and lets you pick what to change. All changes go in one request; if it fails,
                           the failing change is dropped and the menu returns with the rest still pending.
                           CSV columns: AccountId (or SafeName, UserName, Address), NewName, NewAddress,
                           NewUserName, NewPlatformId, AutomaticManagement, ManualManagementReason,
                           prop_<Name> (a value sets it, "(remove)" removes it).
      LinkAccount          Link a logon, enable or reconcile account (whatever the account's platform
                           offers). From the menu: choose the account, pick the link type read from its
                           platform, then find the linked account by ID, by searching a safe, or by typing the
                           safe and object name. CSV columns: AccountId (or SafeName, UserName, Address),
                           LinkType (name such as LogonAccount, or the index number), LinkedAccountId or
                           LinkedSafe + LinkedName, LinkedFolder (default Root).
      UnlinkAccount        Remove a linked account. CSV columns: AccountId (or lookup), LinkType.
      DeleteAccount        Delete accounts. You type DELETE to confirm (or pass -Force). Supports -WhatIf.
                           CSV columns: as GetAccountDetails.
      ChangeCredential     Mark accounts for an immediate CPM password change.
      VerifyCredential     Mark accounts for CPM verification.
      ReconcileCredential  Mark accounts for CPM reconciliation.
                           CSV columns for the three credential actions: as GetAccountDetails.
      RetrievePassword     Retrieves one password with a reason (audited) and puts it on the clipboard,
                           cleared automatically. Uses Get-AccountPassword.ps1. Single account only:
                           bulk password retrieval is deliberately not offered.
      AccountDependents    Opens the account dependents submenu (Manage-AccountDependents.ps1): list, view, add,
                           update and delete the Windows services, scheduled tasks and other dependents of an
                           account, and link or unlink accounts to them. -AccountId opens it on that account.

    Run without -Action to pick from a menu. Prompts for sign-in if there is no active session.
    The menu loops until you choose Q: invalid names and paths are asked again, and any failure returns
    you to the previous prompt or the main menu instead of ending the script.
    CSV export: -ExportCsv saves results to CSVs\PCloud-<Action>-<timestamp>.csv in the IdiraPCloud folder, or -OutputPath <file>.
    Exports never contain passwords.
.EXAMPLE
    .\Manage-Accounts.ps1
.EXAMPLE
    .\Manage-Accounts.ps1 -Action GetAccounts -SafeName 'Linux-Root' -ExportCsv
.EXAMPLE
    .\Manage-Accounts.ps1 -Action GetAccountDetails -CsvPath .\samples\accounts-ids.csv -OutputPath .\details.csv
.EXAMPLE
    .\Manage-Accounts.ps1 -Action AddAccount -CsvPath .\samples\accounts-add.csv -WhatIf
.EXAMPLE
    .\Manage-Accounts.ps1 -Action UpdateAccount -AccountId 12_34
    # opens the update menu for that account
.EXAMPLE
    .\Manage-Accounts.ps1 -Action UpdateAccount -CsvPath .\samples\accounts-update.csv
.EXAMPLE
    .\Manage-Accounts.ps1 -Action LinkAccount -AccountId 12_34 -LinkType ReconcileAccount -LinkedSafe 'Recon' -LinkedName 'Operating System-WinDomain-acme.local-svc_recon'
.EXAMPLE
    .\Manage-Accounts.ps1 -Action LinkAccount -CsvPath .\samples\accounts-link.csv -WhatIf
.EXAMPLE
    .\Manage-Accounts.ps1 -Action ReconcileCredential -SafeName 'Win-Servers' -UserName 'Administrator' -Address 'srv01'
.EXAMPLE
    .\Manage-Accounts.ps1 -Action RetrievePassword -AccountId 12_34 -Reason 'CHG0012345'
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Validated below rather than with [ValidateSet()] because the menu loop reassigns it.
    [ArgumentCompleter({ param($c, $p, $w) 'GetAccounts', 'GetAccountDetails', 'AddAccount', 'UpdateAccount', 'LinkAccount', 'UnlinkAccount', 'DeleteAccount', 'ChangeCredential', 'VerifyCredential', 'ReconcileCredential', 'RetrievePassword', 'AccountDependents' | Where-Object { $_ -like "$w*" } })]
    [string]$Action,

    [string]$CsvPath,
    [string]$OutputPath,
    [switch]$ExportCsv,
    [switch]$Force,

    # Find an account
    [string]$AccountId,
    [string]$SafeName,
    [string]$UserName,
    [string]$Address,
    [string]$Search,

    # AddAccount
    [string]$Name,
    [string]$PlatformId,
    [System.Security.SecureString]$Secret,
    [switch]$PromptForPasswords,
    [hashtable]$PlatformAccountProperties,
    [switch]$DisableAutomaticManagement,
    [string]$ManualManagementReason,

    # UpdateAccount (single, without the menu)
    [string]$NewName,
    [string]$NewAddress,
    [string]$NewUserName,
    [string]$NewPlatformId,
    [ArgumentCompleter({ param($c, $p, $w) 'true', 'false' | Where-Object { $_ -like "$w*" } })]
    [string]$AutomaticManagement,

    # LinkAccount / UnlinkAccount. LinkType: a name such as LogonAccount or ReconcileAccount, or the index number.
    [string]$LinkType,
    [string]$LinkedAccountId,
    [string]$LinkedSafe,
    [string]$LinkedName,
    [string]$LinkedFolder = 'Root',

    # RetrievePassword
    [string]$Reason,
    [string]$TicketingSystemName,
    [string]$TicketId,

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

$actions = @('GetAccounts', 'GetAccountDetails', 'AddAccount', 'UpdateAccount', 'LinkAccount', 'UnlinkAccount', 'DeleteAccount', 'ChangeCredential', 'VerifyCredential', 'ReconcileCredential', 'RetrievePassword', 'AccountDependents')
$actionHelp = @{
    AccountDependents   = 'Windows services, scheduled tasks and other dependents of an account (submenu)'
    GetAccounts         = 'list accounts (all, by safe, or by search)'
    GetAccountDetails   = 'every field of an account, including platform properties'
    AddAccount          = 'onboard an account'
    UpdateAccount       = 'change name, address, user, platform, properties, automatic management'
    LinkAccount         = 'link a logon, enable or reconcile account'
    UnlinkAccount       = 'remove a linked account'
    DeleteAccount       = 'delete an account'
    ChangeCredential    = 'CPM change now'
    VerifyCredential    = 'CPM verify'
    ReconcileCredential = 'CPM reconcile'
    RetrievePassword    = 'copy one password to the clipboard (audited, cleared automatically)'
}
$readActions = @('GetAccounts', 'GetAccountDetails')
if ($Action) {
    $m = @($actions | Where-Object { $_ -eq $Action })
    if ($m.Count -eq 0) { throw ("-Action must be one of: {0}" -f ($actions -join ', ')) }
    $Action = $m[0]
}
if ($AutomaticManagement) { $null = ConvertTo-OptionalBool $AutomaticManagement 'AutomaticManagement' }

$PSBoundParameters_Main = $PSBoundParameters
$ScriptCmdlet = $PSCmdlet
$script:platformCache = $null
$script:linkTypeCache = $null
$removeWord = '(remove)'

# ------------------------------------------------------------------ helpers

function Format-AccountRow {
    param($Account, [switch]$Detailed)
    $auto = Get-NestedValue $Account 'secretManagement.automaticManagementEnabled'
    $o = [ordered]@{
        AccountId              = $Account.id
        Name                   = $Account.name
        SafeName               = $Account.safeName
        PlatformId             = $Account.platformId
        UserName               = $Account.userName
        Address                = $Account.address
        SecretType             = $Account.secretType
        AutomaticManagement    = $auto
        ManualManagementReason = Get-NestedValue $Account 'secretManagement.manualManagementReason'
        CPMStatus              = Get-NestedValue $Account 'secretManagement.status'
        LastModified           = ConvertFrom-PCloudUnixTime (Get-NestedValue $Account 'secretManagement.lastModifiedTime')
        LastVerified           = ConvertFrom-PCloudUnixTime (Get-NestedValue $Account 'secretManagement.lastVerifiedTime')
        LastReconciled         = ConvertFrom-PCloudUnixTime (Get-NestedValue $Account 'secretManagement.lastReconciledTime')
        Created                = ConvertFrom-PCloudUnixTime $Account.createdTime
    }
    if ($Detailed) {
        $o['RemoteMachines'] = Get-NestedValue $Account 'remoteMachinesAccess.remoteMachines'
        $o['AccessRestrictedToRemoteMachines'] = Get-NestedValue $Account 'remoteMachinesAccess.accessRestrictedToRemoteMachines'
        $props = Get-NestedValue $Account 'platformAccountProperties'
        if ($props) {
            # Each property is a column named after it (Notes), so the file can go straight back into an update.
            # A property whose name matches one of the account columns keeps the prop_ prefix.
            foreach ($p in $props.PSObject.Properties) {
                $col = $p.Name
                if ($script:AccountCsvColumns -contains $col -or $o.Contains($col)) { $col = 'prop_{0}' -f $p.Name }
                $o[$col] = $p.Value
            }
        }
    }
    [pscustomobject]$o
}

function Get-AccountProperties {
    # Platform account properties as an ordered name -> value map.
    param($Account)
    $map = [ordered]@{}
    $props = Get-NestedValue $Account 'platformAccountProperties'
    if ($props) { foreach ($p in $props.PSObject.Properties) { $map[$p.Name] = $p.Value } }
    return $map
}

function Find-Account {
    # One account by ID, or by safe + user name (+ address). Throws if none or several match.
    param([string]$Id, [string]$Safe, [string]$User, [string]$Addr)
    if ($Id) { return (Get-PCloudAccount -Id $Id) }
    if (-not $Safe -or -not $User) { throw 'Give AccountId, or SafeName and UserName (and Address if needed).' }
    $text = (@($User, $Addr) | Where-Object { $_ }) -join ' '
    $found = @(Get-PCloudAccount -SafeName $Safe -Search $text | Where-Object {
            $_.userName -eq $User -and (-not $Addr -or [string]$_.address -eq $Addr)
        })
    if ($found.Count -eq 0) { throw ("No account for user '{0}'{1} in safe '{2}'." -f $User, $(if ($Addr) { " at $Addr" } else { '' }), $Safe) }
    if ($found.Count -gt 1) {
        throw ('{0} accounts match; add Address or use AccountId: {1}' -f $found.Count, ((@($found | ForEach-Object { '{0} ({1}@{2})' -f $_.id, $_.userName, $_.address })) -join ', '))
    }
    return $found[0]
}

function Get-TargetPlatforms {
    # Active target platforms, cached for the run; falls back to all target platforms.
    if ($null -ne $script:platformCache) { return $script:platformCache }
    $list = @()
    try { $list = @(Get-PCloudTargetPlatform | Where-Object { $_.Active -eq $true }) } catch {
        Write-Verbose ('Could not read target platforms: {0}' -f $_.Exception.Message)
    }
    $script:platformCache = @($list | Sort-Object PlatformID)
    return $script:platformCache
}

function Read-PlatformId {
    # Pick an active platform from the list, or type its ID. Returns the PlatformID or $null (back).
    param([string]$Prompt = 'Platform')
    $list = @(Get-TargetPlatforms)
    if ($list.Count -eq 0) {
        Write-Warning 'Could not list platforms. Type the platform ID instead.'
        $v = Read-Host 'Platform ID (leave blank to go back)'
        if (-not $v) { return $null }
        return $v
    }
    $pick = Select-FromList -Items $list -Title ('{0} (active platforms)' -f $Prompt) -Label { param($x) '{0}  -  {1} ({2})' -f $x.PlatformID, $x.Name, $x.SystemType }
    if ($null -eq $pick) { return $null }
    return [string]$pick.PlatformID
}

$script:PlatformPropertyCache = @{}

function Get-PlatformPropertyList {
    # The platform's required and optional account properties (Name, DisplayName, Required), read once per
    # platform from GET /API/Platforms. Returns $null when they can't be read, so callers fall back to the
    # name as typed.
    param([string]$PlatformId)
    if (-not $PlatformId) { return $null }
    $key = $PlatformId.ToLowerInvariant()
    if ($script:PlatformPropertyCache.ContainsKey($key)) { return $script:PlatformPropertyCache[$key] }
    $found = $null
    try {
        foreach ($p in @(Get-PCloudPlatform)) {
            if ([string](Get-NestedValue $p 'general.id') -ne $PlatformId) { continue }
            $list = New-Object System.Collections.Generic.List[object]
            foreach ($grp in @('required', 'optional')) {
                foreach ($x in @(Get-NestedValue $p ('properties.{0}' -f $grp))) {
                    if ($null -eq $x) { continue }
                    $n = [string](Get-NestedValue $x 'name')
                    if (-not $n) { continue }
                    $list.Add([pscustomobject]@{ Name = $n; DisplayName = [string](Get-NestedValue $x 'displayName'); Required = ($grp -eq 'required') })
                }
            }
            $found = $list.ToArray()
            break
        }
    } catch {
        Write-Verbose ('Could not read the properties of platform {0}: {1}' -f $PlatformId, $_.Exception.Message)
    }
    $script:PlatformPropertyCache[$key] = $found
    return $found
}

function Format-PlatformProperty {
    param($Item)
    $t = $Item.Name
    if ($Item.DisplayName -and $Item.DisplayName -ne $Item.Name) { $t = '{0} ("{1}")' -f $Item.Name, $Item.DisplayName }
    if ($Item.Required) { $t += ' [required]' }
    return $t
}

function Resolve-PlatformPropertyName {
    # Returns the platform's own spelling of a property, matched by name or display name (any case).
    # Throws when the platform's properties are known and the name isn't one of them, because the API
    # rejects it (PASWS125E "Property ... cannot be added").
    param([string]$PlatformId, [string]$Name)
    $list = @(Get-PlatformPropertyList -PlatformId $PlatformId)
    if ($list.Count -eq 0 -or $null -eq $list[0]) { return $Name }
    $hit = @($list | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1
    if (-not $hit) { $hit = @($list | Where-Object { $_.DisplayName -eq $Name }) | Select-Object -First 1 }
    if ($hit) { return $hit.Name }
    $names = (@($list | ForEach-Object { Format-PlatformProperty $_ })) -join ', '
    throw ("Property '{0}' is not defined on platform {1}, so the account can't hold it. Add it to the platform's optional properties first, or use one of: {2}" -f $Name, $PlatformId, $names)
}

function Get-CsvSecretColumn {
    # Name of the Secret (or Password) column in a CSV, or $null when there is none.
    param([object[]]$Rows)
    if ($Rows.Count -eq 0) { return $null }
    foreach ($n in @('Secret', 'Password')) {
        $c = $Rows[0].PSObject.Properties | Where-Object { $_.Name -eq $n } | Select-Object -First 1
        if ($c) { return $c.Name }
    }
    return $null
}

function ConvertFrom-CsvSecret {
    # Moves a row's secret into a read-only SecureString and clears the plain text from the row.
    # Returns $null when the value is empty. The value is not trimmed: spaces can be part of a password.
    param($Row, [string]$Column)
    $plain = [string]$Row.$Column
    $Row.$Column = $null
    if (-not $plain) { return $null }
    $ss = New-Object System.Security.SecureString
    foreach ($ch in $plain.ToCharArray()) { $ss.AppendChar($ch) }
    $ss.MakeReadOnly()
    $plain = $null
    return $ss
}

function Read-Secret {
    # Masked password prompt. Returns a SecureString, or $null when left empty.
    param([string]$Label)
    $s = Read-Host -AsSecureString -Prompt ('Password for {0} (masked; press Enter to leave it empty for the CPM to reconcile)' -f $Label)
    if ($null -eq $s -or $s.Length -eq 0) { if ($s) { $s.Dispose() }; return $null }
    return $s
}

# ------------------------------------------------------------------ specs and changes

# CSV columns the script reads itself, plus the read-only columns of its own exports (so an export can be
# edited and fed back). For AddAccount and UpdateAccount, any other column is a platform property, with or
# without the prop_ prefix.
$script:AccountCsvColumns = @(
    'AccountId', 'SafeName', 'UserName', 'Address', 'Search', 'Name', 'PlatformId', 'SecretType',
    'AutomaticManagement', 'ManualManagementReason', 'RemoteMachines', 'AccessRestrictedToRemoteMachines',
    'NewName', 'NewAddress', 'NewUserName', 'NewPlatformId',
    'LinkType', 'LinkedAccountId', 'LinkedSafe', 'LinkedName', 'LinkedFolder', 'Secret', 'Password',
    'CPMStatus', 'LastModified', 'LastVerified', 'LastReconciled', 'Created',
    'Row', 'Action', 'Target', 'Id', 'Status', 'Message'
)

function ConvertTo-AccountSpec {
    # Normalized work item from a CSV row, or from the script's single-mode parameters when $Row is $null.
    param($Row, [int]$Index)
    if ($null -ne $Row) {
        $props = [ordered]@{}
        $bareProps = ($Action -eq 'AddAccount' -or $Action -eq 'UpdateAccount')
        foreach ($col in $Row.PSObject.Properties) {
            if ($null -eq $col.Value -or ([string]$col.Value).Trim() -eq '') { continue }
            $pn = $null
            if ($col.Name -like 'prop_*') { $pn = $col.Name.Substring(5) }
            elseif ($bareProps -and $script:AccountCsvColumns -notcontains $col.Name) { $pn = $col.Name.Trim() }
            if ($pn) { $props[$pn] = ([string]$col.Value).Trim() }
        }
        return @{
            Index                  = $Index
            AccountId              = Get-RowValue $Row 'AccountId'
            SafeName               = Get-RowValue $Row 'SafeName'
            UserName               = Get-RowValue $Row 'UserName'
            Address                = Get-RowValue $Row 'Address'
            Search                 = Get-RowValue $Row 'Search'
            Name                   = Get-RowValue $Row 'Name'
            PlatformId             = Get-RowValue $Row 'PlatformId'
            SecretType             = Get-RowValue $Row 'SecretType'
            AutomaticManagement    = ConvertTo-OptionalBool (Get-RowValue $Row 'AutomaticManagement') 'AutomaticManagement'
            ManualManagementReason = Get-RowValue $Row 'ManualManagementReason'
            RemoteMachines         = @(Split-ListValue (Get-RowValue $Row 'RemoteMachines'))
            Properties             = $props
            NewName                = Get-RowValue $Row 'NewName'
            NewAddress             = Get-RowValue $Row 'NewAddress'
            NewUserName            = Get-RowValue $Row 'NewUserName'
            NewPlatformId          = Get-RowValue $Row 'NewPlatformId'
            LinkType               = Get-RowValue $Row 'LinkType'
            LinkedAccountId        = Get-RowValue $Row 'LinkedAccountId'
            LinkedSafe             = Get-RowValue $Row 'LinkedSafe'
            LinkedName             = Get-RowValue $Row 'LinkedName'
            LinkedFolder           = Get-RowValue $Row 'LinkedFolder'
            Secret                 = $null
        }
    }
    $props = [ordered]@{}
    if ($PlatformAccountProperties) { foreach ($k in $PlatformAccountProperties.Keys) { $props[[string]$k] = $PlatformAccountProperties[$k] } }
    $auto = ConvertTo-OptionalBool $AutomaticManagement 'AutomaticManagement'
    if ($Action -eq 'AddAccount' -and $DisableAutomaticManagement) { $auto = $false }
    return @{
        Index                  = 1
        AccountId              = $AccountId
        SafeName               = $SafeName
        UserName               = $UserName
        Address                = $Address
        Search                 = $Search
        Name                   = $Name
        PlatformId             = $PlatformId
        SecretType             = ''
        AutomaticManagement    = $auto
        ManualManagementReason = $ManualManagementReason
        RemoteMachines         = @()
        Properties             = $props
        NewName                = $NewName
        NewAddress             = $NewAddress
        NewUserName            = $NewUserName
        NewPlatformId          = $NewPlatformId
        LinkType               = $LinkType
        LinkedAccountId        = $LinkedAccountId
        LinkedSafe             = $LinkedSafe
        LinkedName             = $LinkedName
        LinkedFolder           = $LinkedFolder
        Secret                 = $Secret
    }
}

function Add-AccountChange {
    # Adds one pending change (same keys in the menu and in CSV/parameter updates).
    param([System.Collections.IDictionary]$Changes, [string]$Key, $Value, $Account)
    switch -Regex ($Key) {
        '^Name$' { $Changes[$Key] = New-PendingChange -Label 'Account name' -Value $Value -Hint '(?i)\bname\b|already exists' }
        '^Address$' { $Changes[$Key] = New-PendingChange -Label 'Address' -Value $Value -Hint '(?i)address' }
        '^UserName$' { $Changes[$Key] = New-PendingChange -Label 'User name' -Value $Value -Hint '(?i)user ?name' }
        '^PlatformId$' { $Changes[$Key] = New-PendingChange -Label 'Platform' -Value $Value -Hint '(?i)platform' }
        '^AutoMgmt$' {
            $d = 'On'
            if (-not $Value.Enabled) { $d = 'Off'; if ($Value.Reason) { $d = 'Off ({0})' -f $Value.Reason } }
            $Changes[$Key] = New-PendingChange -Label 'Automatic management' -Value $Value -Display $d -Hint '(?i)automaticManagement|manualManagementReason|secretManagement'
        }
        '^prop:(.+)$' {
            $pn = $Key.Substring(5)
            $d = [string]$Value
            if ($null -eq $Value) { $d = $removeWord }
            $Changes[$Key] = New-PendingChange -Label ('Property {0}' -f $pn) -Value $Value -Display $d -Hint ('(?i)\b{0}\b' -f [regex]::Escape($pn))
        }
    }
}

function ConvertTo-AccountOperations {
    # Builds the JSON Patch operations for the pending changes against the account's current state.
    param($Account, [System.Collections.IDictionary]$Changes)
    $ops = New-Object System.Collections.Generic.List[object]
    $existing = Get-AccountProperties $Account
    $propSet = [ordered]@{}
    $propRemove = New-Object System.Collections.Generic.List[string]
    # Properties are checked against the platform the account will be on after this update.
    $targetPlatform = [string]$Account.platformId
    if ($Changes.Contains('PlatformId')) { $targetPlatform = [string]$Changes['PlatformId'].Value }
    foreach ($k in $Changes.Keys) {
        $v = $Changes[$k].Value
        switch -Regex ($k) {
            '^Name$' { $ops.Add([ordered]@{ op = 'replace'; path = '/name'; value = [string]$v }) }
            '^Address$' { $ops.Add([ordered]@{ op = 'replace'; path = '/address'; value = [string]$v }) }
            '^UserName$' { $ops.Add([ordered]@{ op = 'replace'; path = '/userName'; value = [string]$v }) }
            '^PlatformId$' { $ops.Add([ordered]@{ op = 'replace'; path = '/platformId'; value = [string]$v }) }
            '^AutoMgmt$' {
                $ops.Add([ordered]@{ op = 'replace'; path = '/secretManagement/automaticManagementEnabled'; value = [bool]$v.Enabled })
                if (-not $v.Enabled -and $v.Reason) {
                    $ops.Add([ordered]@{ op = 'replace'; path = '/secretManagement/manualManagementReason'; value = [string]$v.Reason })
                }
            }
            '^prop:(.+)$' {
                $pn = $k.Substring(5)
                # Use the property's existing spelling if it is already set.
                $known = @($existing.Keys | Where-Object { $_ -eq $pn }) | Select-Object -First 1
                if ($known) { $pn = [string]$known }
                if ($null -eq $v) {
                    if (-not $known) { throw ("Property '{0}' is not set on this account, so it cannot be removed." -f $pn) }
                    $propRemove.Add($pn)
                } else {
                    if (-not $known) { $pn = Resolve-PlatformPropertyName -PlatformId $targetPlatform -Name $pn }
                    $propSet[$pn] = [string]$v
                }
            }
        }
    }
    # Platform properties go in one operation on /platformaccountproperties with an object value.
    foreach ($o in @(New-PCloudAccountPropertyOperation -Set $propSet -Remove $propRemove.ToArray())) { $ops.Add($o) }
    return $ops
}

function Get-SpecChanges {
    # Pending changes from a CSV row or parameters (UpdateAccount without the menu).
    param([hashtable]$Spec, $Account)
    $changes = [ordered]@{}
    if ($Spec.NewName) { Add-AccountChange $changes 'Name' $Spec.NewName $Account }
    if ($Spec.NewAddress) { Add-AccountChange $changes 'Address' $Spec.NewAddress $Account }
    if ($Spec.NewUserName) { Add-AccountChange $changes 'UserName' $Spec.NewUserName $Account }
    if ($Spec.NewPlatformId) { Add-AccountChange $changes 'PlatformId' $Spec.NewPlatformId $Account }
    if ($null -ne $Spec.AutomaticManagement) {
        Add-AccountChange $changes 'AutoMgmt' @{ Enabled = [bool]$Spec.AutomaticManagement; Reason = $Spec.ManualManagementReason } $Account
    }
    foreach ($k in $Spec.Properties.Keys) {
        $v = $Spec.Properties[$k]
        if ([string]$v -eq $removeWord) { $v = $null }
        Add-AccountChange $changes ('prop:{0}' -f $k) $v $Account
    }
    return $changes
}

# ------------------------------------------------------------------ linked accounts

function Get-LinkTypes {
    # Linked account types per platform, read once per run.
    param([string]$Platform)
    if ($null -eq $script:linkTypeCache) { $script:linkTypeCache = @{} }
    if (-not $script:linkTypeCache.ContainsKey($Platform)) { $script:linkTypeCache[$Platform] = @(Get-PCloudPlatformLinkedAccountType -PlatformId $Platform) }
    return $script:linkTypeCache[$Platform]
}

function Resolve-LinkIndex {
    # LinkType as a number, or a name/display name from the account's platform. Returns @{ Index; Label }.
    param($Account, [string]$Value)
    if (-not $Value) { throw 'LinkType is required (for example LogonAccount, ReconcileAccount, or the index number).' }
    $types = @(Get-LinkTypes $Account.platformId)
    $n = 0
    if ([int]::TryParse($Value, [ref]$n) -and $n -gt 0) {
        $t = @($types | Where-Object { $_.ExtraPasswordIndex -eq $n }) | Select-Object -First 1
        $lbl = 'index {0}' -f $n
        if ($t) { $lbl = '{0} (index {1})' -f $t.DisplayName, $n }
        return @{ Index = $n; Label = $lbl }
    }
    $t = @($types | Where-Object { $_.Name -eq $Value -or $_.DisplayName -eq $Value -or ($_.Name -replace 'Account$', '') -eq $Value }) | Select-Object -First 1
    if (-not $t) { throw ("Platform {0} has no linked account type '{1}'. It offers: {2}" -f $Account.platformId, $Value, ((@($types | ForEach-Object { $_.Name })) -join ', ')) }
    if (-not $t.ExtraPasswordIndex) { throw ("The index for '{0}' isn't known. Give LinkType as its index number instead." -f $t.Name) }
    return @{ Index = [int]$t.ExtraPasswordIndex; Label = ('{0} (index {1})' -f $t.DisplayName, $t.ExtraPasswordIndex) }
}

function Read-LinkType {
    # Interactive: pick the link type from the account's platform. Returns the index as a string, or $null (back).
    param($Account)
    $types = @(Get-LinkTypes $Account.platformId)
    if (@($types | Where-Object { $_.Source -eq 'Default' }).Count -gt 0) {
        Write-Host ("Couldn't read the linked account types from platform {0}; showing the standard ones." -f $Account.platformId) -ForegroundColor Yellow
    }
    $pick = Select-FromList -Items $types -Title ('Linked account types on platform {0}' -f $Account.platformId) -Label {
        param($x)
        $i = 'index unknown'
        if ($x.ExtraPasswordIndex) { $i = 'index {0}' -f $x.ExtraPasswordIndex }
        '{0} ({1})' -f $x.DisplayName, $i
    }
    if ($null -eq $pick) { return $null }
    if ($pick.ExtraPasswordIndex) { return [string]$pick.ExtraPasswordIndex }
    while ($true) {
        $v = (Read-Host ('Index number for {0} (leave blank to go back)' -f $pick.DisplayName)).Trim()
        if (-not $v) { return $null }
        $n = 0
        if ([int]::TryParse($v, [ref]$n) -and $n -gt 0) { return [string]$n }
        Write-Host '  Enter a whole number.' -ForegroundColor Red
    }
}

function Invoke-LinkAccount {
    param($Account, [hashtable]$Spec)
    $link = Resolve-LinkIndex -Account $Account -Value $Spec.LinkType
    $lSafe = $Spec.LinkedSafe
    $lName = $Spec.LinkedName
    if ($Spec.LinkedAccountId) {
        if ($Spec.LinkedAccountId -eq $Account.id) { throw 'An account cannot be linked to itself.' }
        $la = Get-PCloudAccount -Id $Spec.LinkedAccountId
        $lSafe = $la.safeName
        $lName = $la.name
    }
    if (-not $lSafe -or -not $lName) { throw 'Give LinkedAccountId, or LinkedSafe and LinkedName.' }
    $folder = $Spec.LinkedFolder
    if (-not $folder) { $folder = 'Root' }
    Add-PCloudLinkedAccount -Id $Account.id -ExtraPasswordIndex $link.Index -LinkedSafe $lSafe -LinkedName $lName -Folder $folder -Confirm:$false
    return ('Linked {0} -> {1} in safe {2}' -f $link.Label, $lName, $lSafe)
}

function Read-NewLink {
    # Interactive LinkAccount / UnlinkAccount details for an account. Sets the script variables; $false = back.
    param($Account, [switch]$Unlink)
    $idx = Read-LinkType -Account $Account
    if (-not $idx) { return $false }
    $script:LinkType = $idx
    if ($Unlink) {
        return (Read-YesNo ('Remove linked account index {0} from account {1}?' -f $idx, $Account.id))
    }
    while ($true) {
        $la = Read-AccountTarget -What 'Linked account' -AllowObjectName
        if ($null -eq $la) { return $false }
        if ($la.id -and $la.id -eq $Account.id) { Write-Host '  An account cannot be linked to itself.' -ForegroundColor Red; continue }
        break
    }
    $script:LinkedAccountId = ''
    if ($la.id) { $script:LinkedAccountId = $la.id }
    $script:LinkedSafe = $la.safeName
    $script:LinkedName = $la.name
    Write-Host ''
    Write-Host ('Link: account {0} ({1}@{2})  <-  index {3}: {4} in safe {5}' -f $Account.id, $Account.userName, $Account.address, $idx, $la.name, $la.safeName)
    return (Read-YesNo 'Create this link?' $true)
}

# ------------------------------------------------------------------ actions (one item each)

function Invoke-AddAccount {
    param([hashtable]$Spec)
    foreach ($req in @('SafeName', 'PlatformId', 'UserName')) { if (-not $Spec[$req]) { throw "$req is required." } }
    $p = @{ SafeName = $Spec.SafeName; PlatformId = $Spec.PlatformId; UserName = $Spec.UserName; Confirm = $false }
    if ($Spec.Address) { $p['Address'] = $Spec.Address }
    if ($Spec.Name) { $p['Name'] = $Spec.Name }
    if ($Spec.SecretType) { $p['SecretType'] = $Spec.SecretType.ToLowerInvariant() }
    if ($Spec.Secret) { $p['Secret'] = $Spec.Secret }
    if ($Spec.AutomaticManagement -eq $false) {
        $p['DisableAutomaticManagement'] = $true
        if ($Spec.ManualManagementReason) { $p['ManualManagementReason'] = $Spec.ManualManagementReason }
    }
    if ($Spec.RemoteMachines.Count -gt 0) { $p['RemoteMachines'] = $Spec.RemoteMachines; $p['AccessRestrictedToRemoteMachines'] = $true }
    if ($Spec.Properties.Count -gt 0) {
        $h = @{}
        foreach ($k in $Spec.Properties.Keys) { $h[(Resolve-PlatformPropertyName -PlatformId $Spec.PlatformId -Name $k)] = [string]$Spec.Properties[$k] }
        $p['PlatformAccountProperties'] = $h
    }
    return (New-PCloudAccount @p)
}

function Invoke-AccountUpdateMenu {
    # Single account: pick what to change. One PATCH applies everything; a failure drops the failing
    # change and returns here with the rest still pending.
    param($Account)
    $current = $Account
    $changes = [ordered]@{}
    $lastError = $null

    function Show-PropertyMenu {
        while ($true) {
            $props = Get-AccountProperties $current
            Write-Host ''
            Write-Host 'Platform properties:'
            if ($props.Count -eq 0) { Write-Host '   (none set)' }
            foreach ($k in $props.Keys) {
                $pend = ''
                $ck = 'prop:{0}' -f $k
                $hit = @($changes.Keys | Where-Object { $_ -eq $ck })
                if ($hit.Count -gt 0) { $pend = ' -> {0}' -f $changes[$hit[0]].Display }
                Write-Host ('   {0} = {1}{2}' -f $k, $props[$k], $pend)
            }
            foreach ($ck in @($changes.Keys | Where-Object { $_ -like 'prop:*' })) {
                $pn = $ck.Substring(5)
                if (@($props.Keys | Where-Object { $_ -eq $pn }).Count -eq 0) { Write-Host ('   {0} (new) -> {1}' -f $pn, $changes[$ck].Display) }
            }
            Write-Host '  1) Add or change a property'
            Write-Host '  2) Remove a property'
            Write-Host '  C) Clear pending property changes'
            Write-Host '  B) Back'
            $c = (Read-Host 'Choice').Trim()
            switch -Regex ($c) {
                '^1$' {
                    $avail = @(Get-PlatformPropertyList -PlatformId $current.platformId)
                    $pn = $null
                    if ($avail.Count -gt 0 -and $null -ne $avail[0]) {
                        $pick = Select-FromList -Items $avail -Title ('Properties of platform {0} - pick one' -f $current.platformId) -Label { param($x) Format-PlatformProperty $x }
                        if ($null -eq $pick) { break }
                        $pn = $pick.Name
                    } else {
                        Write-Host ("  Couldn't read the properties of platform {0}; type the property's name." -f $current.platformId) -ForegroundColor Yellow
                        $pn = (Read-Host 'Property name (e.g. Port, LogonDomain; leave blank to go back)').Trim()
                        if (-not $pn) { break }
                        if ($pn -notmatch '^[A-Za-z0-9_\-]+$') { Write-Host '  Property names use letters, numbers, _ and -.' -ForegroundColor Red; break }
                    }
                    $pv = Read-MultilineValue -Prompt ('Value for {0}' -f $pn)
                    if ($pv -eq '') { Write-Host '  Empty value ignored. Use 2 to remove a property.' -ForegroundColor Yellow; break }
                    Add-AccountChange $changes ('prop:{0}' -f $pn) $pv $current
                }
                '^2$' {
                    if ($props.Count -eq 0) { Write-Host '  No properties to remove.'; break }
                    $pick = Select-FromList -Items @($props.Keys) -Title 'Remove which property' -Label { param($x) [string]$x }
                    if ($null -ne $pick) { Add-AccountChange $changes ('prop:{0}' -f $pick) $null $current }
                }
                '^(?i)c$' { foreach ($ck in @($changes.Keys | Where-Object { $_ -like 'prop:*' })) { $changes.Remove($ck) } }
                '^(?i)b$' { return }
                default { Write-Host 'Choose 1, 2, C or B.' }
            }
        }
    }

    while ($true) {
        $auto = Get-NestedValue $current 'secretManagement.automaticManagementEnabled'
        $autoText = 'On'
        if ($auto -eq $false) {
            $autoText = 'Off'
            $why = Get-NestedValue $current 'secretManagement.manualManagementReason'
            if ($why) { $autoText = 'Off ({0})' -f $why }
        }
        $propCount = (Get-AccountProperties $current).Count
        $propPending = @($changes.Keys | Where-Object { $_ -like 'prop:*' }).Count
        $rows = @(
            @('1', 'Account name', 'Name', $current.name),
            @('2', 'Address', 'Address', $current.address),
            @('3', 'User name', 'UserName', $current.userName),
            @('4', 'Platform', 'PlatformId', $current.platformId),
            @('5', 'Properties', '', ('{0} set' -f $propCount)),
            @('6', 'Auto management', 'AutoMgmt', $autoText)
        )
        Write-Host ''
        if ($lastError) { Write-Host ('Last attempt failed: {0}' -f $lastError) -ForegroundColor Red }
        Write-Host ("Update account {0} ({1}@{2}, safe {3}) - choose a setting to change:" -f $current.id, $current.userName, $current.address, $current.safeName)
        foreach ($r in $rows) {
            $pend = ''
            if ($r[2] -and $changes.Contains($r[2])) { $pend = ' -> {0}' -f $changes[$r[2]].Display }
            if ($r[0] -eq '5' -and $propPending -gt 0) { $pend = ' -> {0} change(s) pending' -f $propPending }
            Write-Host ('  {0}) {1,-16} current: {2}{3}' -f $r[0], $r[1], $r[3], $pend)
        }
        Write-Host '  A) Apply changes'
        Write-Host '  Q) Quit without changes'
        $choice = (Read-Host 'Choice').Trim()
        switch -Regex ($choice) {
            '^1$' {
                $v = Read-Host 'New account name (leave blank to keep)'
                if ($v -and $v -ne $current.name) { Add-AccountChange $changes 'Name' $v $current }
            }
            '^2$' {
                $v = Read-Host 'New address (leave blank to keep)'
                if ($v -and $v -ne $current.address) { Add-AccountChange $changes 'Address' $v $current }
            }
            '^3$' {
                $v = Read-Host 'New user name (leave blank to keep)'
                if ($v -and $v -ne $current.userName) { Add-AccountChange $changes 'UserName' $v $current }
            }
            '^4$' {
                $v = Read-PlatformId -Prompt 'New platform'
                if ($v -and $v -ne $current.platformId) {
                    Write-Host 'Note: the new platform may require properties this account does not have yet (add them with option 5).' -ForegroundColor Yellow
                    Add-AccountChange $changes 'PlatformId' $v $current
                }
            }
            '^5$' { Show-PropertyMenu }
            '^6$' {
                if ($auto -eq $false) {
                    if (Read-YesNo 'Turn automatic (CPM) management on?' $true) { Add-AccountChange $changes 'AutoMgmt' @{ Enabled = $true; Reason = '' } $current }
                } else {
                    Write-Warning 'With automatic management off, the CPM will not change, verify or reconcile this password.'
                    if (Read-YesNo 'Turn automatic management off?') {
                        $why = Read-Host 'Reason (optional)'
                        Add-AccountChange $changes 'AutoMgmt' @{ Enabled = $false; Reason = $why } $current
                    }
                }
            }
            '^(?i)a$' {
                if ($changes.Count -eq 0) { Write-Host 'No changes selected yet.'; break }
                Write-Host ''
                Write-Host 'Changes to apply:'
                Write-PendingChanges $changes
                if (-not (Read-YesNo 'Apply these changes?')) { break }
                if (-not $ScriptCmdlet.ShouldProcess(('account {0}' -f $current.id), 'UpdateAccount')) {
                    Write-Host 'WhatIf: no changes sent.'
                    return
                }
                try {
                    $ops = @(ConvertTo-AccountOperations -Account $current -Changes $changes)
                    Set-PCloudAccount -Id $current.id -Operation $ops -Confirm:$false | Out-Null
                    Write-Host ('Account {0} updated.' -f $current.id) -ForegroundColor Green
                    if ($OutputPath) {
                        Save-Results -Rows @(New-ResultRow -Row 1 -Action 'UpdateAccount' -Target ('{0}@{1}' -f $current.userName, $current.address) -Id $current.id -Status 'Success' -Message ((@($changes.Keys | ForEach-Object { '{0}={1}' -f $changes[$_].Label, $changes[$_].Display })) -join '; ')) -Path $OutputPath
                    }
                    return
                } catch {
                    $err = $_.Exception.Message
                    $lastError = $err
                    Write-Warning ('Update failed: {0}' -f $err)
                    $failed = Select-FailedChange -Changes $changes -Message $err
                    if ($failed) {
                        Write-Host ("Removed '{0}' from the pending changes. The other changes are still pending." -f $changes[$failed].Label) -ForegroundColor Yellow
                        $changes.Remove($failed)
                    }
                    try { $current = Get-PCloudAccount -Id $current.id } catch { }
                }
            }
            '^(?i)q$' { Write-Host 'No changes made.'; return }
            default { Write-Host 'Choose 1-6, A or Q.' }
        }
    }
}

# ------------------------------------------------------------------ run one action

function Invoke-AccountAction {
    $updateParams = @('NewName', 'NewAddress', 'NewUserName', 'NewPlatformId', 'AutomaticManagement', 'PlatformAccountProperties')
    $hasUpdateValues = @($updateParams | Where-Object { $PSBoundParameters_Main.ContainsKey($_) }).Count -gt 0

    if ($Action -eq 'AccountDependents') {
        $dp = @{}
        if ($AccountId) { $dp['AccountId'] = $AccountId }
        & (Join-Path $PSScriptRoot 'Manage-AccountDependents.ps1') @dp
        return
    }

    if ($Action -eq 'RetrievePassword') {
        if ($CsvPath) { throw 'RetrievePassword works on one account at a time; bulk password retrieval is not offered.' }
        $acct = Find-Account -Id $AccountId -Safe $SafeName -User $UserName -Addr $Address
        $why = $Reason
        while (-not $why) {
            $why = (Read-Host 'Reason for retrieving this password (required, recorded in the audit log; B to go back)').Trim()
            if ($why -match '^(?i)b$') { Write-Host 'Nothing retrieved.'; return }
        }
        $pw = @{ AccountId = $acct.id; Reason = $why }
        if ($TicketingSystemName) { $pw['TicketingSystemName'] = $TicketingSystemName }
        if ($TicketId) { $pw['TicketId'] = $TicketId }
        & (Join-Path $PSScriptRoot 'Get-AccountPassword.ps1') @pw
        return
    }

    if ($Action -eq 'UpdateAccount' -and -not $CsvPath -and -not $hasUpdateValues) {
        Invoke-AccountUpdateMenu -Account (Find-Account -Id $AccountId -Safe $SafeName -User $UserName -Addr $Address)
        return
    }

    # Build the work items.
    $specs = New-Object System.Collections.Generic.List[object]
    $results = New-Object System.Collections.Generic.List[object]
    $secretCol = $null
    if ($CsvPath) {
        $rows = @(Import-WorkCsv -Path $CsvPath)
        if ($Action -eq 'AddAccount') {
            $secretCol = Get-CsvSecretColumn -Rows $rows
            if ($PromptForPasswords) { Write-Warning 'CSV onboarding does not ask for passwords. -PromptForPasswords is ignored.' }
            if ($secretCol) {
                Write-Host ("Using the secrets in the '{0}' column. Rows without one are created without a secret." -f $secretCol) -ForegroundColor Yellow
            } else {
                Write-Host 'This CSV has no Secret column, so the accounts are created without secrets.' -ForegroundColor Cyan
            }
        }
        $r = 0
        foreach ($row in $rows) {
            $r++
            $sec = $null
            if ($secretCol) { $sec = ConvertFrom-CsvSecret -Row $row -Column $secretCol }
            try {
                $spec = ConvertTo-AccountSpec -Row $row -Index $r
                if ($secretCol) { $spec.Secret = $sec; $sec = $null }
                $specs.Add($spec)
            } catch {
                if ($sec) { $sec.Dispose() }
                $results.Add((New-ResultRow -Row $r -Action $Action -Target ('{0} {1}' -f (Get-RowValue $row 'SafeName'), (Get-RowValue $row 'UserName')) -Status 'Failed' -Message $_.Exception.Message))
            }
        }
    } else {
        $specs.Add((ConvertTo-AccountSpec -Row $null -Index 1))
    }

    $isWrite = $readActions -notcontains $Action
    if ($Action -eq 'DeleteAccount' -and $specs.Count -gt 0) {
        $what = '{0} account(s)' -f $specs.Count
        if ($specs.Count -eq 1 -and -not $CsvPath) {
            $one = Find-Account -Id $specs[0].AccountId -Safe $specs[0].SafeName -User $specs[0].UserName -Addr $specs[0].Address
            $specs[0].AccountId = $one.id
            $what = 'account {0} ({1}@{2} in safe {3})' -f $one.id, $one.userName, $one.address, $one.safeName
        }
        if (-not (Confirm-Destructive -What $what -Force:$Force)) { Write-Host 'Delete cancelled.'; return }
    }

    $i = 0
    try {
    foreach ($spec in $specs) {
        $i++
        $label = (@($spec.AccountId, $spec.SafeName, $spec.UserName, $spec.Address) | Where-Object { $_ }) -join ' '
        Write-Progress -Activity $Action -Status ('{0} of {1}: {2}' -f $i, $specs.Count, $label) -PercentComplete (($i / [Math]::Max($specs.Count, 1)) * 100)
        $id = $null
        try {
            switch ($Action) {
                'GetAccounts' {
                    if ($spec.Search) {
                        $list = @(Find-AccountsByKeyword -Text $spec.Search -Safe $spec.SafeName)
                    } else {
                        $p = @{}
                        if ($spec.SafeName) { $p['SafeName'] = $spec.SafeName }
                        if ($p.Count -eq 0) { Write-Host 'Reading every account you can see. This can take a while on large vaults...' }
                        $list = @(Get-PCloudAccount @p)
                    }
                    foreach ($a in $list) { $results.Add((Format-AccountRow $a)) }
                }
                'GetAccountDetails' {
                    $results.Add((Format-AccountRow (Find-Account -Id $spec.AccountId -Safe $spec.SafeName -User $spec.UserName -Addr $spec.Address) -Detailed))
                }
                'AddAccount' {
                    $label = '{0}@{1} in safe {2}' -f $spec.UserName, $spec.Address, $spec.SafeName
                    $note = $null
                    if (-not $spec.Secret) {
                        $note = 'Created without a secret (none in the CSV)'
                        if (-not $CsvPath) { $note = 'Created without a secret' }
                        Write-Host ('  {0}: no secret given; creating it without one.' -f $label) -ForegroundColor Yellow
                    }
                    try {
                        if ($ScriptCmdlet.ShouldProcess($label, 'AddAccount')) {
                            $new = Invoke-AddAccount -Spec $spec
                            $results.Add((New-ResultRow -Row $spec.Index -Action $Action -Target $label -Id $new.id -Status 'Success' -Message $note))
                        } else {
                            $results.Add((New-ResultRow -Row $spec.Index -Action $Action -Target $label -Status 'WhatIf' -Message $note))
                        }
                    } finally {
                        # A secret read from the CSV is disposed as soon as its row is done.
                        if ($CsvPath -and $spec.Secret) { $spec.Secret.Dispose(); $spec.Secret = $null }
                    }
                }
                default {
                    $acct = Find-Account -Id $spec.AccountId -Safe $spec.SafeName -User $spec.UserName -Addr $spec.Address
                    $id = $acct.id
                    $label = '{0}@{1} in safe {2}' -f $acct.userName, $acct.address, $acct.safeName
                    if (-not $ScriptCmdlet.ShouldProcess(('account {0} ({1})' -f $id, $label), $Action)) {
                        $results.Add((New-ResultRow -Row $spec.Index -Action $Action -Target $label -Id $id -Status 'WhatIf'))
                        break
                    }
                    $msg = $null
                    switch ($Action) {
                        'UpdateAccount' {
                            $ch = Get-SpecChanges -Spec $spec -Account $acct
                            if ($ch.Count -eq 0) {
                                throw ('Nothing to update in this row. Fill in a New* value, AutomaticManagement, or a platform property column (for example Notes or prop_Notes). Columns read: {0}' -f ((@($rows[0].PSObject.Properties | ForEach-Object { $_.Name })) -join ', '))
                            }
                            $ops = @(ConvertTo-AccountOperations -Account $acct -Changes $ch)
                            Set-PCloudAccount -Id $id -Operation $ops -Confirm:$false | Out-Null
                            $msg = (@($ch.Keys | ForEach-Object { '{0}={1}' -f $ch[$_].Label, $ch[$_].Display })) -join '; '
                        }
                        'LinkAccount' { $msg = Invoke-LinkAccount -Account $acct -Spec $spec }
                        'UnlinkAccount' {
                            $link = Resolve-LinkIndex -Account $acct -Value $spec.LinkType
                            Remove-PCloudLinkedAccount -Id $id -ExtraPasswordIndex $link.Index -Confirm:$false
                            $msg = 'Unlinked {0}' -f $link.Label
                        }
                        'DeleteAccount' { Remove-PCloudAccount -Id $id -Confirm:$false }
                        'ChangeCredential' { Invoke-PCloudAccountChange -Id $id -Confirm:$false | Out-Null; $msg = 'Marked for change' }
                        'VerifyCredential' { Invoke-PCloudAccountVerify -Id $id -Confirm:$false | Out-Null; $msg = 'Marked for verify' }
                        'ReconcileCredential' { Invoke-PCloudAccountReconcile -Id $id -Confirm:$false | Out-Null; $msg = 'Marked for reconcile' }
                    }
                    $results.Add((New-ResultRow -Row $spec.Index -Action $Action -Target $label -Id $id -Status 'Success' -Message $msg))
                }
            }
        } catch {
            $msg = $_.Exception.Message
            Write-Warning ('Row {0} ({1}): {2}' -f $spec.Index, $label, $msg)
            if ($isWrite) { $results.Add((New-ResultRow -Row $spec.Index -Action $Action -Target $label -Id $id -Status 'Failed' -Message $msg)) }
        }
    }
    } finally {
        # Rows not reached (for example after Ctrl+C) still hold a SecureString from the CSV.
        if ($CsvPath) { foreach ($s in $specs) { if ($s.Secret) { $s.Secret.Dispose(); $s.Secret = $null } } }
    }
    Write-Progress -Activity $Action -Completed
    if ($secretCol) {
        Write-Warning ('{0} contains plain-text passwords. Delete it securely now (for example with a secure-delete tool), and empty the Recycle Bin.' -f $CsvPath)
    }

    if ($isWrite) {
        Write-WriteResults -Results $results.ToArray() -Action $Action
    } elseif ($Action -eq 'GetAccountDetails' -and $results.Count -le 3) {
        $results | Format-List | Out-String | Write-Host
    } else {
        $results | Format-Table AccountId, SafeName, UserName, Address, PlatformId, AutomaticManagement, CPMStatus -AutoSize | Out-String | Write-Host
        Write-Host ('{0} account(s).' -f $results.Count)
    }
    Save-Results -Rows $results.ToArray() -Path $OutputPath
}

# ------------------------------------------------------------------ interactive AddAccount

function Read-NewAccount {
    # Sets the single-mode variables for AddAccount. Returns $false if the user goes back.
    $safe = Read-ExistingSafeName
    if (-not $safe) { return $false }
    $plat = Read-PlatformId
    if (-not $plat) { return $false }
    $addr = Read-Host 'Address (host name, IP or domain; leave blank if the platform does not use one)'
    $user = ''
    while (-not $user) {
        $user = Read-Host 'User name (leave blank to go back)'
        if (-not $user) { return $false }
    }
    $nm = Read-Host 'Account name (leave blank to let Privilege Cloud name it)'
    $props = @{}
    Write-Host 'Platform properties (for example LogonDomain or Port). Leave the name blank to finish.'
    while ($true) {
        $pn = (Read-Host '  Property name').Trim()
        if (-not $pn) { break }
        if ($pn -notmatch '^[A-Za-z0-9_\-]+$') { Write-Host '  Property names use letters, numbers, _ and -.' -ForegroundColor Red; continue }
        $pv = Read-MultilineValue -Prompt ('  Value for {0}' -f $pn)
        if ($pv -ne '') { $props[$pn] = $pv }
    }
    $auto = Read-YesNo 'Let the CPM manage this password automatically?' $true
    $why = ''
    if (-not $auto) { $why = Read-Host 'Reason for manual management (optional)' }
    $sec = Read-Secret -Label ('{0}@{1}' -f $user, $addr)

    Write-Host ''
    Write-Host 'Account to add:'
    Write-Host ('  Safe: {0}  Platform: {1}  Address: {2}  User: {3}  Name: {4}' -f $safe, $plat, $addr, $user, $(if ($nm) { $nm } else { '(automatic)' }))
    Write-Host ('  Properties: {0}' -f $(if ($props.Count) { (@($props.Keys | ForEach-Object { '{0}={1}' -f $_, $props[$_] })) -join ', ' } else { '(none)' }))
    Write-Host ('  Automatic management: {0}   Password: {1}' -f $(if ($auto) { 'On' } else { 'Off' }), $(if ($sec) { 'entered (hidden)' } else { 'empty' }))
    if (-not (Read-YesNo 'Add this account?' $true)) {
        if ($sec) { $sec.Dispose() }
        return $false
    }
    $script:SafeName = $safe; $script:PlatformId = $plat; $script:Address = $addr; $script:UserName = $user; $script:Name = $nm
    $script:PlatformAccountProperties = $props
    $script:DisableAutomaticManagement = [switch](-not $auto)
    $script:ManualManagementReason = $why
    $script:Secret = $sec
    return $true
}

# ---------- Non-interactive: -Action given. Runs once; errors end the script as usual.
if ($Action) {
    $createdSecret = $false
    if ($ExportCsv -and -not $OutputPath) { $OutputPath = New-OutputPath -Action $Action }
    if (-not $CsvPath -and $Action -eq 'AddAccount') {
        if (-not $SafeName) { $SafeName = Read-Host 'Safe name' }
        if (-not $PlatformId) { $PlatformId = Read-Host 'Platform ID' }
        if (-not $UserName) { $UserName = Read-Host 'User name' }
        if (-not $Secret -and $PromptForPasswords) { $Secret = Read-Secret -Label ('{0}@{1}' -f $UserName, $Address); $createdSecret = $true }
    } elseif (-not $CsvPath -and $Action -notin @('GetAccounts', 'AccountDependents') -and -not $AccountId -and -not ($SafeName -and $UserName)) {
        $AccountId = Read-Host 'Account ID'
    }
    if (-not $CsvPath -and ($Action -eq 'LinkAccount' -or $Action -eq 'UnlinkAccount') -and -not $LinkType) { $LinkType = Read-Host 'Link type (e.g. LogonAccount, ReconcileAccount, or the index number)' }
    if (-not $CsvPath -and $Action -eq 'LinkAccount' -and -not $LinkedAccountId -and -not ($LinkedSafe -and $LinkedName)) { $LinkedAccountId = Read-Host 'Linked account ID' }
    Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod
    # Only dispose a password this script asked for; a -Secret passed in belongs to the caller.
    try { Invoke-AccountAction } finally { if ($createdSecret -and $Secret) { $Secret.Dispose() } }
    return
}

# ---------- Menu mode: loops until Q. Any failure returns to the previous prompt or the main menu.
Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod

$original = @{
    CsvPath = $CsvPath; OutputPath = $OutputPath; ExportCsv = [bool]$ExportCsv
    AccountId = $AccountId; SafeName = $SafeName; UserName = $UserName; Address = $Address; Search = $Search
    Name = $Name; PlatformId = $PlatformId; PlatformAccountProperties = $PlatformAccountProperties
    DisableAutomaticManagement = [bool]$DisableAutomaticManagement; ManualManagementReason = $ManualManagementReason
    LinkType = $LinkType; LinkedAccountId = $LinkedAccountId; LinkedSafe = $LinkedSafe; LinkedName = $LinkedName; LinkedFolder = $LinkedFolder
}

while ($true) {
    foreach ($k in $original.Keys) { Set-Variable -Name $k -Value $original[$k] -Scope Script }
    $script:Secret = $null
    $Action = $null

    $Action = Read-MainMenu -Title 'Account management - choose an action:' -Actions $actions -Descriptions $actionHelp
    if (-not $Action) { break }

    try {
        if ($Action -eq 'AccountDependents') { Invoke-AccountAction; continue }
        # CSV or single item. RetrievePassword is single only; GetAccounts asks its own questions.
        if ($Action -ne 'RetrievePassword' -and $Action -ne 'GetAccounts' -and -not $CsvPath) {
            $f = Read-ExistingFile -Prompt 'CSV file path (leave blank for a single account, B to go back)'
            if ($null -eq $f) { continue }
            if ($f) { $CsvPath = $f }
        }

        if (-not $CsvPath) {
            switch ($Action) {
                'GetAccounts' {
                    $s = (Read-Host 'Safe name or part of it (leave blank for every safe)').Trim()
                    if ($s) {
                        $SafeName = Resolve-SafeChoice -Text $s
                        if (-not $SafeName) { $SafeName = Read-ExistingSafeName }
                        if (-not $SafeName) { $Action = $null }
                    }
                    if ($Action) { $Search = Read-Host 'Keywords - user, address, name, safe or platform, partial words are fine (leave blank for none)' }
                }
                'AddAccount' { if (-not (Read-NewAccount)) { $Action = $null } }
                default {
                    $acct = Read-AccountTarget
                    if ($null -eq $acct) { $Action = $null } else { $AccountId = $acct.id }
                    if ($Action -eq 'LinkAccount' -or $Action -eq 'UnlinkAccount') {
                        if (-not (Read-NewLink -Account $acct -Unlink:($Action -eq 'UnlinkAccount'))) { $Action = $null }
                    }
                }
            }
            if (-not $Action) { continue }
        }

        if (($readActions -contains $Action) -and -not $OutputPath -and -not $ExportCsv) { $OutputPath = Read-OutputChoice -Action $Action }
        if ($ExportCsv -and -not $OutputPath) { $OutputPath = New-OutputPath -Action $Action }

        Invoke-AccountAction
    } catch {
        Write-Host ''
        Write-Host ('{0} failed: {1}' -f $Action, $_.Exception.Message) -ForegroundColor Red
        Write-Host 'Returning to the main menu.' -ForegroundColor Yellow
    } finally {
        if ($script:Secret) { $script:Secret.Dispose(); $script:Secret = $null }
        $PromptForPasswords = [switch]$false
    }
}
