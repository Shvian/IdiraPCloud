#Requires -Version 5.1
<#
.SYNOPSIS
    Account dependents for Idira Privilege Cloud: the Windows services, scheduled tasks and similar resources
    that use a target account's password. List, view, add, update and delete dependents, and link or unlink
    accounts (such as a logon account) to them. Opened from Manage-Accounts.ps1 (AccountDependents), or run on its own.
.DESCRIPTION
    Uses the Gen 3 API: /api/accounts/{account_id}/account-dependents.

    Actions:
      GetDependents           Dependents of an account. Single: -AccountId [-Keyword].  CSV columns: AccountId, Keyword.
      GetDependentDetails     Every field of one dependent as Setting/Value rows. Single: -AccountId -DependentId.
                              CSV columns: AccountId, DependentId.
      AddDependent            Add a dependent. CSV columns: AccountId, PlatformId (a dependent platform such as
                              WinService), Name, AutomaticManagement, ManualManagementReason,
                              DisableParentAutomaticManagement, prop_<Name> (each dependent platform property).
      UpdateDependent         Change a dependent; blank cells keep the current value, "(remove)" in a prop_ column
                              removes the property. CSV columns: as AddDependent plus DependentId.
      DeleteDependent         Delete dependents (type DELETE to confirm, or -Force). CSV columns: AccountId, DependentId.
      LinkDependentAccount    Link an account to a dependent at an extra password index (1 is usually the logon
                              account). CSV columns: AccountId, DependentId, LinkIndex, LinkedAccountId.
      UnlinkDependentAccount  Remove the link at an index. CSV columns: AccountId, DependentId, LinkIndex.

    From the menu you choose the account first (by ID or keywords), then work on its dependents until you go back.
    Write actions support -WhatIf. CSV export: -ExportCsv or -OutputPath <file> for the Get actions.
.EXAMPLE
    .\Manage-AccountDependents.ps1
.EXAMPLE
    .\Manage-AccountDependents.ps1 -Action GetDependents -AccountId 12_34 -ExportCsv
.EXAMPLE
    .\Manage-AccountDependents.ps1 -Action AddDependent -AccountId 12_34 -PlatformId WinService -DependentProperties @{ Address = 'srv01'; ServiceName = 'Billing' }
.EXAMPLE
    .\Manage-AccountDependents.ps1 -Action LinkDependentAccount -AccountId 12_34 -DependentId 5 -LinkIndex 1 -LinkedAccountId 12_99
.EXAMPLE
    .\Manage-AccountDependents.ps1 -Action AddDependent -CsvPath .\samples\account-dependents-add.csv -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ArgumentCompleter({ param($c, $p, $w) 'GetDependents', 'GetDependentDetails', 'AddDependent', 'UpdateDependent', 'DeleteDependent', 'LinkDependentAccount', 'UnlinkDependentAccount' | Where-Object { $_ -like "$w*" } })]
    [string]$Action,

    [string]$CsvPath,
    [string]$OutputPath,
    [switch]$ExportCsv,
    [switch]$Force,

    [string]$AccountId,
    [string]$DependentId,
    [string]$Keyword,
    [string]$PlatformId,
    [string]$Name,
    [hashtable]$DependentProperties,
    [ArgumentCompleter({ param($c, $p, $w) 'true', 'false' | Where-Object { $_ -like "$w*" } })]
    [string]$AutomaticManagement,
    [string]$ManualManagementReason,
    [ArgumentCompleter({ param($c, $p, $w) 'true', 'false' | Where-Object { $_ -like "$w*" } })]
    [string]$DisableParentAutomaticManagement,
    [string]$LinkIndex,
    [string]$LinkedAccountId,

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

$actions = @('GetDependents', 'GetDependentDetails', 'AddDependent', 'UpdateDependent', 'DeleteDependent', 'LinkDependentAccount', 'UnlinkDependentAccount')
$actionHelp = @{
    GetDependents          = 'list the dependents of the account'
    GetDependentDetails    = 'every field of one dependent'
    AddDependent           = 'add a dependent (Windows service, scheduled task, ...)'
    UpdateDependent        = 'change a dependent''s name, properties or management'
    DeleteDependent        = 'delete a dependent'
    LinkDependentAccount   = 'link an account (for example its logon account) to a dependent'
    UnlinkDependentAccount = 'remove a linked account from a dependent'
}
$readActions = @('GetDependents', 'GetDependentDetails')
if ($Action) {
    $m = @($actions | Where-Object { $_ -eq $Action })
    if ($m.Count -eq 0) { throw ("-Action must be one of: {0}" -f ($actions -join ', ')) }
    $Action = $m[0]
}
$ScriptCmdlet = $PSCmdlet
$script:depPlatformCache = $null
$specColumns = @('AccountId', 'DependentId', 'Keyword', 'PlatformId', 'Name', 'AutomaticManagement', 'ManualManagementReason', 'DisableParentAutomaticManagement', 'LinkIndex', 'LinkedAccountId')

# ------------------------------------------------------------------ helpers

function New-DepSpec {
    # A spec row: every spec column plus prop_<Name> columns for the properties.
    param([hashtable]$Values, [System.Collections.IDictionary]$Props)
    $o = [ordered]@{}
    foreach ($c in $specColumns) { $o[$c] = ''; if ($Values -and $Values.ContainsKey($c) -and $null -ne $Values[$c]) { $o[$c] = [string]$Values[$c] } }
    if ($Props) { foreach ($k in $Props.Keys) { $o[('prop_{0}' -f $k)] = [string]$Props[$k] } }
    return [pscustomobject]$o
}

function Get-SpecProps {
    # prop_<Name> columns -> ordered hashtable. "(remove)" -> $null (removes it on update).
    param($Row)
    $props = [ordered]@{}
    foreach ($col in $Row.PSObject.Properties) {
        if ($col.Name -notlike 'prop_*') { continue }
        $v = ([string]$col.Value).Trim()
        if ($v -eq '') { continue }
        if ($v -match '^(?i)\(remove\)$') { $props[$col.Name.Substring(5)] = $null } else { $props[$col.Name.Substring(5)] = $v }
    }
    return $props
}

function Format-LinkedList {
    param($D)
    $l = @(Get-NestedValue $D 'linkedAccounts' | Where-Object { $null -ne $_ })
    if ($l.Count -eq 0) { return '' }
    return ((@($l | ForEach-Object { '{0}={1} (index {2})' -f (Get-NestedValue $_ 'type_display_name'), (Get-NestedValue $_ 'name'), (Get-NestedValue $_ 'index') })) -join '; ')
}

function Format-DepRow {
    param([string]$Main, $D)
    $o = [ordered]@{
        AccountId                        = $Main
        DependentId                      = [string](Get-NestedValue $D 'id')
        Name                             = Get-NestedValue $D 'name'
        PlatformId                       = Get-NestedValue $D 'platformId'
        AutomaticManagement              = Get-NestedValue $D 'secretManagement.automaticManagementEnabled'
        ManualManagementReason           = Get-NestedValue $D 'secretManagement.manualManagementReason'
        DisableParentAutomaticManagement = Get-NestedValue $D 'secretManagement.disableParentAutomaticManagement'
        LinkedAccounts                   = Format-LinkedList $D
        SafeName                         = Get-NestedValue $D 'safeName'
        CreatedAt                        = Get-NestedValue $D 'createdAt'
        ModifiedAt                       = Get-NestedValue $D 'modifiedAt'
    }
    $props = Get-NestedValue $D 'platformDependentProperties'
    if ($props) { foreach ($p in $props.PSObject.Properties) { $o[('prop_{0}' -f $p.Name)] = $p.Value } }
    return [pscustomobject]$o
}

function Format-DepLabel {
    param($D)
    $n = [string](Get-NestedValue $D 'name')
    $props = Get-NestedValue $D 'platformDependentProperties'
    $hint = ''
    if ($props) { $hint = (@($props.PSObject.Properties | Select-Object -First 3 | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value })) -join ', ' }
    return ('{0,-6} {1,-18} {2}  {3}' -f (Get-NestedValue $D 'id'), (Get-NestedValue $D 'platformId'), $n, $hint)
}

function Get-DependentPlatforms {
    if ($null -ne $script:depPlatformCache) { return $script:depPlatformCache }
    $list = @()
    try { $list = @(Get-PCloudDependentPlatform | Where-Object { $null -ne $_ }) } catch { Write-Verbose ('Could not list dependent platforms: {0}' -f $_.Exception.Message) }
    $script:depPlatformCache = @($list | Sort-Object PlatformID)
    return $script:depPlatformCache
}

function Get-PlatformPropertyNames {
    # Required and optional property names of a platform, from its details ({ properties: { required, optional } }).
    param([string]$Platform)
    $out = [pscustomobject]@{ Required = @(); Optional = @() }
    try {
        $d = Get-PCloudPlatform -PlatformId $Platform
        $props = Get-NestedValue $d 'properties'
        foreach ($kind in @('required', 'optional')) {
            $names = @(@(Get-NestedValue $props $kind) | Where-Object { $null -ne $_ } | ForEach-Object { if ($_ -is [string]) { $_ } else { [string]$_.name } } | Where-Object { $_ })
            if ($kind -eq 'required') { $out.Required = $names } else { $out.Optional = $names }
        }
    } catch { Write-Verbose ('Could not read platform {0}: {1}' -f $Platform, $_.Exception.Message) }
    return $out
}

function Read-DependentPlatform {
    $list = @(Get-DependentPlatforms)
    if ($list.Count -eq 0) {
        $v = (Read-Host 'Dependent platform ID, for example WinService (leave blank to go back)').Trim()
        if (-not $v) { return $null }
        return $v
    }
    $pick = Select-FromList -Items $list -Title 'Dependent platforms' -Label { param($x) '{0}  -  {1}' -f $x.PlatformID, $x.Name }
    if ($null -eq $pick) { return $null }
    return [string]$pick.PlatformID
}

function Read-PropertyValues {
    # Prompts for each property of the platform. With -Current, blank keeps the current value and "-" removes it.
    param([string]$Platform, $Current)
    $names = Get-PlatformPropertyNames $Platform
    $props = [ordered]@{}
    $cur = @{}
    if ($Current) { foreach ($p in $Current.PSObject.Properties) { $cur[$p.Name] = [string]$p.Value } }
    $all = @(@($names.Required) + @($names.Optional) + @($cur.Keys) | Where-Object { $_ } | Select-Object -Unique)
    if ($all.Count -eq 0) { Write-Host '  The platform''s properties could not be read. Type them as Name=Value.' -ForegroundColor Yellow }
    foreach ($n in $all) {
        $req = @($names.Required) -contains $n
        $tag = ''
        if ($req) { $tag = ' (required)' }
        if ($null -ne $Current) {
            $hint = 'blank keeps'
            if ($cur.ContainsKey($n)) { $hint = 'blank keeps "{0}", - removes it' -f $cur[$n] }
            $v = (Read-Host ('  {0}{1} [{2}]' -f $n, $tag, $hint)).Trim()
            if ($v -eq '-') { $props[$n] = $null } elseif ($v) { $props[$n] = $v }
        } else {
            while ($true) {
                $v = (Read-Host ('  {0}{1}' -f $n, $tag)).Trim()
                if ($v -or -not $req) { break }
                Write-Host ('  {0} is required by the platform.' -f $n) -ForegroundColor Red
            }
            if ($v) { $props[$n] = $v }
        }
    }
    while ($true) {
        $extra = (Read-Host '  Another property as Name=Value (leave blank when done)').Trim()
        if (-not $extra) { break }
        if ($extra -notmatch '^([^=]+)=(.*)$') { Write-Host '  Use Name=Value.' -ForegroundColor Red; continue }
        $props[$Matches[1].Trim()] = $Matches[2].Trim()
    }
    return $props
}

function Read-ManagementValues {
    # Returns @{ AutomaticManagement; ManualManagementReason; DisableParentAutomaticManagement } as strings ('' = keep).
    param([switch]$Keep)
    $v = @{ AutomaticManagement = ''; ManualManagementReason = ''; DisableParentAutomaticManagement = '' }
    $suffix = ''
    if ($Keep) { $suffix = ', blank keeps' }
    while ($true) {
        $a = (Read-Host ('  Let the CPM manage this dependent? (Y/N{0})' -f $suffix)).Trim()
        if (-not $a -and $Keep) { break }
        if (-not $a) { $a = 'y' }
        if ($a -match '^(?i)y') { $v.AutomaticManagement = 'true'; break }
        if ($a -match '^(?i)n') { $v.AutomaticManagement = 'false'; $v.ManualManagementReason = Read-Host '  Reason for manual management (optional)'; break }
    }
    if ($Keep) {
        $d = (Read-Host '  Stop the CPM managing the main account when this dependent is not managed? (Y/N, blank keeps)').Trim()
        if ($d -match '^(?i)y') { $v.DisableParentAutomaticManagement = 'true' } elseif ($d -match '^(?i)n') { $v.DisableParentAutomaticManagement = 'false' }
    }
    return $v
}

function Select-Dependent {
    param([string]$Main, [switch]$Multiple, [string]$Title = 'Dependents')
    $deps = @(Get-PCloudAccountDependent -AccountId $Main | Where-Object { $null -ne $_ })
    if ($deps.Count -eq 0) { Write-Host '  This account has no dependents.'; return $null }
    $p = @{ Items = $deps; Title = $Title; Label = { param($x) Format-DepLabel $x } }
    if ($Multiple) { $p['Multiple'] = $true }
    return (Select-FromList @p)
}

function Read-LinkIndex {
    # Index from the dependent platform's linked-account types, or typed.
    param([string]$Platform)
    $types = @()
    try { $types = @(Get-PCloudPlatformLinkedAccountType -PlatformId $Platform | Where-Object { $null -ne $_.ExtraPasswordIndex }) } catch { }
    if ($types.Count -gt 0) {
        Write-Host '  Link types (the index is the extra password index):'
        foreach ($t in $types) { Write-Host ('    {0}  {1}' -f $t.ExtraPasswordIndex, $t.DisplayName) }
    }
    while ($true) {
        $v = (Read-Host '  Index (1 is usually the logon account; leave blank to go back)').Trim()
        if (-not $v) { return $null }
        $n = 0
        if ([int]::TryParse($v, [ref]$n) -and $n -ge 1) { return [string]$n }
        Write-Host '  Enter a whole number from 1.' -ForegroundColor Red
    }
}

# ------------------------------------------------------------------ actions

function Invoke-DependentAction {
    param([object[]]$Rows)
    $specs = @($Rows)
    $results = New-Object System.Collections.Generic.List[object]
    $isWrite = $readActions -notcontains $Action

    if ($Action -in @('DeleteDependent', 'UnlinkDependentAccount')) {
        $what = '{0} dependent(s)' -f $specs.Count
        if ($Action -eq 'UnlinkDependentAccount') { $what = '{0} dependent link(s)' -f $specs.Count }
        if (-not (Confirm-Destructive -What $what -Force:$Force)) { Write-Host 'Cancelled.'; return }
    }

    $i = 0
    foreach ($row in $specs) {
        $i++
        $main = Get-RowValue $row 'AccountId'
        $dep = Get-RowValue $row 'DependentId'
        $label = $main
        if ($dep) { $label = '{0} / dependent {1}' -f $main, $dep }
        Write-Progress -Activity $Action -Status ('{0} of {1}: {2}' -f $i, $specs.Count, $label) -PercentComplete (($i / [Math]::Max($specs.Count, 1)) * 100)
        try {
            if (-not $main) { throw 'AccountId is required.' }
            if ($Action -notin @('GetDependents', 'AddDependent') -and -not $dep) { throw 'DependentId is required.' }
            switch ($Action) {
                'GetDependents' {
                    $p = @{ AccountId = $main }
                    if (Get-RowValue $row 'Keyword') { $p['Keyword'] = Get-RowValue $row 'Keyword' }
                    foreach ($d in @(Get-PCloudAccountDependent @p | Where-Object { $null -ne $_ })) { $results.Add((Format-DepRow $main $d)) }
                }
                'GetDependentDetails' {
                    $d = Get-PCloudAccountDependent -AccountId $main -DependentId $dep -ExtendedDetails
                    foreach ($s in @(ConvertTo-PCloudFlatSetting -InputObject $d)) { $results.Add([pscustomobject]@{ AccountId = $main; DependentId = $dep; Setting = $s.Setting; Value = $s.Value }) }
                }
                { $_ -in @('AddDependent', 'UpdateDependent') } {
                    $p = @{ AccountId = $main; Confirm = $false }
                    $plat = Get-RowValue $row 'PlatformId'
                    if ($Action -eq 'AddDependent' -and -not $plat) { throw 'PlatformId is required.' }
                    if ($plat) { $p['PlatformId'] = $plat }
                    if (Get-RowValue $row 'Name') { $p['Name'] = Get-RowValue $row 'Name' }
                    $props = Get-SpecProps $row
                    if ($Action -eq 'AddDependent') {
                        $clean = [ordered]@{}
                        foreach ($k in $props.Keys) { if ($null -ne $props[$k]) { $clean[$k] = $props[$k] } }
                        $props = $clean
                    }
                    if ($props.Count -gt 0) { $p['Properties'] = $props }
                    $am = ConvertTo-OptionalBool (Get-RowValue $row 'AutomaticManagement') 'AutomaticManagement'
                    if ($null -ne $am) { $p['AutomaticManagement'] = $am }
                    if (Get-RowValue $row 'ManualManagementReason') { $p['ManualManagementReason'] = Get-RowValue $row 'ManualManagementReason' }
                    $dp = ConvertTo-OptionalBool (Get-RowValue $row 'DisableParentAutomaticManagement') 'DisableParentAutomaticManagement'
                    if ($null -ne $dp) { $p['DisableParentAutomaticManagement'] = $dp }
                    if ($Action -eq 'UpdateDependent') {
                        if ($p.Count -le 2) { throw 'Nothing to update. Fill in at least one setting.' }
                        $p['DependentId'] = $dep
                    }
                    if ($ScriptCmdlet.ShouldProcess(('account {0}' -f $label), $Action)) {
                        if ($Action -eq 'AddDependent') {
                            $r = New-PCloudAccountDependent @p
                            $newId = [string](Get-NestedValue $r 'id')
                            $results.Add((New-ResultRow -Row $i -Action $Action -Target $main -Id $newId -Status 'Success' -Message ('Added {0} dependent' -f $plat)))
                        } else {
                            $null = Set-PCloudAccountDependent @p
                            $results.Add((New-ResultRow -Row $i -Action $Action -Target $main -Id $dep -Status 'Success' -Message 'Updated'))
                        }
                    } else { $results.Add((New-ResultRow -Row $i -Action $Action -Target $main -Id $dep -Status 'WhatIf')) }
                }
                'DeleteDependent' {
                    if ($ScriptCmdlet.ShouldProcess($label, $Action)) {
                        Remove-PCloudAccountDependent -AccountId $main -DependentId $dep -Confirm:$false
                        $results.Add((New-ResultRow -Row $i -Action $Action -Target $main -Id $dep -Status 'Success' -Message 'Deleted'))
                    } else { $results.Add((New-ResultRow -Row $i -Action $Action -Target $main -Id $dep -Status 'WhatIf')) }
                }
                { $_ -in @('LinkDependentAccount', 'UnlinkDependentAccount') } {
                    $idx = 0
                    if (-not [int]::TryParse((Get-RowValue $row 'LinkIndex'), [ref]$idx) -or $idx -lt 1) { throw 'LinkIndex must be a whole number from 1.' }
                    if ($Action -eq 'LinkDependentAccount') {
                        $la = Get-RowValue $row 'LinkedAccountId'
                        if (-not $la) { throw 'LinkedAccountId is required.' }
                        if ($ScriptCmdlet.ShouldProcess($label, ('Link {0} at index {1}' -f $la, $idx))) {
                            Add-PCloudAccountDependentLink -AccountId $main -DependentId $dep -Index $idx -LinkedAccountId $la -Confirm:$false
                            $results.Add((New-ResultRow -Row $i -Action $Action -Target $main -Id $dep -Status 'Success' -Message ('Linked {0} at index {1}' -f $la, $idx)))
                        } else { $results.Add((New-ResultRow -Row $i -Action $Action -Target $main -Id $dep -Status 'WhatIf')) }
                    } else {
                        if ($ScriptCmdlet.ShouldProcess($label, ('Unlink index {0}' -f $idx))) {
                            Remove-PCloudAccountDependentLink -AccountId $main -DependentId $dep -Index $idx -Confirm:$false
                            $results.Add((New-ResultRow -Row $i -Action $Action -Target $main -Id $dep -Status 'Success' -Message ('Unlinked index {0}' -f $idx)))
                        } else { $results.Add((New-ResultRow -Row $i -Action $Action -Target $main -Id $dep -Status 'WhatIf')) }
                    }
                }
            }
        } catch {
            $msg = $_.Exception.Message
            Write-Warning ('Row {0} ({1}): {2}' -f $i, $label, $msg)
            if ($isWrite) { $results.Add((New-ResultRow -Row $i -Action $Action -Target $main -Id $dep -Status 'Failed' -Message $msg)) }
        }
    }
    Write-Progress -Activity $Action -Completed

    switch ($Action) {
        'GetDependents' {
            if ($results.Count -eq 0) { Write-Host 'No dependents.' }
            else { $results | Format-Table AccountId, DependentId, PlatformId, Name, AutomaticManagement, LinkedAccounts -AutoSize -Wrap | Out-String | Write-Host }
            Write-Host ('{0} dependent(s).' -f $results.Count)
        }
        'GetDependentDetails' {
            $results | Format-Table DependentId, Setting, Value -AutoSize -Wrap | Out-String | Write-Host
            Write-Host ('{0} setting(s).' -f $results.Count)
        }
        default { Write-WriteResults -Results $results.ToArray() -Action $Action }
    }
    Save-Results -Rows $results.ToArray() -Path $OutputPath
}

function Read-InteractiveRows {
    # Rows for one action on the chosen account, by prompting. @() goes back.
    param($Account)
    $main = [string]$Account.id
    switch ($Action) {
        'GetDependents' {
            $k = (Read-Host 'Keyword to filter by (leave blank for all)').Trim()
            return @(New-DepSpec @{ AccountId = $main; Keyword = $k })
        }
        'GetDependentDetails' {
            $d = Select-Dependent $main -Title 'Show which dependent'
            if ($null -eq $d) { return @() }
            return @(New-DepSpec @{ AccountId = $main; DependentId = $d.id })
        }
        'AddDependent' {
            $plat = Read-DependentPlatform
            if (-not $plat) { return @() }
            $n = (Read-Host 'Name (optional)').Trim()
            Write-Host ('Properties for {0}:' -f $plat)
            $props = Read-PropertyValues -Platform $plat
            $mv = Read-ManagementValues
            return @(New-DepSpec @{ AccountId = $main; PlatformId = $plat; Name = $n; AutomaticManagement = $mv.AutomaticManagement; ManualManagementReason = $mv.ManualManagementReason } $props)
        }
        'UpdateDependent' {
            $d = Select-Dependent $main -Title 'Update which dependent'
            if ($null -eq $d) { return @() }
            Write-Host ('Current: {0}' -f (Format-DepLabel $d))
            $n = (Read-Host ('Name [blank keeps "{0}"]' -f $d.name)).Trim()
            Write-Host 'Properties:'
            $props = Read-PropertyValues -Platform ([string]$d.platformId) -Current (Get-NestedValue $d 'platformDependentProperties')
            $vals = @{ AccountId = $main; DependentId = $d.id; Name = $n }
            $mv = Read-ManagementValues -Keep
            foreach ($k in $mv.Keys) { $vals[$k] = $mv[$k] }
            $out = [ordered]@{}
            foreach ($k in $props.Keys) { if ($null -eq $props[$k]) { $out[$k] = '(remove)' } else { $out[$k] = $props[$k] } }
            $row = New-DepSpec $vals $out
            if (-not ($n -or $out.Count -gt 0 -or $mv.AutomaticManagement -or $mv.DisableParentAutomaticManagement)) { Write-Host 'Nothing changed.'; return @() }
            return @($row)
        }
        'DeleteDependent' {
            $picks = Select-Dependent $main -Multiple -Title 'Delete which dependent(s)'
            if ($null -eq $picks) { return @() }
            return @(@($picks) | ForEach-Object { New-DepSpec @{ AccountId = $main; DependentId = $_.id } })
        }
        'LinkDependentAccount' {
            $d = Select-Dependent $main -Title 'Link an account to which dependent'
            if ($null -eq $d) { return @() }
            $idx = Read-LinkIndex -Platform ([string]$d.platformId)
            if (-not $idx) { return @() }
            $la = Read-AccountTarget -What 'Account to link'
            if ($null -eq $la -or -not $la.id) { return @() }
            return @(New-DepSpec @{ AccountId = $main; DependentId = $d.id; LinkIndex = $idx; LinkedAccountId = $la.id })
        }
        'UnlinkDependentAccount' {
            $d = Select-Dependent $main -Title 'Unlink from which dependent'
            if ($null -eq $d) { return @() }
            $links = @(Get-NestedValue $d 'linkedAccounts' | Where-Object { $null -ne $_ })
            if ($links.Count -eq 0) { Write-Host '  This dependent has no linked accounts.'; return @() }
            $picks = Select-FromList -Items $links -Multiple -Title 'Unlink which account(s)' -Label { param($x) '{0}  {1}  (index {2})' -f (Get-NestedValue $x 'type_display_name'), (Get-NestedValue $x 'name'), (Get-NestedValue $x 'index') }
            if ($null -eq $picks) { return @() }
            return @(@($picks) | ForEach-Object { New-DepSpec @{ AccountId = $main; DependentId = $d.id; LinkIndex = (Get-NestedValue $_ 'index') } })
        }
    }
    return @()
}

# ---------- Non-interactive: -Action given. Runs once; errors end the script as usual.
if ($Action) {
    if ($ExportCsv -and -not $OutputPath) { $OutputPath = New-OutputPath -Action $Action }
    Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod
    if ($CsvPath) { $rows = @(Import-WorkCsv -Path $CsvPath) }
    else {
        if (-not $AccountId) { $AccountId = Read-Host 'Main account ID (for example 12_34)' }
        $rows = @(New-DepSpec @{
                AccountId = $AccountId; DependentId = $DependentId; Keyword = $Keyword; PlatformId = $PlatformId; Name = $Name
                AutomaticManagement = $AutomaticManagement; ManualManagementReason = $ManualManagementReason
                DisableParentAutomaticManagement = $DisableParentAutomaticManagement; LinkIndex = $LinkIndex; LinkedAccountId = $LinkedAccountId
            } $DependentProperties)
    }
    Invoke-DependentAction -Rows $rows
    return
}

# ---------- Menu mode: choose the account, then loop over actions on its dependents. Q goes back.
Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod
$original = @{ CsvPath = $CsvPath; OutputPath = $OutputPath; ExportCsv = [bool]$ExportCsv }
$account = $null
if ($AccountId) { try { $account = Get-PCloudAccount -Id $AccountId } catch { Write-Host ('  {0}' -f $_.Exception.Message) -ForegroundColor Red } }

while ($true) {
    foreach ($k in $original.Keys) { Set-Variable -Name $k -Value $original[$k] -Scope Script }
    if ($null -eq $account) {
        Write-Host ''
        Write-Host 'Account dependents - choose the main account (the one whose password the dependents use).'
        $account = Read-AccountTarget -What 'Main account'
        if ($null -eq $account) { break }
    }
    $menuActions = @($actions) + @('ChooseAnotherAccount')
    $help = @{}
    foreach ($k in $actionHelp.Keys) { $help[$k] = $actionHelp[$k] }
    $help['ChooseAnotherAccount'] = 'work on a different main account'
    $title = 'Dependents of {0}  {1}@{2}  (safe {3}) - choose an action:' -f $account.id, $account.userName, $account.address, $account.safeName
    $Action = $null
    $Action = Read-MainMenu -Title $title -Actions $menuActions -Descriptions $help
    if (-not $Action) { break }
    if ($Action -eq 'ChooseAnotherAccount') { $account = $null; continue }

    try {
        $rows = @()
        if (-not $CsvPath -and $Action -ne 'GetDependents') {
            $f = Read-ExistingFile -Prompt 'CSV file path (leave blank to work on this account, B to go back)'
            if ($null -eq $f) { continue }
            if ($f) { $CsvPath = $f }
        }
        if ($CsvPath) { $rows = @(Import-WorkCsv -Path $CsvPath) }
        else { $rows = @(Read-InteractiveRows -Account $account) }
        if ($rows.Count -eq 0) { continue }

        if (($readActions -contains $Action) -and -not $OutputPath -and -not $ExportCsv) { $OutputPath = Read-OutputChoice -Action $Action }
        if ($ExportCsv -and -not $OutputPath) { $OutputPath = New-OutputPath -Action $Action }

        Invoke-DependentAction -Rows $rows
    } catch {
        Write-Host ''
        Write-Host ('{0} failed: {1}' -f $Action, $_.Exception.Message) -ForegroundColor Red
        Write-Host 'Returning to the dependents menu.' -ForegroundColor Yellow
    }
}
