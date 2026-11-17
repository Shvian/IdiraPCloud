#Requires -Version 5.1
<#
.SYNOPSIS
    PSM assignment for Idira Privilege Cloud target platforms: list PSM servers, see which PSM server and
    connection components each platform uses, and change them. Works on one platform or on every row
    of a CSV, the same way as Manage-Safes.ps1.
.DESCRIPTION
    Actions:
      GetPSMServers      List the PSM servers (ID and name).
      GetPlatformPSM     The PSM server and connection components (enabled and disabled) of a platform.
                         With nothing specified, covers every target platform.
                         Single: -PlatformId.  CSV column: PlatformId.
      UpdatePlatformPSM  Change a platform's PSM server and connection components. For a single platform
                         with no changes given, a menu shows the current settings: pick the PSM server from
                         the list, enable, disable, add or remove connectors, then apply. If the update fails,
                         the failing change is dropped and the menu returns with the rest still pending.
                         CSV columns: PlatformId, PSMServerId (ID or name), EnableConnectors,
                         DisableConnectors, AddConnectors, RemoveConnectors (lists separated by ; or ,).
                         Blank cells leave that part unchanged.

    -PlatformId accepts the platform ID (e.g. WinDomain), its name, or its numeric ID.
    Run without -Action to pick from a menu. Prompts for sign-in if there is no active session.
    The menu loops until you choose Q; any failure returns you to the previous prompt or the main menu.
    UpdatePlatformPSM supports -WhatIf. CSV export: -ExportCsv or -OutputPath <file> for the Get actions.
.EXAMPLE
    .\Manage-PlatformPSM.ps1
.EXAMPLE
    .\Manage-PlatformPSM.ps1 -Action GetPlatformPSM -ExportCsv
    # PSM server and connectors of every platform
.EXAMPLE
    .\Manage-PlatformPSM.ps1 -Action UpdatePlatformPSM -PlatformId WinDomain
    # opens the PSM menu for that platform
.EXAMPLE
    .\Manage-PlatformPSM.ps1 -Action UpdatePlatformPSM -PlatformId UnixSSH -PSMServerId 'PSM-EU' -AddConnectors 'PSM-SSH' -DisableConnectors 'PSM-WinSCP'
.EXAMPLE
    .\Manage-PlatformPSM.ps1 -Action UpdatePlatformPSM -CsvPath .\samples\platform-psm-update.csv -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ArgumentCompleter({ param($c, $p, $w) 'GetPSMServers', 'GetPlatformPSM', 'UpdatePlatformPSM' | Where-Object { $_ -like "$w*" } })]
    [string]$Action,

    [string]$CsvPath,
    [string]$OutputPath,
    [switch]$ExportCsv,

    [string]$PlatformId,
    [string]$PSMServerId,
    [string[]]$EnableConnectors,
    [string[]]$DisableConnectors,
    [string[]]$AddConnectors,
    [string[]]$RemoveConnectors,

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

$actions = @('GetPSMServers', 'GetPlatformPSM', 'UpdatePlatformPSM')
$actionHelp = @{
    GetPSMServers     = 'list PSM servers'
    GetPlatformPSM    = 'PSM server and connectors of one or every platform'
    UpdatePlatformPSM = 'change the PSM server and connectors of a platform'
}
$readActions = @('GetPSMServers', 'GetPlatformPSM')
if ($Action) {
    $m = @($actions | Where-Object { $_ -eq $Action })
    if ($m.Count -eq 0) { throw ("-Action must be one of: {0}" -f ($actions -join ', ')) }
    $Action = $m[0]
}

$PSBoundParameters_Main = $PSBoundParameters
$ScriptCmdlet = $PSCmdlet
$script:psmCache = $null
$script:knownConnectorCache = $null

# ------------------------------------------------------------------ helpers

function Get-PSMServers {
    if ($null -eq $script:psmCache) { $script:psmCache = @(Get-PCloudPSMServer | Sort-Object Name) }
    return $script:psmCache
}

function Find-PSMServer {
    param([string]$Value)
    $all = @(Get-PSMServers)
    foreach ($prop in @('ID', 'Name')) {
        $hit = @($all | Where-Object { [string]$_.$prop -eq $Value })
        if ($hit.Count -gt 0) { return $hit[0] }
    }
    throw ("PSM server '{0}' was not found. Known servers: {1}" -f $Value, ((@($all | ForEach-Object { '{0} ({1})' -f $_.Name, $_.ID })) -join ', '))
}

function Get-PSMServerName {
    param([string]$Id)
    if (-not $Id) { return '' }
    try {
        $hit = @(Get-PSMServers | Where-Object { [string]$_.ID -eq $Id })
        if ($hit.Count -gt 0) { return [string]$hit[0].Name }
    } catch { }
    return ''
}

function Get-ConnectorList {
    # The platform's connectors as an ordered list of @{ PSMConnectorID; Enabled }.
    param($Config)
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($c in @(Get-NestedValue $Config 'PSMConnectors')) {
        if ($null -eq $c -or -not $c.PSMConnectorID) { continue }
        $list.Add([ordered]@{ PSMConnectorID = [string]$c.PSMConnectorID; Enabled = [bool]$c.Enabled })
    }
    return , $list
}

function Find-Connector {
    param($List, [string]$Id)
    foreach ($c in $List) { if ($c.PSMConnectorID -eq $Id) { return $c } }
    return $null
}

function Get-KnownConnectors {
    # Connector IDs in use on any target platform, plus the common built-in ones. Read once, then cached.
    # Returns objects { PSMConnectorID; UsedBy } sorted by ID.
    if ($null -ne $script:knownConnectorCache) { return $script:knownConnectorCache }
    $seen = @{}
    foreach ($d in @('PSM-RDP', 'PSM-RDPConsole', 'PSM-SSH', 'PSM-WinSCP', 'PSM-WinSSH', 'PSM-Telnet')) { $seen[$d.ToLowerInvariant()] = [pscustomobject]@{ PSMConnectorID = $d; UsedBy = 0 } }
    $plats = @(Get-AllTargetPlatforms)
    $i = 0
    foreach ($p in $plats) {
        $i++
        Write-Progress -Activity 'Collecting PSM connectors from the platforms' -Status $p.PlatformID -PercentComplete (($i / [Math]::Max($plats.Count, 1)) * 100)
        try {
            foreach ($c in (Get-ConnectorList (Get-PCloudPlatformPSMConfig -TargetPlatformId $p.ID))) {
                $key = $c.PSMConnectorID.ToLowerInvariant()
                if (-not $seen.ContainsKey($key)) { $seen[$key] = [pscustomobject]@{ PSMConnectorID = $c.PSMConnectorID; UsedBy = 0 } }
                $seen[$key].UsedBy++
            }
        } catch { }
    }
    Write-Progress -Activity 'Collecting PSM connectors from the platforms' -Completed
    $script:knownConnectorCache = @($seen.Values | Sort-Object PSMConnectorID)
    return $script:knownConnectorCache
}

function Format-KnownConnector {
    param($C)
    if ($C.UsedBy -eq 1) { return ('{0}  (used by 1 platform)' -f $C.PSMConnectorID) }
    if ($C.UsedBy -gt 1) { return ('{0}  (used by {1} platforms)' -f $C.PSMConnectorID, $C.UsedBy) }
    return ('{0}  (built-in, not used yet)' -f $C.PSMConnectorID)
}

function Read-ConnectorToAdd {
    # Pick connector(s) to add: L lists every known connector, part of an ID searches them,
    # and an exact ID that is not known yet can still be added. Returns connector IDs, or @() to go back.
    param($Planned)
    $txt = (Read-Host 'Connector ID or part of it, or L to list known connectors (leave blank to go back)').Trim()
    if (-not $txt) { return @() }
    $known = @()
    try { $known = @(Get-KnownConnectors) } catch { Write-Host ('  Could not collect the known connectors: {0}' -f $_.Exception.Message) -ForegroundColor Yellow }
    $avail = @($known | Where-Object { -not (Find-Connector $Planned $_.PSMConnectorID) })
    if ($txt -match '^(?i)l$') {
        if ($avail.Count -eq 0) { Write-Host '  Every known connector is already on this platform. Type an exact ID to add a new one.'; return @() }
        $picks = Select-FromList -Items $avail -Multiple -Title 'Add which connector(s)' -Label { param($x) Format-KnownConnector $x }
        if ($null -eq $picks) { return @() }
        return @(@($picks) | ForEach-Object { [string]$_.PSMConnectorID })
    }
    $exact = @($known | Where-Object { $_.PSMConnectorID -eq $txt })
    if ($exact.Count -gt 0) { return @([string]$exact[0].PSMConnectorID) }
    $pattern = '*{0}*' -f [System.Management.Automation.WildcardPattern]::Escape($txt)
    $hits = @($avail | Where-Object { $_.PSMConnectorID -like $pattern })
    if ($hits.Count -gt 0) {
        $pick = Select-PartialMatch -Items $hits -Text $txt -Noun 'connector' -Label { param($x) Format-KnownConnector $x }
        if ($null -ne $pick) { return @([string]$pick.PSMConnectorID) }
        return @()
    }
    if (Find-Connector $Planned $txt) { return @($txt) }
    if ($txt -notmatch '^[A-Za-z0-9_\-\.]+$') { Write-Host ("  No known connector matches '{0}', and connector IDs use only letters, numbers, _ - and ." -f $txt) -ForegroundColor Red; return @() }
    if (Read-YesNo ("  No known connector matches '{0}'. Add it as a new connector ID? It must match a connector set up on your PSM servers." -f $txt)) { return @($txt) }
    return @()
}

function Get-PlannedPSMConfig {
    # Applies the pending changes to the current config. Returns @{ Server; Connectors }.
    param($Config, [System.Collections.IDictionary]$Changes)
    $server = [string](Get-NestedValue $Config 'PSMServerID')
    if ($Changes.Contains('Server')) { $server = [string]$Changes['Server'].Value }
    $list = Get-ConnectorList $Config
    foreach ($k in @($Changes.Keys | Where-Object { $_ -like 'Add:*' })) {
        $id = $k.Substring(4)
        if (-not (Find-Connector $list $id)) { $list.Add([ordered]@{ PSMConnectorID = $id; Enabled = $true }) }
    }
    foreach ($k in @($Changes.Keys | Where-Object { $_ -like 'State:*' })) {
        $id = $k.Substring(6)
        $c = Find-Connector $list $id
        if (-not $c) { throw ("Connector '{0}' is not on this platform. Add it first." -f $id) }
        $c['Enabled'] = [bool]$Changes[$k].Value
    }
    foreach ($k in @($Changes.Keys | Where-Object { $_ -like 'Remove:*' })) {
        $id = $k.Substring(7)
        $c = Find-Connector $list $id
        if ($c) { $null = $list.Remove($c) }
    }
    return @{ Server = $server; Connectors = $list.ToArray() }
}

function Add-PSMChange {
    param([System.Collections.IDictionary]$Changes, [string]$Kind, [string]$Id, $Value, [string]$Display)
    $hint = '(?i)' + [regex]::Escape($Id)
    switch ($Kind) {
        'Server' { $Changes['Server'] = New-PendingChange -Label 'PSM server' -Value $Value -Display $Display -Hint '(?i)PSMServer|server' }
        'Add' {
            $Changes.Remove(('Remove:{0}' -f $Id))
            $Changes[('Add:{0}' -f $Id)] = New-PendingChange -Label ('Add connector {0}' -f $Id) -Value $true -Display 'enabled' -Hint $hint
        }
        'Remove' {
            $addKey = 'Add:{0}' -f $Id
            if ($Changes.Contains($addKey)) { $Changes.Remove($addKey); return }
            $Changes.Remove(('State:{0}' -f $Id))
            $Changes[('Remove:{0}' -f $Id)] = New-PendingChange -Label ('Remove connector {0}' -f $Id) -Value $true -Display 'remove' -Hint $hint
        }
        'State' {
            $d = 'disabled'
            if ($Value) { $d = 'enabled' }
            $Changes[('State:{0}' -f $Id)] = New-PendingChange -Label ('Connector {0}' -f $Id) -Value ([bool]$Value) -Display $d -Hint $hint
        }
    }
}

function Format-PSMRow {
    param($Platform, $Config)
    $list = Get-ConnectorList $Config
    $server = [string](Get-NestedValue $Config 'PSMServerID')
    [pscustomobject]@{
        ID                 = $Platform.ID
        PlatformID         = $Platform.PlatformID
        Name               = $Platform.Name
        Active             = $Platform.Active
        PSMServerId        = $server
        PSMServerName      = Get-PSMServerName $server
        EnabledConnectors  = (@($list | Where-Object { $_.Enabled } | ForEach-Object { $_.PSMConnectorID })) -join '; '
        DisabledConnectors = (@($list | Where-Object { -not $_.Enabled } | ForEach-Object { $_.PSMConnectorID })) -join '; '
    }
}

function ConvertTo-PSMSpec {
    param($Row, [int]$Index)
    if ($null -ne $Row) {
        return @{
            Index = $Index; PlatformId = Get-RowValue $Row 'PlatformId'; PSMServerId = Get-RowValue $Row 'PSMServerId'
            Enable = @(Split-ListValue (Get-RowValue $Row 'EnableConnectors')); Disable = @(Split-ListValue (Get-RowValue $Row 'DisableConnectors'))
            Add = @(Split-ListValue (Get-RowValue $Row 'AddConnectors')); Remove = @(Split-ListValue (Get-RowValue $Row 'RemoveConnectors'))
        }
    }
    return @{
        Index = 1; PlatformId = $PlatformId; PSMServerId = $PSMServerId
        Enable = @(Split-ListValue ($EnableConnectors -join ';')); Disable = @(Split-ListValue ($DisableConnectors -join ';'))
        Add = @(Split-ListValue ($AddConnectors -join ';')); Remove = @(Split-ListValue ($RemoveConnectors -join ';'))
    }
}

function Get-SpecPSMChanges {
    param([hashtable]$Spec)
    $changes = [ordered]@{}
    if ($Spec.PSMServerId) {
        $srv = Find-PSMServer -Value $Spec.PSMServerId
        Add-PSMChange $changes 'Server' '' ([string]$srv.ID) ('{0} ({1})' -f $srv.Name, $srv.ID)
    }
    foreach ($id in $Spec.Add) { Add-PSMChange $changes 'Add' $id $true }
    foreach ($id in $Spec.Enable) { Add-PSMChange $changes 'State' $id $true }
    foreach ($id in $Spec.Disable) { Add-PSMChange $changes 'State' $id $false }
    foreach ($id in $Spec.Remove) { Add-PSMChange $changes 'Remove' $id $true }
    return $changes
}

function Invoke-PSMUpdateMenu {
    param($Platform)
    $config = Get-PCloudPlatformPSMConfig -TargetPlatformId $Platform.ID
    $changes = [ordered]@{}
    $lastError = $null

    while ($true) {
        $plan = $null
        $planError = $null
        try { $plan = Get-PlannedPSMConfig -Config $config -Changes $changes } catch { $planError = $_.Exception.Message }
        $curList = Get-ConnectorList $config
        $curServer = [string](Get-NestedValue $config 'PSMServerID')

        Write-Host ''
        if ($lastError) { Write-Host ('Last attempt failed: {0}' -f $lastError) -ForegroundColor Red }
        Write-Host ("PSM settings for platform {0} (ID {1}):" -f $Platform.PlatformID, $Platform.ID)
        $pendServer = ''
        if ($changes.Contains('Server')) { $pendServer = ' -> {0}' -f $changes['Server'].Display }
        Write-Host ('  PSM server: {0} {1}{2}' -f $curServer, $(if (Get-PSMServerName $curServer) { '(' + (Get-PSMServerName $curServer) + ')' } else { '' }), $pendServer)
        Write-Host '  Connectors:'
        if ($curList.Count -eq 0 -and @($changes.Keys | Where-Object { $_ -like 'Add:*' }).Count -eq 0) { Write-Host '     (none)' }
        foreach ($c in $curList) {
            $state = 'disabled'
            if ($c.Enabled) { $state = 'enabled' }
            $pend = ''
            if ($changes.Contains(('State:{0}' -f $c.PSMConnectorID))) { $pend = ' -> {0}' -f $changes[('State:{0}' -f $c.PSMConnectorID)].Display }
            if ($changes.Contains(('Remove:{0}' -f $c.PSMConnectorID))) { $pend = ' -> remove' }
            Write-Host ('     {0,-28} {1}{2}' -f $c.PSMConnectorID, $state, $pend)
        }
        foreach ($k in @($changes.Keys | Where-Object { $_ -like 'Add:*' })) { Write-Host ('     {0,-28} (new) -> enabled' -f $k.Substring(4)) }
        if ($planError) { Write-Host ('  Problem with the pending changes: {0}' -f $planError) -ForegroundColor Red }
        Write-Host '  1) Choose the PSM server'
        Write-Host '  2) Enable connector(s)'
        Write-Host '  3) Disable connector(s)'
        Write-Host '  4) Add connector(s): pick from the list, or search by part of an ID'
        Write-Host '  5) Remove connector(s)'
        Write-Host '  C) Clear pending changes'
        Write-Host '  A) Apply changes'
        Write-Host '  Q) Quit without changes'

        $planned = @()
        if ($plan) { $planned = @($plan.Connectors) }
        $choice = (Read-Host 'Choice').Trim()
        switch -Regex ($choice) {
            '^1$' {
                $servers = @()
                try { $servers = @(Get-PSMServers) } catch { Write-Host ('  Could not list PSM servers: {0}' -f $_.Exception.Message) -ForegroundColor Red }
                if ($servers.Count -eq 0) {
                    $v = (Read-Host 'PSM server ID (leave blank to go back)').Trim()
                    if ($v) { Add-PSMChange $changes 'Server' '' $v $v }
                    break
                }
                $pick = Select-FromList -Items $servers -Title 'PSM servers' -Label { param($x) '{0}  ({1})' -f $x.Name, $x.ID }
                if ($null -eq $pick) { break }
                if ([string]$pick.ID -eq $curServer) { Write-Host 'That is already the PSM server.'; $changes.Remove('Server') }
                else { Add-PSMChange $changes 'Server' '' ([string]$pick.ID) ('{0} ({1})' -f $pick.Name, $pick.ID) }
            }
            '^(2|3)$' {
                $wantOn = ($choice -eq '2')
                $cands = @($planned | Where-Object { [bool]$_.Enabled -ne $wantOn })
                if ($cands.Count -eq 0) { Write-Host ('  No connectors to {0}.' -f $(if ($wantOn) { 'enable' } else { 'disable' })); break }
                $picks = Select-FromList -Items $cands -Multiple -Title $(if ($wantOn) { 'Enable which connector(s)' } else { 'Disable which connector(s)' }) -Label { param($x) [string]$x.PSMConnectorID }
                if ($null -eq $picks) { break }
                foreach ($p in @($picks)) {
                    $id = [string]$p.PSMConnectorID
                    $addKey = 'Add:{0}' -f $id
                    $orig = Find-Connector $curList $id
                    if ($changes.Contains($addKey)) {
                        Write-Host ('  {0} is a new connector; it is added enabled. Apply first, then disable it if needed.' -f $id) -ForegroundColor Yellow
                    } elseif ($orig -and [bool]$orig.Enabled -eq $wantOn) {
                        $changes.Remove(('State:{0}' -f $id))
                    } else {
                        Add-PSMChange $changes 'State' $id $wantOn
                    }
                }
            }
            '^4$' {
                foreach ($id in @(Read-ConnectorToAdd -Planned $planned)) {
                    if (Find-Connector $planned $id) { Write-Host ('  {0} is already on this platform.' -f $id); continue }
                    if (Find-Connector $curList $id) { $changes.Remove(('Remove:{0}' -f $id)); continue }
                    Add-PSMChange $changes 'Add' $id $true
                }
            }
            '^5$' {
                if ($planned.Count -eq 0) { Write-Host '  No connectors to remove.'; break }
                $picks = Select-FromList -Items $planned -Multiple -Title 'Remove which connector(s)' -Label { param($x) [string]$x.PSMConnectorID }
                if ($null -eq $picks) { break }
                foreach ($p in @($picks)) { Add-PSMChange $changes 'Remove' ([string]$p.PSMConnectorID) $true }
            }
            '^(?i)c$' { $changes.Clear() }
            '^(?i)a$' {
                if ($changes.Count -eq 0) { Write-Host 'No changes selected yet.'; break }
                if ($planError) { Write-Host 'Fix the problem above first (C clears the pending changes).' -ForegroundColor Yellow; break }
                if (-not $plan.Server) { Write-Host 'Choose a PSM server first (option 1).' -ForegroundColor Yellow; break }
                Write-Host ''
                Write-Host 'Changes to apply:'
                Write-PendingChanges $changes
                if (@($plan.Connectors).Count -eq 0) { Write-Warning 'The platform will have no PSM connectors, so PSM sessions will not be available for its accounts.' }
                if (-not (Read-YesNo 'Apply these changes?')) { break }
                if (-not $ScriptCmdlet.ShouldProcess(('platform {0} (ID {1})' -f $Platform.PlatformID, $Platform.ID), 'UpdatePlatformPSM')) {
                    Write-Host 'WhatIf: no changes sent.'
                    return
                }
                try {
                    Set-PCloudPlatformPSMConfig -TargetPlatformId $Platform.ID -PSMServerId $plan.Server -PSMConnectors $plan.Connectors -Confirm:$false | Out-Null
                    Write-Host ('PSM settings updated for {0}.' -f $Platform.PlatformID) -ForegroundColor Green
                    if ($OutputPath) {
                        Save-Results -Rows @(Format-PSMRow $Platform (Get-PCloudPlatformPSMConfig -TargetPlatformId $Platform.ID)) -Path $OutputPath
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
                    try { $config = Get-PCloudPlatformPSMConfig -TargetPlatformId $Platform.ID } catch { }
                }
            }
            '^(?i)q$' { Write-Host 'No changes made.'; return }
            default { Write-Host 'Choose 1-5, C, A or Q.' }
        }
    }
}

# ------------------------------------------------------------------ run one action

function Invoke-PSMAction {
    $changeParams = @('PSMServerId', 'EnableConnectors', 'DisableConnectors', 'AddConnectors', 'RemoveConnectors')
    $hasChanges = @($changeParams | Where-Object { $PSBoundParameters_Main.ContainsKey($_) }).Count -gt 0
    if ($Action -eq 'UpdatePlatformPSM' -and -not $CsvPath -and -not $hasChanges) {
        Invoke-PSMUpdateMenu -Platform (Find-Platform -Value $PlatformId)
        return
    }

    $results = New-Object System.Collections.Generic.List[object]
    if ($Action -eq 'GetPSMServers') {
        foreach ($s in @(Get-PSMServers)) { $results.Add($s) }
        $results | Format-Table -AutoSize | Out-String | Write-Host
        Write-Host ('{0} PSM server(s).' -f $results.Count)
        Save-Results -Rows $results.ToArray() -Path $OutputPath
        return
    }

    $specs = New-Object System.Collections.Generic.List[object]
    if ($CsvPath) {
        $r = 0
        foreach ($row in @(Import-WorkCsv -Path $CsvPath)) { $r++; $specs.Add((ConvertTo-PSMSpec -Row $row -Index $r)) }
    } else {
        $specs.Add((ConvertTo-PSMSpec -Row $null -Index 1))
    }

    if ($Action -eq 'GetPlatformPSM') {
        $targets = New-Object System.Collections.Generic.List[object]
        foreach ($spec in $specs) {
            if ($spec.PlatformId) {
                try { $targets.Add((Find-Platform -Value $spec.PlatformId)) } catch { Write-Warning ('Row {0}: {1}' -f $spec.Index, $_.Exception.Message) }
            } else {
                foreach ($p in @(Get-AllTargetPlatforms)) { $targets.Add($p) }
            }
        }
        $i = 0
        foreach ($p in $targets) {
            $i++
            Write-Progress -Activity 'Reading platform PSM settings' -Status $p.PlatformID -PercentComplete (($i / [Math]::Max($targets.Count, 1)) * 100)
            try { $results.Add((Format-PSMRow $p (Get-PCloudPlatformPSMConfig -TargetPlatformId $p.ID))) }
            catch { Write-Warning ('{0}: {1}' -f $p.PlatformID, $_.Exception.Message) }
        }
        Write-Progress -Activity 'Reading platform PSM settings' -Completed
        $results | Format-Table PlatformID, Active, PSMServerName, PSMServerId, EnabledConnectors, DisabledConnectors -AutoSize -Wrap | Out-String | Write-Host
        Write-Host ('{0} platform(s).' -f $results.Count)
        Save-Results -Rows $results.ToArray() -Path $OutputPath
        return
    }

    # UpdatePlatformPSM from a CSV or parameters
    $i = 0
    foreach ($spec in $specs) {
        $i++
        $label = $spec.PlatformId
        $id = $null
        Write-Progress -Activity $Action -Status ('{0} of {1}: {2}' -f $i, $specs.Count, $label) -PercentComplete (($i / [Math]::Max($specs.Count, 1)) * 100)
        try {
            $p = Find-Platform -Value $spec.PlatformId
            $id = [string]$p.ID
            $label = $p.PlatformID
            $changes = Get-SpecPSMChanges -Spec $spec
            if ($changes.Count -eq 0) { throw 'Nothing to update. Fill in PSMServerId or a connector column.' }
            $config = Get-PCloudPlatformPSMConfig -TargetPlatformId $p.ID
            foreach ($k in @($changes.Keys | Where-Object { $_ -like 'Remove:*' })) {
                if (-not (Find-Connector (Get-ConnectorList $config) $k.Substring(7))) { throw ("Connector '{0}' is not on this platform, so it cannot be removed." -f $k.Substring(7)) }
            }
            $plan = Get-PlannedPSMConfig -Config $config -Changes $changes
            if (-not $plan.Server) { throw 'The platform has no PSM server yet. Give PSMServerId.' }
            if ($ScriptCmdlet.ShouldProcess(('platform {0} (ID {1})' -f $label, $id), $Action)) {
                Set-PCloudPlatformPSMConfig -TargetPlatformId $p.ID -PSMServerId $plan.Server -PSMConnectors $plan.Connectors -Confirm:$false | Out-Null
                $results.Add((New-ResultRow -Row $spec.Index -Action $Action -Target $label -Id $id -Status 'Success' -Message ((@($changes.Keys | ForEach-Object { '{0}={1}' -f $changes[$_].Label, $changes[$_].Display })) -join '; ')))
            } else {
                $results.Add((New-ResultRow -Row $spec.Index -Action $Action -Target $label -Id $id -Status 'WhatIf'))
            }
        } catch {
            $msg = $_.Exception.Message
            Write-Warning ('Row {0} ({1}): {2}' -f $spec.Index, $label, $msg)
            $results.Add((New-ResultRow -Row $spec.Index -Action $Action -Target $label -Id $id -Status 'Failed' -Message $msg))
        }
    }
    Write-Progress -Activity $Action -Completed
    Write-WriteResults -Results $results.ToArray() -Action $Action
    Save-Results -Rows $results.ToArray() -Path $OutputPath
}

# ---------- Non-interactive: -Action given. Runs once; errors end the script as usual.
if ($Action) {
    if ($ExportCsv -and -not $OutputPath) { $OutputPath = New-OutputPath -Action $Action }
    if (-not $CsvPath -and $Action -eq 'UpdatePlatformPSM' -and -not $PlatformId) { $PlatformId = Read-Host 'Platform ID or name' }
    Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod
    Invoke-PSMAction
    return
}

# ---------- Menu mode: loops until Q. Any failure returns to the previous prompt or the main menu.
Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod

$original = @{ CsvPath = $CsvPath; OutputPath = $OutputPath; ExportCsv = [bool]$ExportCsv; PlatformId = $PlatformId }

while ($true) {
    foreach ($k in $original.Keys) { Set-Variable -Name $k -Value $original[$k] -Scope Script }
    $Action = $null
    $Action = Read-MainMenu -Title 'Platform PSM management - choose an action:' -Actions $actions -Descriptions $actionHelp
    if (-not $Action) { break }

    try {
        if ($Action -ne 'GetPSMServers' -and -not $CsvPath -and -not $PlatformId) {
            $f = Read-ExistingFile -Prompt 'CSV file path (leave blank for a single platform, B to go back)'
            if ($null -eq $f) { continue }
            if ($f) { $CsvPath = $f }
        }
        if (-not $CsvPath -and -not $PlatformId) {
            if ($Action -eq 'GetPlatformPSM') {
                if (Read-YesNo 'Show every platform? (No lets you pick one)' $true) { $PlatformId = '' }
                else {
                    $p = Read-PlatformTarget
                    if ($null -eq $p) { continue }
                    $PlatformId = $p.PlatformID
                }
            } elseif ($Action -eq 'UpdatePlatformPSM') {
                $p = Read-PlatformTarget
                if ($null -eq $p) { continue }
                $PlatformId = $p.PlatformID
            }
        }
        if (($readActions -contains $Action) -and -not $OutputPath -and -not $ExportCsv) { $OutputPath = Read-OutputChoice -Action $Action }
        if ($ExportCsv -and -not $OutputPath) { $OutputPath = New-OutputPath -Action $Action }

        Invoke-PSMAction
    } catch {
        Write-Host ''
        Write-Host ('{0} failed: {1}' -f $Action, $_.Exception.Message) -ForegroundColor Red
        Write-Host 'Returning to the main menu.' -ForegroundColor Yellow
    }
}
