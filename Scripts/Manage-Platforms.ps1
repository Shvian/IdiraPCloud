#Requires -Version 5.1
<#
.SYNOPSIS
    Platform management for Idira Privilege Cloud: list and view target platforms, activate, deactivate,
    duplicate, delete, export and import. Actions work on one platform or on every row of a CSV, the
    same way as Manage-Safes.ps1. PSM assignment is in Manage-PlatformPSM.ps1.
.DESCRIPTION
    Actions:
      GetPlatforms        List target platforms with their main policy settings (CPM change/verify/
                          reconcile, dual control, exclusive and one-time access, PSM server).
                          With nothing specified, returns every target platform.
                          Single: -Search and/or -Active true|false.  CSV column: Search.
      GetPlatformDetails  Every setting of a platform as Setting/Value rows (properties, CPM policy,
                          session management, workflows). Single: -PlatformId.  CSV column: PlatformId.
      ActivatePlatform    Activate platforms.                  CSV column: PlatformId.
      DeactivatePlatform  Deactivate platforms.                CSV column: PlatformId.
      DuplicatePlatform   Copy a platform under a new name.    CSV columns: PlatformId, NewName, Description.
      DeletePlatform      Delete platforms (type DELETE to confirm, or -Force). CSV column: PlatformId.
      ExportPlatform      Save a platform package (.zip).      CSV columns: PlatformId, Path (file or folder).
      ImportPlatform      Import a platform package (.zip).    CSV column: Path.

    -PlatformId accepts the platform ID (e.g. WinDomain), its name, or its numeric ID. From the menu you
    can type one or pick from a list (long lists ask for filter text first).
    Run without -Action to pick from a menu. Prompts for sign-in if there is no active session.
    The menu loops until you choose Q; any failure returns you to the previous prompt or the main menu.
    Write actions support -WhatIf. CSV export: -ExportCsv or -OutputPath <file> for the Get actions.
.EXAMPLE
    .\Manage-Platforms.ps1
.EXAMPLE
    .\Manage-Platforms.ps1 -Action GetPlatforms -Active true -ExportCsv
.EXAMPLE
    .\Manage-Platforms.ps1 -Action GetPlatformDetails -PlatformId WinDomain -OutputPath .\windomain.csv
.EXAMPLE
    .\Manage-Platforms.ps1 -Action DuplicatePlatform -PlatformId UnixSSH -NewName 'UnixSSH-Prod' -Description 'Prod Unix'
.EXAMPLE
    .\Manage-Platforms.ps1 -Action ExportPlatform -CsvPath .\samples\platforms-export.csv
.EXAMPLE
    .\Manage-Platforms.ps1 -Action DeactivatePlatform -CsvPath .\samples\platforms-ids.csv -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ArgumentCompleter({ param($c, $p, $w) 'GetPlatforms', 'GetPlatformDetails', 'ActivatePlatform', 'DeactivatePlatform', 'DuplicatePlatform', 'DeletePlatform', 'ExportPlatform', 'ImportPlatform' | Where-Object { $_ -like "$w*" } })]
    [string]$Action,

    [string]$CsvPath,
    [string]$OutputPath,
    [switch]$ExportCsv,
    [switch]$Force,

    [string]$PlatformId,
    [string]$Search,
    [ArgumentCompleter({ param($c, $p, $w) 'true', 'false' | Where-Object { $_ -like "$w*" } })]
    [string]$Active,
    [string]$NewName,
    [string]$Description,
    # ExportPlatform: target .zip or folder. ImportPlatform: the .zip to import.
    [string]$Path,

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

$actions = @('GetPlatforms', 'GetPlatformDetails', 'ActivatePlatform', 'DeactivatePlatform', 'DuplicatePlatform', 'DeletePlatform', 'ExportPlatform', 'ImportPlatform')
$actionHelp = @{
    GetPlatforms       = 'list target platforms and their main policy settings'
    GetPlatformDetails = 'every setting of a platform'
    ActivatePlatform   = 'make a platform available for accounts'
    DeactivatePlatform = 'stop new accounts using a platform'
    DuplicatePlatform  = 'copy a platform under a new name'
    DeletePlatform     = 'delete a platform'
    ExportPlatform     = 'save a platform package (.zip)'
    ImportPlatform     = 'import a platform package (.zip)'
}
$readActions = @('GetPlatforms', 'GetPlatformDetails')
if ($Action) {
    $m = @($actions | Where-Object { $_ -eq $Action })
    if ($m.Count -eq 0) { throw ("-Action must be one of: {0}" -f ($actions -join ', ')) }
    $Action = $m[0]
}
if ($Active) { $null = ConvertTo-OptionalBool $Active 'Active' }

$ScriptCmdlet = $PSCmdlet

# ------------------------------------------------------------------ helpers

function Format-PlatformRow {
    param($P)
    [pscustomobject]@{
        ID                = $P.ID
        PlatformID        = $P.PlatformID
        Name              = $P.Name
        Active            = $P.Active
        SystemType        = $P.SystemType
        AllowedSafes      = $P.AllowedSafes
        AutoChange        = Get-NestedValue $P 'CredentialsManagementPolicy.Change.PerformAutomatic'
        ChangeEveryXDays  = Get-NestedValue $P 'CredentialsManagementPolicy.Change.RequirePasswordEveryXDays'
        AutoVerify        = Get-NestedValue $P 'CredentialsManagementPolicy.Verification.PerformAutomatic'
        VerifyEveryXDays  = Get-NestedValue $P 'CredentialsManagementPolicy.Verification.RequirePasswordEveryXDays'
        AutoReconcile     = Get-NestedValue $P 'CredentialsManagementPolicy.Reconcile.AutomaticReconcileWhenUnsynced'
        DualControl       = Get-NestedValue $P 'PrivilegedAccessWorkflows.RequireDualControlPasswordAccessApproval.IsActive'
        ExclusiveAccess   = Get-NestedValue $P 'PrivilegedAccessWorkflows.EnforceCheckinCheckoutExclusiveAccess.IsActive'
        OneTimeAccess     = Get-NestedValue $P 'PrivilegedAccessWorkflows.EnforceOnetimePasswordAccess.IsActive'
        PSMServerId       = Get-NestedValue $P 'PrivilegedSessionManagement.PSMServerId'
        PSMServerName     = Get-NestedValue $P 'PrivilegedSessionManagement.PSMServerName'
    }
}

function Get-PlatformDetailRows {
    param($P)
    $detail = $null
    try { $detail = Get-PCloudPlatform -PlatformId $P.PlatformID } catch {
        Write-Verbose ('Platform details not available for {0}: {1}' -f $P.PlatformID, $_.Exception.Message)
    }
    if ($null -eq $detail) { $detail = $P }
    foreach ($s in @(ConvertTo-PCloudFlatSetting -InputObject $detail)) {
        [pscustomobject]@{ PlatformID = $P.PlatformID; Setting = $s.Setting; Value = $s.Value }
    }
}

function Resolve-ExportPath {
    param([string]$Value, [string]$PlatformName)
    $file = '{0}.zip' -f ($PlatformName -replace '[\\/:*?"<>|]', '_')
    if (-not $Value) { return (Join-Path (Get-PCloudOutputFolder) $file) }
    $full = Resolve-PCloudOutputPath $Value
    if (Test-Path -LiteralPath $full -PathType Container) { return (Join-Path $full $file) }
    return $full
}

function ConvertTo-PlatformSpec {
    param($Row, [int]$Index)
    if ($null -ne $Row) {
        return @{
            Index = $Index; PlatformId = Get-RowValue $Row 'PlatformId'; Search = Get-RowValue $Row 'Search'
            NewName = Get-RowValue $Row 'NewName'; Description = Get-RowValue $Row 'Description'; Path = Get-RowValue $Row 'Path'
        }
    }
    return @{ Index = 1; PlatformId = $PlatformId; Search = $Search; NewName = $NewName; Description = $Description; Path = $Path }
}

# ------------------------------------------------------------------ run one action

function Invoke-PlatformAction {
    $specs = New-Object System.Collections.Generic.List[object]
    $results = New-Object System.Collections.Generic.List[object]
    if ($CsvPath) {
        $r = 0
        foreach ($row in @(Import-WorkCsv -Path $CsvPath)) { $r++; $specs.Add((ConvertTo-PlatformSpec -Row $row -Index $r)) }
    } else {
        $specs.Add((ConvertTo-PlatformSpec -Row $null -Index 1))
    }
    $isWrite = $readActions -notcontains $Action

    if ($Action -eq 'DeletePlatform') {
        $what = '{0} platform(s)' -f $specs.Count
        if ($specs.Count -eq 1) { $what = 'platform {0}' -f (Find-Platform -Value $specs[0].PlatformId).PlatformID }
        if (-not (Confirm-Destructive -What $what -Force:$Force)) { Write-Host 'Delete cancelled.'; return }
    }

    $changed = $false
    $i = 0
    foreach ($spec in $specs) {
        $i++
        $label = $spec.PlatformId
        if ($Action -eq 'ImportPlatform') { $label = $spec.Path }
        Write-Progress -Activity $Action -Status ('{0} of {1}: {2}' -f $i, $specs.Count, $label) -PercentComplete (($i / [Math]::Max($specs.Count, 1)) * 100)
        $id = $null
        try {
            switch ($Action) {
                'GetPlatforms' {
                    $list = @(Get-AllTargetPlatforms)
                    if ($spec.Search) { $list = @($list | Where-Object { $_.PlatformID -like "*$($spec.Search)*" -or $_.Name -like "*$($spec.Search)*" -or $_.SystemType -like "*$($spec.Search)*" }) }
                    if ($Active) { $want = ConvertTo-OptionalBool $Active 'Active'; $list = @($list | Where-Object { [bool]$_.Active -eq $want }) }
                    foreach ($p in $list) { $results.Add((Format-PlatformRow $p)) }
                }
                'GetPlatformDetails' {
                    foreach ($row in @(Get-PlatformDetailRows (Find-Platform -Value $spec.PlatformId))) { $results.Add($row) }
                }
                'ImportPlatform' {
                    if (-not $spec.Path) { throw 'Path to the platform .zip is required.' }
                    $zip = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($spec.Path.Trim('"'))
                    if (-not (Test-Path -LiteralPath $zip -PathType Leaf)) { throw "File not found: $zip" }
                    if ($ScriptCmdlet.ShouldProcess($zip, 'ImportPlatform')) {
                        $res = Import-PCloudPlatform -Path $zip -Confirm:$false
                        $newId = Get-NestedValue $res 'PlatformID'
                        $changed = $true
                        $results.Add((New-ResultRow -Row $spec.Index -Action $Action -Target $zip -Id $newId -Status 'Success' -Message 'Imported (new platforms start inactive; activate when ready)'))
                    } else {
                        $results.Add((New-ResultRow -Row $spec.Index -Action $Action -Target $zip -Status 'WhatIf'))
                    }
                }
                default {
                    $p = Find-Platform -Value $spec.PlatformId
                    $id = [string]$p.ID
                    $label = $p.PlatformID
                    $msg = $null
                    if ($Action -eq 'ActivatePlatform' -and $p.Active) { $results.Add((New-ResultRow -Row $spec.Index -Action $Action -Target $label -Id $id -Status 'Success' -Message 'Already active')); break }
                    if ($Action -eq 'DeactivatePlatform' -and -not $p.Active) { $results.Add((New-ResultRow -Row $spec.Index -Action $Action -Target $label -Id $id -Status 'Success' -Message 'Already inactive')); break }
                    $exportFile = $null
                    if ($Action -eq 'ExportPlatform') {
                        $exportFile = Resolve-ExportPath -Value $spec.Path -PlatformName $p.PlatformID
                        if ((Test-Path -LiteralPath $exportFile) -and -not $Force) { throw ("{0} already exists. Choose another path or use -Force." -f $exportFile) }
                    }
                    if ($Action -eq 'DuplicatePlatform' -and -not $spec.NewName) { throw 'NewName is required.' }
                    if (-not $ScriptCmdlet.ShouldProcess(('platform {0} (ID {1})' -f $p.PlatformID, $id), $Action)) {
                        $results.Add((New-ResultRow -Row $spec.Index -Action $Action -Target $label -Id $id -Status 'WhatIf'))
                        break
                    }
                    switch ($Action) {
                        'ActivatePlatform' { Enable-PCloudTargetPlatform -TargetPlatformId $p.ID -Confirm:$false; $msg = 'Activated' }
                        'DeactivatePlatform' { Disable-PCloudTargetPlatform -TargetPlatformId $p.ID -Confirm:$false; $msg = 'Deactivated' }
                        'DeletePlatform' { Remove-PCloudTargetPlatform -TargetPlatformId $p.ID -Confirm:$false; $msg = 'Deleted' }
                        'DuplicatePlatform' {
                            $cp = @{ TargetPlatformId = $p.ID; Name = $spec.NewName; Confirm = $false }
                            if ($spec.Description) { $cp['Description'] = $spec.Description }
                            $new = Copy-PCloudTargetPlatform @cp
                            $msg = 'Copied as {0} (ID {1}, PlatformID {2})' -f $spec.NewName, (Get-NestedValue $new 'ID'), (Get-NestedValue $new 'PlatformID')
                        }
                        'ExportPlatform' { Export-PCloudPlatform -PlatformId $p.PlatformID -Path $exportFile | Out-Null; $msg = 'Saved to {0}' -f $exportFile }
                    }
                    if ($Action -ne 'ExportPlatform') { $changed = $true }
                    $results.Add((New-ResultRow -Row $spec.Index -Action $Action -Target $label -Id $id -Status 'Success' -Message $msg))
                }
            }
        } catch {
            $msg = $_.Exception.Message
            Write-Warning ('Row {0} ({1}): {2}' -f $spec.Index, $label, $msg)
            if ($isWrite) { $results.Add((New-ResultRow -Row $spec.Index -Action $Action -Target $label -Id $id -Status 'Failed' -Message $msg)) }
        }
    }
    Write-Progress -Activity $Action -Completed
    if ($changed) { $null = Get-AllTargetPlatforms -Refresh }

    if ($isWrite) {
        Write-WriteResults -Results $results.ToArray() -Action $Action
    } elseif ($Action -eq 'GetPlatformDetails') {
        $results | Format-Table PlatformID, Setting, Value -AutoSize -Wrap | Out-String | Write-Host
        Write-Host ('{0} setting(s).' -f $results.Count)
    } else {
        $results | Format-Table PlatformID, Name, Active, SystemType, AutoChange, ChangeEveryXDays, DualControl, PSMServerName -AutoSize | Out-String | Write-Host
        Write-Host ('{0} platform(s).' -f $results.Count)
    }
    Save-Results -Rows $results.ToArray() -Path $OutputPath
}

# ---------- Non-interactive: -Action given. Runs once; errors end the script as usual.
if ($Action) {
    if ($ExportCsv -and -not $OutputPath) { $OutputPath = New-OutputPath -Action $Action }
    if (-not $CsvPath) {
        if ($Action -eq 'ImportPlatform') { if (-not $Path) { $Path = Read-Host 'Platform package (.zip) path' } }
        elseif ($Action -ne 'GetPlatforms' -and -not $PlatformId) { $PlatformId = Read-Host 'Platform ID or name' }
        if ($Action -eq 'DuplicatePlatform' -and -not $NewName) { $NewName = Read-Host 'New platform name' }
    }
    Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod
    Invoke-PlatformAction
    return
}

# ---------- Menu mode: loops until Q. Any failure returns to the previous prompt or the main menu.
Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod

$original = @{
    CsvPath = $CsvPath; OutputPath = $OutputPath; ExportCsv = [bool]$ExportCsv
    PlatformId = $PlatformId; Search = $Search; Active = $Active; NewName = $NewName; Description = $Description; Path = $Path
}

while ($true) {
    foreach ($k in $original.Keys) { Set-Variable -Name $k -Value $original[$k] -Scope Script }
    $Action = $null
    $Action = Read-MainMenu -Title 'Platform management - choose an action:' -Actions $actions -Descriptions $actionHelp
    if (-not $Action) { break }

    try {
        if ($Action -ne 'GetPlatforms' -and -not $CsvPath) {
            $f = Read-ExistingFile -Prompt 'CSV file path (leave blank for a single platform, B to go back)'
            if ($null -eq $f) { continue }
            if ($f) { $CsvPath = $f }
        }

        if (-not $CsvPath) {
            switch ($Action) {
                'GetPlatforms' {
                    $Search = Read-Host 'Filter text for platform ID, name or system type (leave blank for all)'
                    while ($true) {
                        $a = (Read-Host 'Show (A)ll, active only (Y) or inactive only (N)? [A]').Trim()
                        if (-not $a -or $a -match '^(?i)a$') { $Active = ''; break }
                        if ($a -match '^(?i)y$') { $Active = 'true'; break }
                        if ($a -match '^(?i)n$') { $Active = 'false'; break }
                        Write-Host '  Enter A, Y or N.' -ForegroundColor Red
                    }
                }
                'ImportPlatform' {
                    $f = Read-ExistingFile -Prompt 'Platform package (.zip) to import (leave blank or B to go back)'
                    if (-not $f) { $Action = $null } else { $Path = $f }
                }
                default {
                    $p = Read-PlatformTarget
                    if ($null -eq $p) { $Action = $null } else { $PlatformId = $p.PlatformID }
                }
            }
            if ($Action -eq 'DuplicatePlatform') {
                $NewName = (Read-Host 'New platform name (leave blank to go back)').Trim()
                if (-not $NewName) { $Action = $null } else { $Description = Read-Host 'Description (optional)' }
            }
            if ($Action -eq 'ExportPlatform') {
                $Path = Read-Host ('Save to (file or folder; leave blank for {0}\{1}.zip)' -f $script:PCloudOutputFolder, $PlatformId)
            }
            if (-not $Action) { continue }
        }

        if (($readActions -contains $Action) -and -not $OutputPath -and -not $ExportCsv) { $OutputPath = Read-OutputChoice -Action $Action }
        if ($ExportCsv -and -not $OutputPath) { $OutputPath = New-OutputPath -Action $Action }

        Invoke-PlatformAction
    } catch {
        Write-Host ''
        Write-Host ('{0} failed: {1}' -f $Action, $_.Exception.Message) -ForegroundColor Red
        Write-Host 'Returning to the main menu.' -ForegroundColor Yellow
    }
}
