#Requires -Version 5.1
<#
.SYNOPSIS
    Application (Credential Provider) management for Idira Privilege Cloud: list and view applications,
    add and delete them, manage their authentication methods, and grant or revoke their safe access.
    Actions work on one application or on every row of a CSV, the same way as Manage-Safes.ps1.
.DESCRIPTION
    Actions:
      GetApplications       List applications. Single: -Search (part of the AppID) and/or -Location.
                            CSV columns: Search, Location. With nothing given, lists every application.
      GetApplicationDetails Every setting of an application and its authentication methods as Setting/Value rows.
                            Single: -AppId.  CSV column: AppID.
      AddApplication        Add applications. CSV columns: AppID, Description, Location, AccessPermittedFrom,
                            AccessPermittedTo, ExpirationDate, Disabled, BusinessOwnerFName, BusinessOwnerLName,
                            BusinessOwnerEmail, BusinessOwnerPhone. Location defaults to the root (\); locations are
                            deprecated in Privilege Cloud, so the menu doesn't ask. The access hours default to 0-23.
      DeleteApplication     Delete applications (type DELETE to confirm, or -Force). CSV column: AppID.
      GetAuthentications    An application's authentication methods.  CSV column: AppID.
      AddAuthentication     Add an authentication method. CSV columns: AppID, AuthType, AuthValue, IsFolder,
                            AllowInternalScripts, Comment, Subject, Issuer, SubjectAlternativeName.
                            AuthType: path, hash, osUser, machineAddress, certificateserialnumber or
                            certificateattr (certificate attributes use Subject/Issuer/SubjectAlternativeName,
                            each a ;-separated list, instead of AuthValue).
      RemoveAuthentication  Remove authentication methods (type DELETE to confirm, or -Force).
                            CSV columns: AppID plus AuthID, or AuthType and AuthValue to match.
      GrantSafeAccess       Add the application to a safe with List and Retrieve accounts, the access a
                            Credential Provider application needs. Providers (;-separated, for example
                            Prov_SERVER01) are added too, with List, Retrieve and View safe members.
                            CSV columns: AppID, SafeName, Providers.
      RevokeSafeAccess      Remove the application (and any listed Providers) from a safe.
                            CSV columns: AppID, SafeName, Providers.

    -AppId takes the exact application ID. From the menu you can type part of one, or L to pick from a list.
    The Applications API has no update call: change an application's methods with Add/RemoveAuthentication.
    Run without -Action to pick from a menu. Prompts for sign-in if there is no active session.
    The menu loops until you choose Q; any failure returns you to the previous prompt or the main menu.
    Write actions support -WhatIf. CSV export: -ExportCsv or -OutputPath <file> for the Get actions.
.EXAMPLE
    .\Manage-Applications.ps1
.EXAMPLE
    .\Manage-Applications.ps1 -Action GetApplications -Search billing -ExportCsv
.EXAMPLE
    .\Manage-Applications.ps1 -Action AddApplication -AppId BillingApp -Description 'Billing batch jobs'
.EXAMPLE
    .\Manage-Applications.ps1 -Action AddAuthentication -AppId BillingApp -AuthType machineAddress -AuthValue 10.0.1.25
.EXAMPLE
    .\Manage-Applications.ps1 -Action GrantSafeAccess -AppId BillingApp -SafeName Billing-DB -Providers Prov_APP01
.EXAMPLE
    .\Manage-Applications.ps1 -Action AddApplication -CsvPath .\samples\applications-add.csv -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ArgumentCompleter({ param($c, $p, $w) 'GetApplications', 'GetApplicationDetails', 'AddApplication', 'DeleteApplication', 'GetAuthentications', 'AddAuthentication', 'RemoveAuthentication', 'GrantSafeAccess', 'RevokeSafeAccess' | Where-Object { $_ -like "$w*" } })]
    [string]$Action,

    [string]$CsvPath,
    [string]$OutputPath,
    [switch]$ExportCsv,
    [switch]$Force,

    [string]$AppId,
    [string]$Search,
    [string]$Location,
    [string]$Description,
    [string]$AccessPermittedFrom,
    [string]$AccessPermittedTo,
    [string]$ExpirationDate,
    [ArgumentCompleter({ param($c, $p, $w) 'true', 'false' | Where-Object { $_ -like "$w*" } })]
    [string]$Disabled,
    [string]$BusinessOwnerFName,
    [string]$BusinessOwnerLName,
    [string]$BusinessOwnerEmail,
    [string]$BusinessOwnerPhone,

    [ArgumentCompleter({ param($c, $p, $w) 'path', 'hash', 'osUser', 'machineAddress', 'certificateserialnumber', 'certificateattr' | Where-Object { $_ -like "$w*" } })]
    [string]$AuthType,
    [string]$AuthValue,
    [string]$AuthId,
    [string]$IsFolder,
    [string]$AllowInternalScripts,
    [string]$Comment,
    [string]$Subject,
    [string]$Issuer,
    [string]$SubjectAlternativeName,

    [string]$SafeName,
    # ;-separated Provider users, for example 'Prov_SERVER01;Prov_SERVER02'
    [string]$Providers,

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

$actions = @('GetApplications', 'GetApplicationDetails', 'AddApplication', 'DeleteApplication', 'GetAuthentications', 'AddAuthentication', 'RemoveAuthentication', 'GrantSafeAccess', 'RevokeSafeAccess')
$actionHelp = @{
    GetApplications       = 'list applications (search by part of the ID)'
    GetApplicationDetails = 'every setting and authentication method of an application'
    AddApplication        = 'add an application'
    DeleteApplication     = 'delete an application'
    GetAuthentications    = 'authentication methods of an application'
    AddAuthentication     = 'add a path, hash, OS user, address or certificate method'
    RemoveAuthentication  = 'remove authentication method(s)'
    GrantSafeAccess       = 'let the application (and its providers) retrieve from a safe'
    RevokeSafeAccess      = 'remove the application from a safe'
}
$readActions = @('GetApplications', 'GetApplicationDetails', 'GetAuthentications')
if ($Action) {
    $m = @($actions | Where-Object { $_ -eq $Action })
    if ($m.Count -eq 0) { throw ("-Action must be one of: {0}" -f ($actions -join ', ')) }
    $Action = $m[0]
}
$ScriptCmdlet = $PSCmdlet

$authTypes = @(
    [pscustomobject]@{ Type = 'path'; Text = 'Path - the program or folder that requests the credential' },
    [pscustomobject]@{ Type = 'hash'; Text = 'Hash - the hash of the program (from the AIM GetHash utility)' },
    [pscustomobject]@{ Type = 'osUser'; Text = 'OS user - the user the program runs as (DOMAIN\user)' },
    [pscustomobject]@{ Type = 'machineAddress'; Text = 'Machine address - IP, host name or address range' },
    [pscustomobject]@{ Type = 'certificateserialnumber'; Text = 'Certificate serial number (Central Credential Provider)' },
    [pscustomobject]@{ Type = 'certificateattr'; Text = 'Certificate attributes - subject, issuer, SAN (Central Credential Provider)' }
)
$specColumns = @('AppID', 'Search', 'Location', 'Description', 'AccessPermittedFrom', 'AccessPermittedTo', 'ExpirationDate', 'Disabled',
    'BusinessOwnerFName', 'BusinessOwnerLName', 'BusinessOwnerEmail', 'BusinessOwnerPhone', 'AuthType', 'AuthValue', 'AuthID',
    'IsFolder', 'AllowInternalScripts', 'Comment', 'Subject', 'Issuer', 'SubjectAlternativeName', 'SafeName', 'Providers')

# ------------------------------------------------------------------ helpers

function ConvertTo-AuthType {
    # Accepts the API names in any case plus a few short forms. Throws on anything else.
    param([string]$Value)
    $v = ([string]$Value).Trim().ToLowerInvariant() -replace '[\s_\-]', ''
    switch -Regex ($v) {
        '^path$' { return 'path' }
        '^hash$' { return 'hash' }
        '^(osuser|user)$' { return 'osUser' }
        '^(machineaddress|machine|address|ip)$' { return 'machineAddress' }
        '^(certificateserialnumber|certserial|serial|serialnumber)$' { return 'certificateserialnumber' }
        '^(certificateattr|certificateattributes|certattr|certificate)$' { return 'certificateattr' }
    }
    throw ("Unknown AuthType '{0}'. Use path, hash, osUser, machineAddress, certificateserialnumber or certificateattr." -f $Value)
}

function ConvertTo-Hour {
    param([string]$Value, [string]$Name, [int]$Default)
    if (-not $Value) { return $Default }
    $n = 0
    if ([int]::TryParse($Value.Trim(), [ref]$n) -and $n -ge 0 -and $n -le 23) { return $n }
    throw ('{0} must be an hour from 0 to 23.' -f $Name)
}

function ConvertTo-AppDate {
    param([string]$Value)
    if (-not $Value) { return $null }
    $d = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::None
    foreach ($fmt in @('yyyy-MM-dd', 'MM-dd-yyyy', 'MM/dd/yyyy')) {
        if ([datetime]::TryParseExact($Value.Trim(), $fmt, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
    }
    if ([datetime]::TryParse($Value.Trim(), [ref]$d)) { return $d }
    throw ("ExpirationDate '{0}' is not a date. Use yyyy-MM-dd." -f $Value)
}

function Format-AppRow {
    param($A)
    $exp = Get-NestedValue $A 'ExpirationDate'
    [pscustomobject]@{
        AppID               = [string](Get-NestedValue $A 'AppID')
        Description         = Get-NestedValue $A 'Description'
        Location            = Get-NestedValue $A 'Location'
        Disabled            = Get-NestedValue $A 'Disabled'
        AccessPermittedFrom = Get-NestedValue $A 'AccessPermittedFrom'
        AccessPermittedTo   = Get-NestedValue $A 'AccessPermittedTo'
        ExpirationDate      = $exp
        BusinessOwnerFName  = Get-NestedValue $A 'BusinessOwnerFName'
        BusinessOwnerLName  = Get-NestedValue $A 'BusinessOwnerLName'
        BusinessOwnerEmail  = Get-NestedValue $A 'BusinessOwnerEmail'
        BusinessOwnerPhone  = Get-NestedValue $A 'BusinessOwnerPhone'
    }
}

function Format-AuthRow {
    param([string]$App, $M)
    $join = { param($v) if ($null -eq $v) { '' } else { (@($v) | ForEach-Object { [string]$_ }) -join '; ' } }
    [pscustomobject]@{
        AppID                  = $App
        AuthID                 = [string](Get-NestedValue $M 'authID')
        AuthType               = Get-NestedValue $M 'AuthType'
        AuthValue              = Get-NestedValue $M 'AuthValue'
        IsFolder               = Get-NestedValue $M 'IsFolder'
        AllowInternalScripts   = Get-NestedValue $M 'AllowInternalScripts'
        Comment                = Get-NestedValue $M 'Comment'
        Subject                = & $join (Get-NestedValue $M 'Subject')
        Issuer                 = & $join (Get-NestedValue $M 'Issuer')
        SubjectAlternativeName = & $join (Get-NestedValue $M 'SubjectAlternativeName')
    }
}

function Format-AppLabel {
    param($A)
    $id = [string](Get-NestedValue $A 'AppID')
    $d = [string](Get-NestedValue $A 'Description')
    $off = ''
    if ([string](Get-NestedValue $A 'Disabled') -match '^(?i)true$') { $off = '  [disabled]' }
    if ($d) { return ('{0}  - {1}{2}' -f $id, $d, $off) }
    return ('{0}{1}' -f $id, $off)
}

function Format-AuthLabel {
    param($R)
    $v = $R.AuthValue
    if ($R.AuthType -eq 'certificateattr') { $v = ('subject: {0}  issuer: {1}  SAN: {2}' -f $R.Subject, $R.Issuer, $R.SubjectAlternativeName) }
    $extra = ''
    if ($R.AuthType -eq 'path') { $extra = '  (folder: {0}, internal scripts: {1})' -f $R.IsFolder, $R.AllowInternalScripts }
    return ('{0,-24} {1}{2}' -f $R.AuthType, $v, $extra)
}

function Find-App {
    # Exact application ID. A miss lists the IDs that contain the text, to help with typos.
    param([string]$Value)
    if (-not $Value) { throw 'AppID is required.' }
    try {
        $a = Get-PCloudApplication -AppId $Value -ExactMatch
        if ($a) { return $a }
    } catch { }
    $near = @()
    try { $near = @(Get-PCloudApplication -AppId $Value | ForEach-Object { [string]$_.AppID }) } catch { }
    if ($near.Count -gt 0) { throw ("Application '{0}' was not found. Similar IDs: {1}" -f $Value, (($near | Select-Object -First 10) -join ', ')) }
    throw ("Application '{0}' was not found." -f $Value)
}

function Read-AppTarget {
    # Exact ID, part of an ID, or L for the full list. Returns the application object, or $null to go back.
    while ($true) {
        $t = (Read-Host 'Application ID or part of it, or L to list all (leave blank to go back)').Trim()
        if (-not $t) { return $null }
        if ($t -match '^(?i)l$') {
            $all = @(Get-PCloudApplication | Sort-Object AppID)
            $pick = Select-FromList -Items $all -Title 'Applications' -Label { param($x) Format-AppLabel $x }
            if ($null -ne $pick) { return $pick }
            continue
        }
        $exact = $null
        try { $exact = Get-PCloudApplication -AppId $t -ExactMatch } catch { }
        if ($exact) { return $exact }
        $pattern = '*{0}*' -f [System.Management.Automation.WildcardPattern]::Escape($t)
        $hits = @()
        try { $hits = @(Get-PCloudApplication -AppId $t | Where-Object { [string]$_.AppID -like $pattern }) } catch { Write-Host ('  {0}' -f $_.Exception.Message) -ForegroundColor Red }
        if ($hits.Count -eq 0) {
            # Fall back to a contains-match over every application (ID and description).
            try { $hits = @(Get-PCloudApplication | Where-Object { [string]$_.AppID -like $pattern -or [string]$_.Description -like $pattern }) } catch { }
        }
        $hits = @($hits | Sort-Object AppID)
        $pick = Select-PartialMatch -Items $hits -Text $t -Noun 'application' -Label { param($x) Format-AppLabel $x }
        if ($null -ne $pick) { return $pick }
    }
}

function Read-Validated {
    # Prompts until $Check accepts the answer (it throws to reject). Blank keeps $Default; B returns $null.
    param([string]$Prompt, [scriptblock]$Check, [string]$Default = '')
    while ($true) {
        $v = (Read-Host $Prompt).Trim()
        if ($v -match '^(?i)b$') { return $null }
        if (-not $v) { $v = $Default }
        try { $null = & $Check $v; return $v } catch { Write-Host ('  {0}' -f $_.Exception.Message) -ForegroundColor Red }
    }
}

function New-SpecRow {
    # A row with every spec column, filled from a hashtable.
    param([hashtable]$Values)
    $o = [ordered]@{}
    foreach ($c in $specColumns) { $o[$c] = ''; if ($Values -and $Values.ContainsKey($c) -and $null -ne $Values[$c]) { $o[$c] = [string]$Values[$c] } }
    return [pscustomobject]$o
}

function Read-NewApplication {
    # Prompts for a new application. Returns a spec row, or $null to go back.
    while ($true) {
        $id = (Read-Host 'New application ID (leave blank to go back)').Trim()
        if (-not $id) { return $null }
        if ($id.Length -gt 128) { Write-Host '  Application IDs are at most 128 characters.' -ForegroundColor Red; continue }
        $exists = $null
        try { $exists = Get-PCloudApplication -AppId $id -ExactMatch } catch { }
        if ($exists) { Write-Host ('  Application {0} already exists.' -f $id) -ForegroundColor Red; continue }
        break
    }
    Write-Host '  B at any prompt goes back. Blank keeps the value in brackets.'
    $v = @{ AppID = $id }
    $v.Description = Read-Host 'Description (optional)'
    $v.AccessPermittedFrom = Read-Validated -Prompt 'Access permitted from hour (0-23) [0]' -Default '0' -Check { param($x) ConvertTo-Hour $x 'The hour' 0 }
    if ($null -eq $v.AccessPermittedFrom) { return $null }
    $v.AccessPermittedTo = Read-Validated -Prompt 'Access permitted to hour (0-23) [23]' -Default '23' -Check { param($x) ConvertTo-Hour $x 'The hour' 23 }
    if ($null -eq $v.AccessPermittedTo) { return $null }
    $v.ExpirationDate = Read-Validated -Prompt 'Expiration date, yyyy-MM-dd (blank for none)' -Check { param($x) ConvertTo-AppDate $x }
    if ($null -eq $v.ExpirationDate) { return $null }
    $v.Disabled = 'false'
    if (Read-YesNo 'Create it disabled?') { $v.Disabled = 'true' }
    if (Read-YesNo 'Add business owner details?') {
        $v.BusinessOwnerFName = Read-Host 'Business owner first name'
        $v.BusinessOwnerLName = Read-Host 'Business owner last name'
        $v.BusinessOwnerEmail = Read-Host 'Business owner email'
        $v.BusinessOwnerPhone = Read-Host 'Business owner phone'
    }
    return (New-SpecRow $v)
}

function Read-NewAuthentication {
    # Prompts for one authentication method. Returns a spec row, or $null to go back.
    param([string]$App)
    $t = Select-FromList -Items $authTypes -Title 'Authentication type' -Label { param($x) $x.Text }
    if ($null -eq $t) { return $null }
    $v = @{ AppID = $App; AuthType = $t.Type }
    switch ($t.Type) {
        'certificateattr' {
            Write-Host '  Give at least one. Separate several values with ;'
            $v.Subject = Read-Host 'Subject attributes (for example CN=billing;OU=Apps)'
            $v.Issuer = Read-Host 'Issuer attributes'
            $v.SubjectAlternativeName = Read-Host 'Subject alternative names (for example DNS Name=app01.acme.com)'
            if (-not ($v.Subject -or $v.Issuer -or $v.SubjectAlternativeName)) { Write-Host '  Nothing entered.' -ForegroundColor Yellow; return $null }
        }
        default {
            $prompts = @{
                path                    = 'Full path of the program or folder'
                hash                    = 'Hash value'
                osUser                  = 'OS user (DOMAIN\user or user)'
                machineAddress          = 'IP address, host name or range (for example 10.0.1.0/24)'
                certificateserialnumber = 'Certificate serial number'
            }
            $val = (Read-Host ('{0} (leave blank to go back)' -f $prompts[$t.Type])).Trim()
            if (-not $val) { return $null }
            $v.AuthValue = $val
            if ($t.Type -eq 'path') {
                $v.IsFolder = [string](Read-YesNo 'Is this a folder (any program in it may request)?')
                $v.AllowInternalScripts = [string](Read-YesNo 'Allow internal scripts?')
            }
            if ($t.Type -in @('hash', 'certificateserialnumber')) { $v.Comment = Read-Host 'Comment (optional)' }
        }
    }
    return (New-SpecRow $v)
}

function Get-AppAuthRows {
    param([string]$App)
    return @(@(Get-PCloudApplicationAuthentication -AppId $App) | ForEach-Object { Format-AuthRow $App $_ })
}

function Get-AppPermission {
    # Least privilege for Credential Provider access: the app lists and retrieves; a provider also views members.
    param([switch]$Provider)
    $o = @{ listAccounts = $true; retrieveAccounts = $true }
    if ($Provider) { $o['viewSafeMembers'] = $true }
    return (Get-PCloudSafePermissionSet -Preset None -Override $o)
}

# ------------------------------------------------------------------ actions

function Invoke-AppAction {
    param([object[]]$Rows)
    $specs = @($Rows)
    $results = New-Object System.Collections.Generic.List[object]
    $isWrite = $readActions -notcontains $Action

    if ($Action -in @('DeleteApplication', 'RemoveAuthentication')) {
        $noun = 'application'
        if ($Action -eq 'RemoveAuthentication') { $noun = 'authentication method' }
        $what = '{0} {1}(s)' -f $specs.Count, $noun
        if ($specs.Count -eq 1 -and $Action -eq 'DeleteApplication') { $what = 'application {0} and all its authentication methods' -f (Get-RowValue $specs[0] 'AppID') }
        if (-not (Confirm-Destructive -What $what -Force:$Force)) { Write-Host 'Cancelled.'; return }
    }
    if ($Action -eq 'RevokeSafeAccess' -and -not $Force -and -not $WhatIfPreference) {
        if (-not (Read-YesNo ('Remove safe access for {0} row(s)? Applications lose access to the safe straight away.' -f $specs.Count))) { Write-Host 'Cancelled.'; return }
    }

    $i = 0
    foreach ($row in $specs) {
        $i++
        $app = Get-RowValue $row 'AppID'
        $label = $app
        if ($Action -eq 'GetApplications') { $label = Get-RowValue $row 'Search' }
        Write-Progress -Activity $Action -Status ('{0} of {1}: {2}' -f $i, $specs.Count, $label) -PercentComplete (($i / [Math]::Max($specs.Count, 1)) * 100)
        try {
            switch ($Action) {
                'GetApplications' {
                    $p = @{}
                    if (Get-RowValue $row 'Search') { $p['AppId'] = Get-RowValue $row 'Search' }
                    if (Get-RowValue $row 'Location') { $p['Location'] = Get-RowValue $row 'Location' }
                    foreach ($a in @(Get-PCloudApplication @p)) { $results.Add((Format-AppRow $a)) }
                }
                'GetApplicationDetails' {
                    $a = Find-App $app
                    $id = [string]$a.AppID
                    foreach ($s in @(ConvertTo-PCloudFlatSetting -InputObject (Format-AppRow $a))) { $results.Add([pscustomobject]@{ AppID = $id; Setting = $s.Setting; Value = $s.Value }) }
                    $n = 0
                    foreach ($r in @(Get-AppAuthRows $id)) {
                        $results.Add([pscustomobject]@{ AppID = $id; Setting = ('Authentication[{0}]' -f $n); Value = (Format-AuthLabel $r) + ('  (AuthID {0})' -f $r.AuthID) })
                        $n++
                    }
                    if ($n -eq 0) { $results.Add([pscustomobject]@{ AppID = $id; Setting = 'Authentication'; Value = '(none - the application cannot authenticate yet)' }) }
                }
                'GetAuthentications' {
                    $a = Find-App $app
                    foreach ($r in @(Get-AppAuthRows ([string]$a.AppID))) { $results.Add($r) }
                }
                'AddApplication' {
                    if (-not $app) { throw 'AppID is required.' }
                    $p = @{
                        AppId               = $app
                        AccessPermittedFrom = ConvertTo-Hour (Get-RowValue $row 'AccessPermittedFrom') 'AccessPermittedFrom' 0
                        AccessPermittedTo   = ConvertTo-Hour (Get-RowValue $row 'AccessPermittedTo') 'AccessPermittedTo' 23
                        Confirm             = $false
                    }
                    # Locations are deprecated in Privilege Cloud: new applications go in the root unless a Location is given.
                    $loc = Get-RowValue $row 'Location'
                    if ($loc) { $p['Location'] = $loc }
                    $exp = ConvertTo-AppDate (Get-RowValue $row 'ExpirationDate')
                    if ($exp) { $p['ExpirationDate'] = $exp }
                    $dis = ConvertTo-OptionalBool (Get-RowValue $row 'Disabled') 'Disabled'
                    if ($null -ne $dis) { $p['Disabled'] = $dis }
                    foreach ($n in @('Description', 'BusinessOwnerFName', 'BusinessOwnerLName', 'BusinessOwnerEmail', 'BusinessOwnerPhone')) {
                        $val = Get-RowValue $row $n
                        if ($val) { $p[$n] = $val }
                    }
                    if ($ScriptCmdlet.ShouldProcess(('application {0}' -f $app), $Action)) {
                        $null = New-PCloudApplication @p
                        $results.Add((New-ResultRow -Row $i -Action $Action -Target $app -Status 'Success' -Message 'Added. Add authentication methods and grant safe access next.'))
                    } else { $results.Add((New-ResultRow -Row $i -Action $Action -Target $app -Status 'WhatIf')) }
                }
                'DeleteApplication' {
                    $a = Find-App $app
                    $label = [string]$a.AppID
                    if ($ScriptCmdlet.ShouldProcess(('application {0}' -f $label), $Action)) {
                        Remove-PCloudApplication -AppId $label -Confirm:$false
                        $results.Add((New-ResultRow -Row $i -Action $Action -Target $label -Status 'Success' -Message 'Deleted'))
                    } else { $results.Add((New-ResultRow -Row $i -Action $Action -Target $label -Status 'WhatIf')) }
                }
                'AddAuthentication' {
                    $a = Find-App $app
                    $label = [string]$a.AppID
                    $type = ConvertTo-AuthType (Get-RowValue $row 'AuthType')
                    $p = @{ AppId = $label; AuthType = $type; Confirm = $false }
                    $val = Get-RowValue $row 'AuthValue'
                    if ($val) { $p['AuthValue'] = $val }
                    foreach ($n in @('IsFolder', 'AllowInternalScripts')) {
                        $b = ConvertTo-OptionalBool (Get-RowValue $row $n) $n
                        if ($null -ne $b) { $p[$n] = $b }
                    }
                    if (Get-RowValue $row 'Comment') { $p['Comment'] = Get-RowValue $row 'Comment' }
                    foreach ($n in @('Subject', 'Issuer', 'SubjectAlternativeName')) {
                        $list = @(Split-ListValue (Get-RowValue $row $n))
                        if ($list.Count -gt 0) { $p[$n] = $list }
                    }
                    $desc = $val
                    if ($type -eq 'certificateattr') { $desc = 'certificate attributes' }
                    $dup = @(Get-AppAuthRows $label | Where-Object { $_.AuthType -eq $type -and $val -and [string]$_.AuthValue -eq $val })
                    if ($dup.Count -gt 0) { $results.Add((New-ResultRow -Row $i -Action $Action -Target $label -Id $dup[0].AuthID -Status 'Success' -Message ('{0} {1} is already there' -f $type, $val))); break }
                    if ($ScriptCmdlet.ShouldProcess(('application {0}' -f $label), ('Add {0} {1}' -f $type, $desc))) {
                        Add-PCloudApplicationAuthentication @p
                        $results.Add((New-ResultRow -Row $i -Action $Action -Target $label -Status 'Success' -Message ('Added {0} {1}' -f $type, $desc)))
                    } else { $results.Add((New-ResultRow -Row $i -Action $Action -Target $label -Status 'WhatIf')) }
                }
                'RemoveAuthentication' {
                    $a = Find-App $app
                    $label = [string]$a.AppID
                    $auths = @(Get-AppAuthRows $label)
                    $want = Get-RowValue $row 'AuthID'
                    $hits = @()
                    if ($want) { $hits = @($auths | Where-Object { $_.AuthID -eq $want }) }
                    else {
                        if (-not (Get-RowValue $row 'AuthType') -or -not (Get-RowValue $row 'AuthValue')) { throw 'Give AuthID, or AuthType and AuthValue.' }
                        $type = ConvertTo-AuthType (Get-RowValue $row 'AuthType')
                        $hits = @($auths | Where-Object { $_.AuthType -eq $type -and [string]$_.AuthValue -eq (Get-RowValue $row 'AuthValue') })
                    }
                    if ($hits.Count -eq 0) { throw 'No matching authentication method on this application.' }
                    foreach ($h in $hits) {
                        if ($ScriptCmdlet.ShouldProcess(('application {0}' -f $label), ('Remove {0} {1} (AuthID {2})' -f $h.AuthType, $h.AuthValue, $h.AuthID))) {
                            Remove-PCloudApplicationAuthentication -AppId $label -AuthId $h.AuthID -Confirm:$false
                            $results.Add((New-ResultRow -Row $i -Action $Action -Target $label -Id $h.AuthID -Status 'Success' -Message ('Removed {0} {1}' -f $h.AuthType, $h.AuthValue)))
                        } else { $results.Add((New-ResultRow -Row $i -Action $Action -Target $label -Id $h.AuthID -Status 'WhatIf')) }
                    }
                    if (@($auths).Count -eq $hits.Count) { Write-Warning ('{0} has no authentication methods left, so it cannot retrieve credentials until one is added.' -f $label) }
                }
                { $_ -in @('GrantSafeAccess', 'RevokeSafeAccess') } {
                    $a = Find-App $app
                    $label = [string]$a.AppID
                    $safe = Get-RowValue $row 'SafeName'
                    if (-not $safe) { throw 'SafeName is required.' }
                    $null = Get-PCloudSafe -SafeName $safe
                    $members = @(@{ Name = $label; Provider = $false })
                    foreach ($pv in @(Split-ListValue (Get-RowValue $row 'Providers'))) { $members += @{ Name = $pv; Provider = $true } }
                    foreach ($mb in $members) {
                        $target = '{0} in {1}' -f $mb.Name, $safe
                        try {
                            if (-not $ScriptCmdlet.ShouldProcess($target, $Action)) { $results.Add((New-ResultRow -Row $i -Action $Action -Target $target -Status 'WhatIf')); continue }
                            if ($Action -eq 'GrantSafeAccess') {
                                Add-PCloudSafeMember -SafeName $safe -MemberName $mb.Name -MemberType User -SearchIn 'Vault' -Permission (Get-AppPermission -Provider:$mb.Provider) -Confirm:$false | Out-Null
                                $msg = 'Added with List and Retrieve accounts'
                                if ($mb.Provider) { $msg += ' and View safe members' }
                            } else {
                                Remove-PCloudSafeMember -SafeName $safe -MemberName $mb.Name -Confirm:$false
                                $msg = 'Removed from the safe'
                            }
                            $results.Add((New-ResultRow -Row $i -Action $Action -Target $target -Status 'Success' -Message $msg))
                        } catch {
                            Write-Warning ('Row {0} ({1}): {2}' -f $i, $target, $_.Exception.Message)
                            $results.Add((New-ResultRow -Row $i -Action $Action -Target $target -Status 'Failed' -Message $_.Exception.Message))
                        }
                    }
                }
            }
        } catch {
            $msg = $_.Exception.Message
            Write-Warning ('Row {0} ({1}): {2}' -f $i, $label, $msg)
            if ($isWrite) { $results.Add((New-ResultRow -Row $i -Action $Action -Target $label -Status 'Failed' -Message $msg)) }
        }
    }
    Write-Progress -Activity $Action -Completed

    switch ($Action) {
        'GetApplications' {
            $rows = @($results | Sort-Object AppID -Unique)
            $rows | Format-Table AppID, Description, Location, Disabled, AccessPermittedFrom, AccessPermittedTo, ExpirationDate -AutoSize -Wrap | Out-String | Write-Host
            Write-Host ('{0} application(s).' -f $rows.Count)
            Save-Results -Rows $rows -Path $OutputPath
            return
        }
        'GetApplicationDetails' {
            $results | Format-Table AppID, Setting, Value -AutoSize -Wrap | Out-String | Write-Host
            Write-Host ('{0} setting(s).' -f $results.Count)
        }
        'GetAuthentications' {
            if ($results.Count -eq 0) { Write-Host 'No authentication methods. The application cannot retrieve credentials until one is added.' -ForegroundColor Yellow }
            else { $results | Format-Table AppID, AuthID, AuthType, AuthValue, IsFolder, AllowInternalScripts, Comment, Subject, Issuer -AutoSize -Wrap | Out-String | Write-Host }
            Write-Host ('{0} authentication method(s).' -f $results.Count)
        }
        default { Write-WriteResults -Results $results.ToArray() -Action $Action }
    }
    Save-Results -Rows $results.ToArray() -Path $OutputPath
}

function Get-ParamRow {
    # The single-item spec from the script parameters.
    return (New-SpecRow @{
            AppID = $AppId; Search = $Search; Location = $Location; Description = $Description
            AccessPermittedFrom = $AccessPermittedFrom; AccessPermittedTo = $AccessPermittedTo; ExpirationDate = $ExpirationDate; Disabled = $Disabled
            BusinessOwnerFName = $BusinessOwnerFName; BusinessOwnerLName = $BusinessOwnerLName; BusinessOwnerEmail = $BusinessOwnerEmail; BusinessOwnerPhone = $BusinessOwnerPhone
            AuthType = $AuthType; AuthValue = $AuthValue; AuthID = $AuthId; IsFolder = $IsFolder; AllowInternalScripts = $AllowInternalScripts; Comment = $Comment
            Subject = $Subject; Issuer = $Issuer; SubjectAlternativeName = $SubjectAlternativeName; SafeName = $SafeName; Providers = $Providers
        })
}

function Read-InteractiveRows {
    # Builds the rows for one menu action by prompting. Returns @() to go back to the main menu.
    if ($Action -eq 'GetApplications') {
        $s = (Read-Host 'Part of the application ID to search for (leave blank for all)').Trim()
        return @(New-SpecRow @{ Search = $s })
    }
    if ($Action -eq 'AddApplication') {
        $r = Read-NewApplication
        if ($null -eq $r) { return @() }
        return @($r)
    }
    $a = Read-AppTarget
    if ($null -eq $a) { return @() }
    $id = [string]$a.AppID
    switch ($Action) {
        'AddAuthentication' {
            $rows = @()
            while ($true) {
                $r = Read-NewAuthentication -App $id
                if ($null -ne $r) { $rows += $r }
                if (-not (Read-YesNo ('Add another authentication method to {0}?' -f $id))) { break }
            }
            return $rows
        }
        'RemoveAuthentication' {
            $auths = @(Get-AppAuthRows $id)
            if ($auths.Count -eq 0) { Write-Host ('  {0} has no authentication methods.' -f $id); return @() }
            $picks = Select-FromList -Items $auths -Multiple -Title ('Remove which method(s) from {0}' -f $id) -Label { param($x) Format-AuthLabel $x }
            if ($null -eq $picks) { return @() }
            return @(@($picks) | ForEach-Object { New-SpecRow @{ AppID = $id; AuthID = $_.AuthID } })
        }
        { $_ -in @('GrantSafeAccess', 'RevokeSafeAccess') } {
            $rows = @()
            while ($true) {
                $safe = Read-ExistingSafeName
                if (-not $safe) { break }
                $prov = ''
                if ($Action -eq 'GrantSafeAccess') {
                    $prov = Read-Host 'Provider user(s) to add too, ;-separated (for example Prov_SERVER01; blank for none)'
                } elseif (Read-YesNo 'Also remove Provider users from this safe? Other applications may still need them.') {
                    $prov = Read-Host 'Provider user(s) to remove, ;-separated'
                }
                $rows += New-SpecRow @{ AppID = $id; SafeName = $safe; Providers = $prov }
                if (-not (Read-YesNo 'Another safe?')) { break }
            }
            return $rows
        }
        default { return @(New-SpecRow @{ AppID = $id }) }
    }
}

# ---------- Non-interactive: -Action given. Runs once; errors end the script as usual.
if ($Action) {
    if ($ExportCsv -and -not $OutputPath) { $OutputPath = New-OutputPath -Action $Action }
    Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod
    if ($CsvPath) { $rows = @(Import-WorkCsv -Path $CsvPath) }
    else {
        if ($Action -ne 'GetApplications' -and -not $AppId) { $AppId = Read-Host 'Application ID' }
        $rows = @(Get-ParamRow)
    }
    Invoke-AppAction -Rows $rows
    return
}

# ---------- Menu mode: loops until Q. Any failure returns to the previous prompt or the main menu.
Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod
$original = @{ CsvPath = $CsvPath; OutputPath = $OutputPath; ExportCsv = [bool]$ExportCsv }

while ($true) {
    foreach ($k in $original.Keys) { Set-Variable -Name $k -Value $original[$k] -Scope Script }
    $Action = $null
    $Action = Read-MainMenu -Title 'Applications (Credential Provider) - choose an action:' -Actions $actions -Descriptions $actionHelp
    if (-not $Action) { break }

    try {
        $rows = @()
        if (-not $CsvPath -and $Action -ne 'GetApplications') {
            $f = Read-ExistingFile -Prompt 'CSV file path (leave blank for a single application, B to go back)'
            if ($null -eq $f) { continue }
            if ($f) { $CsvPath = $f }
        }
        if ($CsvPath) { $rows = @(Import-WorkCsv -Path $CsvPath) }
        else { $rows = @(Read-InteractiveRows) }
        if ($rows.Count -eq 0) { continue }

        if (($readActions -contains $Action) -and -not $OutputPath -and -not $ExportCsv) { $OutputPath = Read-OutputChoice -Action $Action }
        if ($ExportCsv -and -not $OutputPath) { $OutputPath = New-OutputPath -Action $Action }

        Invoke-AppAction -Rows $rows
    } catch {
        Write-Host ''
        Write-Host ('{0} failed: {1}' -f $Action, $_.Exception.Message) -ForegroundColor Red
        Write-Host 'Returning to the main menu.' -ForegroundColor Yellow
    }
}
