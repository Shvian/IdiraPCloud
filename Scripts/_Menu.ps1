#Requires -Version 5.1
# Shared menu and CSV helpers for the Manage-*.ps1 scripts. Dot-source after _Common.ps1.
# Menus never end the script on a failure: helpers return $null for "go back" and re-prompt on bad input.

function ConvertTo-OptionalBool {
    param($Value, [string]$Name)
    if ($null -eq $Value) { return $null }
    $v = ([string]$Value).Trim()
    if ($v -eq '') { return $null }
    if ($v -match '^(?i)(true|yes|y|1|on)$') { return $true }
    if ($v -match '^(?i)(false|no|n|0|off)$') { return $false }
    throw "Value '$v' for $Name is not true/false."
}

function Get-RowValue {
    param($Row, [string]$Name)
    if ($null -eq $Row) { return '' }
    $prop = $Row.PSObject.Properties | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if ($null -eq $prop -or $null -eq $prop.Value) { return '' }
    return ([string]$prop.Value).Trim()
}

function Split-ListValue {
    # "a; b, c" -> @('a','b','c')
    param([string]$Value)
    if (-not $Value) { return @() }
    return @($Value -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Get-NestedValue {
    # Safe property path lookup: Get-NestedValue $obj 'secretManagement.status'
    param($Object, [string]$Path)
    $cur = $Object
    foreach ($part in ($Path -split '\.')) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) { $cur = $cur[$part]; continue }
        $p = $cur.PSObject.Properties | Where-Object { $_.Name -eq $part } | Select-Object -First 1
        if ($null -eq $p) { return $null }
        $cur = $p.Value
    }
    return $cur
}

function New-OutputPath {
    param([string]$Action, [string]$Extension = 'csv')
    return (New-PCloudOutputFile -Name $Action -Extension $Extension)
}

function Read-OutputChoice {
    # Returns a file path, or '' to skip.
    param([string]$Action)
    $ans = Read-Host ('Save results to CSV? Y for an automatic name in {0}, a file name or path, or leave blank to skip' -f $script:PCloudOutputFolder)
    if (-not $ans) { return '' }
    if ($ans -match '^(?i)(y|yes)$') { return (New-OutputPath -Action $Action) }
    return (Resolve-PCloudOutputPath $ans)
}

function ConvertTo-UniformRows {
    # Export-Csv takes its columns from the first row; give every row the same columns.
    param([object[]]$Rows)
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($r in $Rows) { foreach ($p in $r.PSObject.Properties) { if (-not $names.Contains($p.Name)) { $names.Add($p.Name) } } }
    foreach ($r in $Rows) {
        $o = [ordered]@{}
        foreach ($n in $names) { $o[$n] = $r.$n }
        [pscustomobject]$o
    }
}

function Save-Results {
    param([object[]]$Rows, [string]$Path)
    if (-not $Path) { return }
    $rowsArr = @($Rows)
    $full = Resolve-PCloudOutputPath $Path
    if ($rowsArr.Count -eq 0) { Write-Host 'Nothing to save.' -ForegroundColor Yellow; return }
    @(ConvertTo-UniformRows -Rows $rowsArr) | Export-Csv -LiteralPath $full -NoTypeInformation -Encoding UTF8
    Write-Host ('{0} row(s) written to {1}' -f $rowsArr.Count, $full)
    Write-Host 'The file holds no secrets but does describe privileged access: keep it somewhere only you can read.' -ForegroundColor DarkGray
}

function Read-ExistingFile {
    # '' = blank (single item), $null = B (go back), otherwise an existing file path.
    param([string]$Prompt)
    while ($true) {
        $f = Read-Host $Prompt
        if (-not $f) { return '' }
        if ($f -match '^(?i)b$') { return $null }
        $f = $f.Trim('"')
        if (Test-Path -LiteralPath $f -PathType Leaf) { return $f }
        Write-Host ('  File not found: {0}' -f $f) -ForegroundColor Red
    }
}

function Import-WorkCsv {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "CSV not found: $Path" }
    $rows = @(Import-Csv -LiteralPath $Path)
    if ($rows.Count -eq 0) { throw "CSV has no rows: $Path" }
    # Excel in some regions saves CSVs with semicolons: one column whose name holds ';' means that.
    $cols = @($rows[0].PSObject.Properties | ForEach-Object { $_.Name })
    if ($cols.Count -eq 1 -and $cols[0] -like '*;*') { $rows = @(Import-Csv -LiteralPath $Path -Delimiter ';') }
    return $rows
}

function Read-YesNo {
    param([string]$Prompt, [bool]$Default = $false)
    $hint = '(y/N)'
    if ($Default) { $hint = '(Y/n)' }
    while ($true) {
        $a = (Read-Host ('{0} {1}' -f $Prompt, $hint)).Trim()
        if (-not $a) { return $Default }
        if ($a -match '^(?i)(y|yes)$') { return $true }
        if ($a -match '^(?i)(n|no)$') { return $false }
        Write-Host '  Enter Y or N.' -ForegroundColor Red
    }
}

function Read-MainMenu {
    # Returns the chosen action name, or $null for Q.
    param([string]$Title, [string[]]$Actions, [hashtable]$Descriptions)
    while ($true) {
        Write-Host ''
        Write-Host $Title
        for ($i = 0; $i -lt $Actions.Count; $i++) {
            $d = ''
            if ($Descriptions -and $Descriptions.ContainsKey($Actions[$i])) { $d = ' - ' + $Descriptions[$Actions[$i]] }
            Write-Host ('  {0}) {1}{2}' -f ($i + 1), $Actions[$i], $d)
        }
        Write-Host '  Q) Quit'
        $c = (Read-Host ('Enter 1-{0} or Q' -f $Actions.Count)).Trim()
        if ($c -match '^(?i)q$') { return $null }
        $n = 0
        if ([int]::TryParse($c, [ref]$n) -and $n -ge 1 -and $n -le $Actions.Count) { return $Actions[$n - 1] }
        Write-Host 'Invalid choice.' -ForegroundColor Yellow
    }
}

function Select-FromList {
    <#
        Numbered pick list. Long lists ask for filter text first.
        Returns the chosen item (or items with -Multiple; wrap the result in @()), or $null when the user goes back.
    #>
    param(
        [object[]]$Items,
        [Parameter(Mandatory = $true)][scriptblock]$Label,
        [string]$Title = 'Choose',
        [switch]$Multiple,
        [int]$FilterAbove = 30
    )
    $all = @($Items)
    if ($all.Count -eq 0) { Write-Host '  Nothing to choose from.' -ForegroundColor Yellow; return $null }
    $shown = $all
    $askFilter = $all.Count -gt $FilterAbove
    while ($true) {
        if ($askFilter) {
            $f = Read-Host ('  {0} items. Type text to filter, Enter to show all, B to go back' -f $all.Count)
            if ($f -match '^(?i)b$') { return $null }
            if ($f) {
                $shown = @($all | Where-Object { (& $Label $_) -like ('*{0}*' -f $f) })
                if ($shown.Count -eq 0) { Write-Host '  No matches.' -ForegroundColor Yellow; continue }
            } else { $shown = $all }
            $askFilter = $false
        }
        Write-Host ('  {0}:' -f $Title)
        for ($i = 0; $i -lt $shown.Count; $i++) { Write-Host ('    {0}) {1}' -f ($i + 1), (& $Label $shown[$i])) }
        $prompt = '  Number'
        if ($Multiple) { $prompt = '  Number(s), comma separated' }
        $raw = (Read-Host ('{0} (F to filter, B to go back)' -f $prompt)).Trim()
        if ($raw -match '^(?i)b$' -or -not $raw) { return $null }
        if ($raw -match '^(?i)f$') { $askFilter = $true; continue }
        $picked = @()
        $bad = $false
        foreach ($part in ($raw -split '[,; ]+' | Where-Object { $_ })) {
            $n = 0
            if ([int]::TryParse($part, [ref]$n) -and $n -ge 1 -and $n -le $shown.Count) { $picked += , $shown[$n - 1] }
            else { $bad = $true }
        }
        if ($bad -or $picked.Count -eq 0) { Write-Host ('  Enter a number from 1 to {0}.' -f $shown.Count) -ForegroundColor Red; continue }
        if ($Multiple) { return $picked }
        return $picked[0]
    }
}

function Select-PartialMatch {
    # One item from partial matches: none -> $null, one -> confirm, several -> pick list.
    param([object[]]$Items, [string]$Text, [string]$Noun, [scriptblock]$Label)
    $hits = @($Items)
    if ($hits.Count -eq 0) { Write-Host ("  No {0} matches '{1}'." -f $Noun, $Text) -ForegroundColor Red; return $null }
    if ($hits.Count -eq 1) {
        $only = $hits[0]
        if (Read-YesNo ("  Found {0} '{1}'. Use it?" -f $Noun, (& $Label $only)) $true) { return $only }
        return $null
    }
    return (Select-FromList -Items $hits -Title ("{0} {1}s match '{2}'" -f $hits.Count, $Noun, $Text) -Label $Label)
}

function Resolve-SafeChoice {
    # Exact safe name, or a partial match picked from a list. Returns the safe name or $null.
    param([string]$Text)
    try { $null = Get-PCloudSafe -SafeName $Text; return $Text } catch { }
    $pattern = '*{0}*' -f [System.Management.Automation.WildcardPattern]::Escape($Text)
    $hits = @()
    try { $hits = @(Get-PCloudSafe -Search $Text | Where-Object { $_.safeName -like $pattern }) } catch { }
    if ($hits.Count -eq 0) {
        # The API search matches whole words; fall back to a contains-match over every safe name.
        try { $hits = @(Get-PCloudSafe | Where-Object { $_.safeName -like $pattern }) } catch {
            Write-Host ('  {0}' -f $_.Exception.Message) -ForegroundColor Red
        }
    }
    $hits = @($hits | Sort-Object safeName -Unique)
    $pick = Select-PartialMatch -Items $hits -Text $Text -Noun 'safe' -Label { param($x) [string]$x.safeName }
    if ($null -eq $pick) { return $null }
    return [string]$pick.safeName
}

function Read-ExistingSafeName {
    # Prompts until a safe is chosen: exact name, or part of a name to pick from the matches.
    # Returns $null if left blank (go back).
    param([string]$Prompt = 'Safe name or part of it (leave blank to go back)')
    while ($true) {
        $n = (Read-Host $Prompt).Trim()
        if (-not $n) { return $null }
        $safe = Resolve-SafeChoice -Text $n
        if ($safe) { return $safe }
        Write-Host '  Try again.'
    }
}

function New-PendingChange {
    # One pending change in an update menu. Hint is a regex that matches API errors about this change.
    param([string]$Label, $Value, [string]$Display, [string]$Hint)
    if (-not $Display) { $Display = [string]$Value }
    [pscustomobject]@{ Label = $Label; Value = $Value; Display = $Display; Hint = $Hint }
}

function Write-PendingChanges {
    param([System.Collections.IDictionary]$Changes)
    foreach ($k in $Changes.Keys) { Write-Host ('  {0} = {1}' -f $Changes[$k].Label, $Changes[$k].Display) }
}

function Select-FailedChange {
    # Works out which pending change an error refers to; asks when it cannot tell. Returns the key or $null.
    param([System.Collections.IDictionary]$Changes, [string]$Message)
    $keys = @($Changes.Keys)
    if ($keys.Count -eq 0) { return $null }
    if ($keys.Count -eq 1) { return $keys[0] }
    $hits = @($keys | Where-Object { $Changes[$_].Hint -and ($Message -match $Changes[$_].Hint) })
    if ($hits.Count -eq 1) { return $hits[0] }
    Write-Host 'Could not tell which change caused the failure. Which one should be removed?'
    for ($i = 0; $i -lt $keys.Count; $i++) {
        Write-Host ('  {0}) {1} = {2}' -f ($i + 1), $Changes[$keys[$i]].Label, $Changes[$keys[$i]].Display)
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

function New-ResultRow {
    param([int]$Row, [string]$Action, [string]$Target, [string]$Status, [string]$Message, [string]$Id)
    [pscustomobject]@{ Row = $Row; Action = $Action; Target = $Target; Id = $Id; Status = $Status; Message = $Message }
}

function Write-WriteResults {
    param([object[]]$Results, [string]$Action)
    $r = @($Results)
    $r | Sort-Object Row | Format-Table Row, Target, Id, Status, Message -AutoSize -Wrap | Out-String | Write-Host
    $ok = @($r | Where-Object { $_.Status -eq 'Success' }).Count
    $bad = @($r | Where-Object { $_.Status -eq 'Failed' }).Count
    Write-Host ('{0}: {1} succeeded, {2} failed.' -f $Action, $ok, $bad)
}

function Confirm-Destructive {
    # Typed confirmation for deletes. -WhatIf skips the prompt (nothing is sent anyway).
    param([string]$What, [switch]$Force)
    if ($WhatIfPreference -or $Force) { return $true }
    Write-Warning ('This permanently deletes {0}.' -f $What)
    $t = Read-Host 'Type DELETE to confirm (anything else cancels)'
    return ($t -ceq 'DELETE')
}

# ------------------------------------------------------------------ target platforms (cached per run)

function Get-AllTargetPlatforms {
    param([switch]$Refresh)
    if ($Refresh -or $null -eq $script:allPlatformCache) { $script:allPlatformCache = @(Get-PCloudTargetPlatform | Sort-Object PlatformID) }
    return $script:allPlatformCache
}

function Find-Platform {
    # By PlatformID, name or numeric ID, from the cached list.
    param([string]$Value)
    if (-not $Value) { throw 'PlatformId is required.' }
    $all = @(Get-AllTargetPlatforms)
    foreach ($prop in @('PlatformID', 'Name', 'ID')) {
        $hit = @($all | Where-Object { [string]$_.$prop -eq $Value })
        if ($hit.Count -gt 0) { return $hit[0] }
    }
    throw ("Target platform '{0}' was not found." -f $Value)
}

function Format-PlatformLabel {
    param($P)
    $state = 'inactive'
    if ($P.Active) { $state = 'active' }
    return ('{0}  -  {1} ({2}, {3})' -f $P.PlatformID, $P.Name, $P.SystemType, $state)
}

function Read-PlatformTarget {
    # Interactive: type a platform or pick it from the list. Returns the platform or $null (back).
    while ($true) {
        $v = (Read-Host 'Platform ID or name, or part of it (press Enter to pick from a list, B to go back)').Trim()
        if ($v -match '^(?i)b$') { return $null }
        if ($v) {
            try { return (Find-Platform -Value $v) } catch { }
            $pattern = '*{0}*' -f [System.Management.Automation.WildcardPattern]::Escape($v)
            $hits = @(Get-AllTargetPlatforms | Where-Object { [string]$_.PlatformID -like $pattern -or [string]$_.Name -like $pattern -or [string]$_.SystemType -like $pattern })
            $pick = Select-PartialMatch -Items $hits -Text $v -Noun 'platform' -Label { param($x) Format-PlatformLabel $x }
            if ($null -ne $pick) { return $pick }
            Write-Host '  Try again.'
            continue
        }
        $pick = Select-FromList -Items @(Get-AllTargetPlatforms) -Title 'Target platforms' -Label { param($x) Format-PlatformLabel $x }
        if ($null -ne $pick) { return $pick }
    }
}

# ------------------------------------------------------------------ accounts (shared by Manage-Accounts and Manage-AccountDependents)

function Find-AccountsByKeyword {
    <#
        Accounts matching every keyword (any number, partial words allowed) in any of: ID, name, user name,
        address, safe, platform. Optional -Safe limits it to one safe. The API's "contains" search finds the
        candidates; every keyword is then checked here, so the results only include true matches.
    #>
    param([string]$Text, [string]$Safe)
    $words = @(([string]$Text) -split '\s+' | Where-Object { $_ })
    $p = @{ SearchType = 'contains' }
    if ($Safe) { $p['SafeName'] = $Safe }
    if ($words.Count -eq 0) {
        if (-not $Safe) { throw 'Give at least one keyword or a safe.' }
        return @(Get-PCloudAccount @p)
    }
    $p['Search'] = $words -join ' '
    $found = @(Get-PCloudAccount @p)
    if ($found.Count -eq 0 -and $words.Count -gt 1) {
        # Some tenants AND the words together on one field; widen with the most specific word and filter here.
        $p['Search'] = @($words | Sort-Object Length -Descending)[0]
        $found = @(Get-PCloudAccount @p)
    }
    $patterns = @($words | ForEach-Object { '*{0}*' -f [System.Management.Automation.WildcardPattern]::Escape($_) })
    return @($found | Where-Object {
            $a = $_
            $hay = @($a.id, $a.name, $a.userName, $a.address, $a.safeName, $a.platformId) | ForEach-Object { [string]$_ }
            $ok = $true
            foreach ($pat in $patterns) { if (-not (@($hay | Where-Object { $_ -like $pat }).Count -gt 0)) { $ok = $false; break } }
            $ok
        })
}

function Read-AccountTarget {
    # Interactive: find one account by ID or by keywords (any safe, or S to pick a safe first).
    # Returns the account or $null (back). -AllowObjectName adds N: type the safe and object name directly
    # (returns @{ id=$null; safeName; name }).
    param([string]$What = 'Account', [switch]$AllowObjectName)
    while ($true) {
        $extra = ''
        if ($AllowObjectName) { $extra = ', N to type the safe and object name' }
        Write-Host ('{0}: enter its ID (e.g. 12_34), or keywords to search - user, address, name, safe or platform, partial words are fine.' -f $What)
        $in = (Read-Host ('ID or keywords (S to limit the search to one safe{0}, B to go back)' -f $extra)).Trim()
        if ($in -match '^(?i)b$') { return $null }
        if (-not $in) { continue }
        if ($AllowObjectName -and $in -match '^(?i)n$') {
            $safe = Read-ExistingSafeName
            if (-not $safe) { continue }
            $obj = (Read-Host 'Object name, e.g. Operating System-WinDomain-acme.local-svc_recon (leave blank to go back)').Trim()
            if (-not $obj) { continue }
            return [pscustomobject]@{ id = $null; safeName = $safe; name = $obj; userName = ''; address = '' }
        }
        if ($in -match '^\d+_\d+$') {
            try { return (Get-PCloudAccount -Id $in) } catch {
                Write-Host ('  {0}' -f $_.Exception.Message) -ForegroundColor Red
                Write-Host '  Try again.'
                continue
            }
        }
        $safe = ''
        $text = $in
        if ($in -match '^(?i)s$') {
            $safe = Read-ExistingSafeName
            if (-not $safe) { continue }
            $text = Read-Host 'Keywords to search in that safe (leave blank to list the whole safe)'
        }
        $found = @()
        try { $found = @(Find-AccountsByKeyword -Text $text -Safe $safe) } catch { Write-Host ('  {0}' -f $_.Exception.Message) -ForegroundColor Red; continue }
        $pick = Select-PartialMatch -Items $found -Text $(if ($text) { $text } else { $safe }) -Noun 'account' -Label { param($a) '{0}  {1}@{2}  (safe {3}, {4})' -f $a.id, $a.userName, $a.address, $a.safeName, $a.platformId }
        if ($null -eq $pick) { Write-Host '  Try again.'; continue }
        return $pick
    }
}
