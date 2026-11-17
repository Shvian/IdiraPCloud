#Requires -Version 5.1
# Identity directory lookups, used to tell users, groups and roles apart.
# The safe members API can report an Identity role as memberType 'Group'; these helpers check the
# name against Identity so the real type can be shown and used when adding members.
# Calls go to the session's Identity tenant over HTTPS with the session token (Identity rights to read
# roles/users are needed; without them the API's value is kept).

$script:PCloudDirectoryCache = $null

function Reset-PCloudDirectoryCache {
    $script:PCloudDirectoryCache = $null
}

function Invoke-PCloudIdentityApi {
    # POST to an Identity endpoint with the session token.
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][hashtable]$Body)
    Assert-PCloudSession
    Update-PCloudTokenIfNeeded
    $s = $script:PCloudSession
    $base = $s.IdentityBaseUrl
    if (-not $base) { $base = $s.IdentityUrl }
    if (-not $base) { throw 'The session has no Identity URL.' }
    $uri = $base.TrimEnd('/') + $Path
    Assert-PCloudHttpsUrl -Url $uri -Name 'Identity URL'

    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Body -Depth 6 -Compress))
    $params = Get-PCloudWebParams
    $params['Method'] = 'Post'
    $params['Uri'] = $uri
    $params['ContentType'] = 'application/json; charset=utf-8'
    $params['Body'] = $bodyBytes
    $params['Headers'] = @{
        'Authorization'        = 'Bearer ' + (ConvertFrom-PCloudSecureString $s.AccessToken)
        'X-IDAP-NATIVE-CLIENT' = 'true'
        'Accept'               = 'application/json'
    }
    Write-Verbose "POST $uri"
    try {
        $r = Invoke-PCloudHttp -Params $params -Service 'Idira Identity'
    } catch {
        $detail = Get-PCloudErrorDetail -ErrorRecord $_
        $msg = 'Identity call failed: POST {0}' -f $uri
        if ($detail.StatusCode) { $msg += " | HTTP $($detail.StatusCode)" }
        if ($detail.ErrorMessage) { $msg += " | $($detail.ErrorMessage)" }
        throw $msg
    } finally {
        Clear-PCloudBytes $bodyBytes
        $params = $null
    }
    if ($null -ne $r -and ($r.PSObject.Properties.Name -contains 'success') -and -not $r.success) {
        $m = $r.Message
        if (-not $m) { $m = 'unsuccessful' }
        throw "Identity call failed: $m"
    }
    return $r.Result
}

function Invoke-PCloudIdentityQuery {
    # Identity reporting query (POST /Redrock/query). Returns the Row objects.
    param([Parameter(Mandatory = $true)][string]$Script)
    $result = Invoke-PCloudIdentityApi -Path '/Redrock/query' -Body @{
        Script = $Script
        Args   = @{ PageNumber = 1; PageSize = 100000; Limit = 100000; SortBy = ''; Caching = -1 }
    }
    if ($null -eq $result) { return @() }
    return @($result.Results | ForEach-Object { $_.Row })
}

function Get-PCloudDirectoryCache {
    # Loads Identity role names once per session. Returns $null if Identity cannot be read.
    if ($null -ne $script:PCloudDirectoryCache) {
        if ($script:PCloudDirectoryCache.Available) { return $script:PCloudDirectoryCache }
        return $null
    }
    $cache = @{ Available = $false; Roles = @{}; Users = @{}; Error = $null }
    try {
        foreach ($row in (Invoke-PCloudIdentityQuery -Script 'Select ID, Name from Role')) {
            if ($row.Name) { $cache.Roles[([string]$row.Name).ToLowerInvariant()] = [string]$row.Name }
        }
        $cache.Available = $true
    } catch {
        $cache.Error = $_.Exception.Message
        Write-Verbose ('Identity roles could not be read; member types are shown as the API reports them. {0}' -f $cache.Error)
    }
    $script:PCloudDirectoryCache = $cache
    if ($cache.Available) { return $cache }
    return $null
}

function Test-PCloudIdentityUser {
    # True/False if Identity can say whether the name is a user; $null if it cannot be checked.
    param([Parameter(Mandatory = $true)][string]$Name)
    $cache = Get-PCloudDirectoryCache
    if ($null -eq $cache) { return $null }
    $key = $Name.ToLowerInvariant()
    if ($cache.Users.ContainsKey($key)) { return $cache.Users[$key] }
    $safeName = $Name.Replace("'", "''")
    try {
        $rows = @(Invoke-PCloudIdentityQuery -Script ("Select ID, Username from User where Username = '{0}'" -f $safeName))
        $found = $rows.Count -gt 0
    } catch {
        return $null
    }
    $cache.Users[$key] = $found
    return $found
}

function Resolve-PCloudSafeMemberType {
    <#
    .SYNOPSIS
        Works out whether a safe member name is a User, Group or Role.
    .DESCRIPTION
        Checks the name against Idira Identity roles (and users, when the type is unknown).
          - A name that matches an Identity role resolves to Role, even if the API reported Group.
          - With -ReportedType User/Group (from the API) the reported type is kept otherwise.
          - Without -ReportedType: role -> Role; Identity user, or a name with '@' -> User; otherwise Group.
        Returns MemberType, ReportedType and Source ('Identity', 'API' or 'Guess').
        If Identity cannot be read (missing rights), the reported type is kept and Source is 'API'.
    .EXAMPLE
        Resolve-PCloudSafeMemberType -MemberName 'Privilege Cloud Users'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$MemberName,
        [Parameter(ValueFromPipelineByPropertyName = $true)][string]$ReportedType
    )
    process {
        $cache = Get-PCloudDirectoryCache
        $type = $ReportedType
        $source = 'API'
        if ($null -ne $cache) {
            if ($cache.Roles.ContainsKey($MemberName.ToLowerInvariant())) {
                $type = 'Role'
                $source = 'Identity'
            } elseif (-not $ReportedType) {
                $isUser = Test-PCloudIdentityUser -Name $MemberName
                if ($isUser -eq $true) { $type = 'User'; $source = 'Identity' }
            }
        }
        if (-not $type) {
            $source = 'Guess'
            if ($MemberName -match '@') { $type = 'User' } else { $type = 'Group' }
        }
        # Normalize casing from the API (user/group/role).
        switch -Regex ($type) {
            '^(?i)user$' { $type = 'User' }
            '^(?i)group$' { $type = 'Group' }
            '^(?i)role$' { $type = 'Role' }
        }
        [pscustomobject]@{ MemberName = $MemberName; MemberType = $type; ReportedType = $ReportedType; Source = $source }
    }
}
