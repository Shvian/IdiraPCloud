#Requires -Version 5.1

function New-PCloudSession {
    <#
    .SYNOPSIS
        Signs in to Idira Identity and stores a Privilege Cloud session for the other cmdlets.
    .DESCRIPTION
        Gets a bearer token from Idira Identity (Identity Security Platform Shared Services) and
        stores it in module scope with the Privilege Cloud API base URL.

        -AuthMethod chooses how to sign in:
          ServiceUser  (default) OAuth2 client_credentials for an Identity service user flagged
                       "Is Service User" + "Is OAuth confidential client".
                       POST https://<tenant>.id.cyberark.cloud/oauth2/platformtoken
                       Renewed automatically before expiry.
          OAuthApp     OAuth2 client_credentials against a custom Identity OAuth2 server web app.
                       POST .../oauth2/token/<AppId>. Renewed automatically.
          Interactive  Any Identity sign-in method your policy allows: password, mobile app push,
                       OTP/authenticator code, SMS, email, phone call, security question, RADIUS.
                       POST .../Security/StartAuthentication then .../Security/AdvanceAuthentication.
                       Prompts in the console for each MFA step. Renewed silently with the Identity
                       refresh token; you are asked to sign in again only if that is refused.
          AccessToken  Use a token you already have (never renewed). Pass it as a SecureString,
                       e.g. -AccessToken (Read-Host 'Token' -AsSecureString).

        Token renewal: before every API call the token's expiry is checked (expires_in, or the JWT
        'exp' claim), and it is renewed -RefreshThresholdSec seconds early. ServiceUser and OAuthApp
        request a new token with the stored secret. Interactive uses the Identity refresh token and
        only asks you to sign in again if Identity refuses it. A 401 also triggers one renewal and retry.

        If -AuthMethod is not given: -AccessToken implies AccessToken, -AppId implies OAuthApp,
        otherwise ServiceUser.
    .PARAMETER Subdomain
        Privilege Cloud subdomain, e.g. 'acme' for acme.cyberark.cloud (a full URL is also accepted).
        Builds https://<Subdomain>.privilegecloud.cyberark.cloud/PasswordVault and is used to find the
        Identity tenant. You are prompted for it if neither -Subdomain nor -PCloudUrl is given.
    .PARAMETER IdentityUrl
        Optional. Identity tenant URL, e.g. https://abc1234.id.cyberark.cloud. Normally discovered
        automatically by following the redirect from https://<subdomain>.cyberark.cloud.
    .PARAMETER PCloudUrl
        Full Privilege Cloud base URL ending in /PasswordVault. Use instead of -Subdomain if your URL differs.
    .PARAMETER Credential
        ServiceUser/OAuthApp: the client ID and secret (service user name with suffix and its password).
        Interactive: optional. The user name is used, and the password answers the password step
        so you are only prompted for MFA.
    .PARAMETER UserName
        Interactive only: the Identity user name, if you do not pass -Credential.
    .PARAMETER PreferredMechanism
        Interactive only: MFA methods to pick automatically when several are offered, in order,
        e.g. OTP (mobile app push), OATH (authenticator code), SMS, EMAIL, PF (phone call).
    .PARAMETER RefreshThresholdSec
        Renew the token when it is this many seconds from expiring (default 120). Renewal is checked
        before every API call, so long-running scripts keep a valid token.
    .PARAMETER MfaTimeoutSec
        Interactive only: how long to wait for push/email/SMS approval. Default 180 seconds.
    .EXAMPLE
        # Service user (OAuth2 client credentials)
        $cred = Get-Credential 'svc-pcloud-api@acme.com.1234'
        New-PCloudSession -Subdomain acme -Credential $cred
    .EXAMPLE
        # Your own user with MFA, prompted for each step
        New-PCloudSession -AuthMethod Interactive -Subdomain acme -UserName jdoe@acme.com
    .EXAMPLE
        # Password from a credential, then auto-pick a mobile push
        New-PCloudSession -AuthMethod Interactive -Subdomain acme -Credential (Get-Credential jdoe@acme.com) -PreferredMechanism OTP
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('ServiceUser', 'OAuthApp', 'Interactive', 'AccessToken')]
        [string]$AuthMethod,

        [string]$IdentityUrl,

        [string]$Subdomain,

        [string]$PCloudUrl,

        [System.Management.Automation.PSCredential]$Credential,

        [string]$UserName,

        [string]$AppId,

        [string]$Scope,

        [System.Security.SecureString]$AccessToken,

        [string[]]$PreferredMechanism,

        [int]$MfaTimeoutSec = 180,

        [ValidateRange(10, 3600)]
        [int]$RefreshThresholdSec = 120,

        [int]$TimeoutSec = 120,

        [string]$Proxy,

        [switch]$ProxyUseDefaultCredentials,

        [switch]$PassThru
    )

    if (-not $AuthMethod) {
        if ($AccessToken) { $AuthMethod = 'AccessToken' }
        elseif ($AppId) { $AuthMethod = 'OAuthApp' }
        else { $AuthMethod = 'ServiceUser' }
    }

    if (-not $PCloudUrl -and -not $Subdomain) {
        $Subdomain = Read-Host 'Privilege Cloud subdomain (the "acme" in acme.cyberark.cloud)'
        if (-not $Subdomain) { throw 'A subdomain (or -PCloudUrl) is required.' }
    }
    if ($Subdomain) { $Subdomain = ConvertTo-PCloudSubdomain $Subdomain }
    if (-not $PCloudUrl) {
        $PCloudUrl = 'https://{0}.privilegecloud.cyberark.cloud/PasswordVault' -f $Subdomain
    } elseif (-not $Subdomain) {
        $Subdomain = ConvertTo-PCloudSubdomain $PCloudUrl
    }
    $PCloudUrl = $PCloudUrl.TrimEnd('/')
    if ($PCloudUrl -match '(?i)/API$') { $PCloudUrl = $PCloudUrl.Substring(0, $PCloudUrl.Length - 4) }
    if ($PCloudUrl -notmatch '(?i)/PasswordVault$') { $PCloudUrl = $PCloudUrl + '/PasswordVault' }

    if ($PCloudUrl -notmatch '^(?i)[a-z][a-z0-9+.-]*://') { $PCloudUrl = 'https://' + $PCloudUrl }
    Assert-PCloudHttpsUrl -Url $PCloudUrl -Name '-PCloudUrl'

    if ($IdentityUrl) {
        $IdentityUrl = $IdentityUrl.TrimEnd('/')
        if ($IdentityUrl -notmatch '^(?i)[a-z][a-z0-9+.-]*://') { $IdentityUrl = 'https://' + $IdentityUrl }
        Assert-PCloudHttpsUrl -Url $IdentityUrl -Name '-IdentityUrl'
    } elseif ($AuthMethod -ne 'AccessToken') {
        # Users normally know only the subdomain; https://<subdomain>.cyberark.cloud redirects to the Identity tenant.
        $IdentityUrl = Resolve-PCloudIdentityUrl -Subdomain $Subdomain -Proxy $Proxy -ProxyUseDefaultCredentials ([bool]$ProxyUseDefaultCredentials)
        Write-Verbose "Identity tenant: $IdentityUrl"
    }

    switch ($AuthMethod) {
        'AccessToken' {
            if (-not $AccessToken) { throw '-AuthMethod AccessToken needs -AccessToken.' }
        }
        'Interactive' {
        }
        'OAuthApp' {
            if (-not $AppId) { throw '-AuthMethod OAuthApp needs -AppId.' }
            if (-not $Credential) { $Credential = Get-Credential -Message 'OAuth client ID and secret' }
        }
        default {
            if (-not $Credential) { $Credential = Get-Credential -Message 'Identity service user (name with suffix) and password' }
        }
    }

    # Dispose any previous session's secrets before replacing it.
    if ($null -ne $script:PCloudSession) { Remove-PCloudSession }

    # Keep a private copy of the credential so signing out can dispose it without touching the caller's object.
    $sessionCredential = $null
    if ($Credential) {
        $sessionCredential = New-Object System.Management.Automation.PSCredential($Credential.UserName, $Credential.Password.Copy())
    }
    $sessionToken = $null
    if ($AccessToken) {
        $sessionToken = $AccessToken.Copy()
        $sessionToken.MakeReadOnly()
    }

    $script:PCloudSession = [pscustomobject]@{
        PCloudUrl                  = $PCloudUrl
        IdentityUrl                = $IdentityUrl
        AuthMethod                 = $AuthMethod
        AppId                      = $AppId
        Scope                      = $Scope
        Credential                 = $sessionCredential
        UserName                   = $UserName
        PreferredMechanism         = $PreferredMechanism
        MfaTimeoutSec              = $MfaTimeoutSec
        RefreshThresholdSec        = $RefreshThresholdSec
        RefreshToken               = $null
        IdentityWebSession         = $null
        IdentityBaseUrl            = $null
        LastRenewed                = $null
        CanRefresh                 = ($AuthMethod -ne 'AccessToken')
        AccessToken                = $sessionToken
        TokenType                  = 'Bearer'
        ExpiresAt                  = $null
        TimeoutSec                 = $TimeoutSec
        Proxy                      = $Proxy
        ProxyUseDefaultCredentials = [bool]$ProxyUseDefaultCredentials
        Created                    = Get-Date
    }

    if ($AuthMethod -eq 'AccessToken') {
        $plainToken = ConvertFrom-PCloudSecureString $AccessToken
        $script:PCloudSession.ExpiresAt = Get-PCloudJwtExpiry $plainToken
        $plainToken = $null
        if ($null -ne $script:PCloudSession.ExpiresAt -and $script:PCloudSession.ExpiresAt -lt (Get-Date)) {
            Write-Warning ("The supplied token expired at {0}." -f $script:PCloudSession.ExpiresAt)
        }
    }

    if ($AuthMethod -ne 'AccessToken') {
        try {
            Request-PCloudToken
        } catch {
            Remove-PCloudSession
            throw
        }
    }

    # Idle sign-out (Idle.ps1): the countdown starts now.
    $script:PCloudIdle.SignedOut = $false
    Register-PCloudActivity
    Start-PCloudIdleTimer
    if ($PassThru) { return (Get-PCloudSession) }
    Write-Verbose "Connected to $PCloudUrl using $AuthMethod"
}

function Get-PCloudSession {
    <#
    .SYNOPSIS
        Shows the current session (without the token or secret).
    #>
    [CmdletBinding()]
    param()
    if ($null -eq $script:PCloudSession) { return $null }
    $s = $script:PCloudSession
    $user = $null
    if ($s.Credential) { $user = $s.Credential.UserName } elseif ($s.UserName) { $user = $s.UserName }
    return [pscustomobject]@{
        PCloudUrl   = $s.PCloudUrl
        IdentityUrl = $s.IdentityUrl
        AuthMethod  = $s.AuthMethod
        User        = $user
        ExpiresAt   = $s.ExpiresAt
        LastRenewed = $s.LastRenewed
        RefreshTokenAvailable = [bool]($s.RefreshToken -or $s.IdentityWebSession)
        RefreshThresholdSec = $s.RefreshThresholdSec
        CanRefresh  = $s.CanRefresh
        Created     = $s.Created
    }
}

function Update-PCloudSession {
    <#
    .SYNOPSIS
        Renews the session token now, or only if it is close to expiring.
    .DESCRIPTION
        Every API call already renews the token automatically. Use this before a long step that makes
        no API calls (for example a long Start-Sleep or a large local file operation), or with -Force to
        renew immediately. Interactive sessions use the Identity refresh token.
    .EXAMPLE
        Update-PCloudSession -Force -Verbose
    #>
    [CmdletBinding()]
    param([switch]$Force, [switch]$PassThru)
    Assert-PCloudSession
    if (-not $script:PCloudSession.CanRefresh) {
        throw 'This session uses a supplied access token and cannot be renewed. Run New-PCloudSession again.'
    }
    if ($Force) { Request-PCloudToken } else { Update-PCloudTokenIfNeeded }
    if ($PassThru) { return (Get-PCloudSession) }
}

function Remove-PCloudSession {
    <#
    .SYNOPSIS
        Signs out locally: disposes the token, refresh token and credential and clears the Identity cookies.
    .PARAMETER ClearPowerShellSession
        Also clears this PowerShell window's session data (Clear-PCloudPowerShellSession). Log out with
        Disconnect-PCloudSession, which does both.
    #>
    [CmdletBinding()]
    param([switch]$ClearPowerShellSession, [switch]$KeepScreen)
    $s = $script:PCloudSession
    if ($null -ne $s) {
        foreach ($name in @('AccessToken', 'RefreshToken')) {
            if ($s.$name -is [System.Security.SecureString]) { $s.$name.Dispose() }
            $s.$name = $null
        }
        # This is the module's private copy, not the caller's credential object.
        if ($s.Credential -and $s.Credential.Password) { $s.Credential.Password.Dispose() }
        $s.Credential = $null
        $s.IdentityWebSession = $null
    }
    $script:PCloudSession = $null
    Stop-PCloudIdleTimer
    Reset-PCloudDirectoryCache
    if ($ClearPowerShellSession) { Clear-PCloudPowerShellSession -KeepScreen:$KeepScreen }
    [System.GC]::Collect()
}

function Invoke-PCloudApi {
    <#
    .SYNOPSIS
        Calls any Privilege Cloud REST endpoint with auth, error handling, retries and paging.
    .DESCRIPTION
        Use this for endpoints that do not have a dedicated cmdlet. Privilege Cloud spreads its API over
        three generations, chosen with -Generation:
          2 (default)  https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/<Path>
                       ('API/' is added if missing; 'WebServices/...' paths reach Gen 1)
          3            https://<subdomain>.privilegecloud.cyberark.cloud/api/<Path>
        With -All, responses shaped { value: [...], nextLink: '...' } are followed page by page and the
        items are returned. Other response shapes are returned as they come.
    .EXAMPLE
        Invoke-PCloudApi -Method Get -Path 'Accounts' -Query @{ search = 'admin'; limit = 100 } -All
    .EXAMPLE
        Invoke-PCloudApi -Method Post -Path 'Accounts/12_3/Verify'
    .EXAMPLE
        Invoke-PCloudApi -Generation 3 -Method Get -Path 'platforms/master-rotation-policy'
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Get', 'Post', 'Put', 'Patch', 'Delete')]
        [string]$Method = 'Get',

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [hashtable]$Query,

        [object]$Body,

        [string]$OutFile,

        [switch]$All,

        [ValidateSet(1, 2, 3)][int]$Generation = 2
    )

    Assert-PCloudSession
    $target = $Path
    if ($Generation -eq 3 -and $Path -notmatch '^(?i)https://') {
        $own = [Uri]$script:PCloudSession.PCloudUrl
        $p = $Path.TrimStart('/')
        if ($p -match '^(?i)api/') { $p = $p.Substring(4) }
        $target = 'https://{0}/api/{1}' -f $own.Authority, $p
    } elseif ($Generation -eq 1 -and $Path -notmatch '^(?i)(https://|/?webservices/)') {
        $target = 'WebServices/' + $Path.TrimStart('/')
    }
    $uri = (Resolve-PCloudUri -Path $target) + (ConvertTo-PCloudQueryString -Query $Query)

    $coreParams = @{ Method = $Method; Uri = $uri }
    if ($PSBoundParameters.ContainsKey('Body')) { $coreParams['Body'] = $Body }
    if ($OutFile) { $coreParams['OutFile'] = $OutFile }

    $result = Invoke-PCloudRequestCore @coreParams
    if (-not $All -or $null -eq $result) { return $result }
    if (-not ($result.PSObject.Properties.Name -contains 'value')) { return $result }

    while ($true) {
        foreach ($item in @($result.value)) { $item }
        $next = $null
        if ($result.PSObject.Properties.Name -contains 'nextLink') { $next = $result.nextLink }
        if (-not $next) { break }
        $result = Invoke-PCloudRequestCore -Method 'Get' -Uri (Resolve-PCloudUri -Path $next)
        if ($null -eq $result) { break }
    }
}
