#Requires -Version 5.1
# Internal token handling for Idira Identity (Identity Security Platform Shared Services).
#
# Auth methods (session.AuthMethod):
#   ServiceUser  - OAuth2 client_credentials for an Identity service user
#                  POST {IdentityUrl}/oauth2/platformtoken
#   OAuthApp     - OAuth2 client_credentials against a custom Identity OAuth2 web app
#                  POST {IdentityUrl}/oauth2/token/{AppId}
#   Interactive  - Any Identity sign-in method (password, MFA push, OTP, SMS, email, phone, etc.)
#                  POST {IdentityUrl}/Security/StartAuthentication, then /Security/AdvanceAuthentication
#   AccessToken  - A token supplied by the caller (never renewed)
#
# Renewal: before every API call the token's expiry (from expires_in, or the JWT 'exp' claim) is
# checked, and the token is renewed when it is within RefreshThresholdSec of expiring.
#   ServiceUser/OAuthApp - client_credentials has no refresh token, so a new token is requested
#                          with the stored client secret (no user interaction).
#   Interactive          - the Identity refresh token is used (POST /OAuth2/RefreshToken/...);
#                          if Identity refuses it, the user is asked to sign in again.

function Get-PCloudWebParams {
    # Common Invoke-RestMethod parameters (timeout and proxy) from the session.
    $s = $script:PCloudSession
    $p = @{ UseBasicParsing = $true; ErrorAction = 'Stop' }
    if ($s.TimeoutSec -gt 0) { $p['TimeoutSec'] = $s.TimeoutSec }
    if ($s.Proxy) {
        $p['Proxy'] = $s.Proxy
        if ($s.ProxyUseDefaultCredentials) { $p['ProxyUseDefaultCredentials'] = $true }
    }
    return $p
}

function Get-PCloudJwtExpiry {
    # Reads the 'exp' claim from a JWT without validating it. Returns $null if not a JWT.
    param([string]$Token)
    if (-not $Token) { return $null }
    $parts = $Token.Split('.')
    if ($parts.Count -lt 2) { return $null }
    try {
        $payload = $parts[1].Replace('-', '+').Replace('_', '/')
        switch ($payload.Length % 4) {
            2 { $payload += '==' }
            3 { $payload += '=' }
        }
        $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
        $claims = $json | ConvertFrom-Json
        if ($claims.exp) { return (ConvertFrom-PCloudUnixTime $claims.exp) }
    } catch {
        Write-Verbose 'Token is not a readable JWT; expiry unknown.'
    }
    return $null
}

function Set-PCloudSessionToken {
    # Stores the token (and refresh token) as SecureStrings; plain copies are dropped by the caller.
    param([Parameter(Mandatory = $true)][string]$Token, [int]$ExpiresIn = 0, [string]$RefreshToken)
    $s = $script:PCloudSession
    if ($s.AccessToken -is [System.Security.SecureString]) { $s.AccessToken.Dispose() }
    $s.AccessToken = ConvertTo-PCloudSecureString $Token
    $s.TokenType = 'Bearer'
    $exp = Get-PCloudJwtExpiry $Token
    if ($ExpiresIn -gt 0) {
        $byLifetime = (Get-Date).AddSeconds($ExpiresIn)
        if ($null -eq $exp -or $byLifetime -lt $exp) { $exp = $byLifetime }
    }
    $s.ExpiresAt = $exp
    if ($RefreshToken) {
        if ($s.RefreshToken -is [System.Security.SecureString]) { $s.RefreshToken.Dispose() }
        $s.RefreshToken = ConvertTo-PCloudSecureString $RefreshToken
    }
    $s.LastRenewed = Get-Date
    if ($null -ne $exp) {
        Write-Verbose ("Token set; expires {0:u}" -f $exp.ToUniversalTime())
    } else {
        Write-Verbose 'Token set; expiry unknown (renewed on 401).'
    }
}

function Request-PCloudToken {
    Assert-PCloudSession
    $s = $script:PCloudSession
    if (-not $s.CanRefresh) {
        throw 'The session was created from a supplied access token and cannot be renewed. Run New-PCloudSession again.'
    }
    Initialize-PCloudTls

    if ($s.AuthMethod -eq 'Interactive') {
        if ($s.RefreshToken -or $s.IdentityWebSession) {
            try {
                Invoke-PCloudInteractiveRefresh
                return
            } catch {
                Write-Warning ("Could not renew the Identity session silently ({0}). Please sign in again." -f $_.Exception.Message)
            }
        }
        if ($s.RefreshToken -is [System.Security.SecureString]) { $s.RefreshToken.Dispose() }
        $s.RefreshToken = $null
        $s.IdentityWebSession = $null
        $login = Invoke-PCloudInteractiveLogin
        try {
            Set-PCloudSessionToken -Token $login.Token -RefreshToken $login.RefreshToken
        } finally {
            $login = $null
        }
        return
    }

    Request-PCloudClientCredentialsToken
}

function Request-PCloudClientCredentialsToken {
    $s = $script:PCloudSession
    $clientId = $s.Credential.UserName
    $clientSecret = $s.Credential.GetNetworkCredential().Password

    if ($s.AuthMethod -eq 'OAuthApp') {
        $tokenUri = '{0}/oauth2/token/{1}' -f $s.IdentityUrl, [System.Uri]::EscapeDataString($s.AppId)
    } else {
        $tokenUri = '{0}/oauth2/platformtoken' -f $s.IdentityUrl
    }

    $form = @{
        grant_type    = 'client_credentials'
        client_id     = $clientId
        client_secret = $clientSecret
    }
    if ($s.Scope) { $form['scope'] = $s.Scope }

    $params = Get-PCloudWebParams
    $params['Method'] = 'Post'
    $params['Uri'] = $tokenUri
    $params['Body'] = $form
    $params['ContentType'] = 'application/x-www-form-urlencoded'

    try {
        $response = Invoke-PCloudHttp -Params $params -Service 'Idira Identity'
    } catch {
        $detail = Get-PCloudErrorDetail -ErrorRecord $_
        $msg = 'Identity authentication failed at {0}' -f $tokenUri
        if ($detail.StatusCode) { $msg += " | HTTP $($detail.StatusCode)" }
        if ($detail.ErrorMessage) { $msg += " | $($detail.ErrorMessage)" }
        if ($detail.StatusCode -eq 400 -and $s.AuthMethod -eq 'ServiceUser') {
            $msg += ' | Check that the user name includes its suffix (user@domain.1234), that the user is flagged "Is Service User" and "Is OAuth confidential client", or use -AuthMethod Interactive.'
        }
        throw $msg
    } finally {
        $clientSecret = $null
        $form = $null
        $params = $null
    }

    if (-not $response.access_token) {
        throw "Identity returned no access_token from $tokenUri."
    }

    $expiresIn = 0
    if ($response.expires_in) { $expiresIn = [int]$response.expires_in }
    Set-PCloudSessionToken -Token ([string]$response.access_token) -ExpiresIn $expiresIn
    $response = $null
    if ($null -eq $s.ExpiresAt) { $s.ExpiresAt = (Get-Date).AddSeconds(900) }
}

function Update-PCloudTokenIfNeeded {
    Assert-PCloudSession
    $s = $script:PCloudSession
    if (-not $s.CanRefresh) { return }
    if (-not $s.AccessToken) { Request-PCloudToken; return }
    if ($null -eq $s.ExpiresAt) {
        # Expiry unknown: interactive tokens are then renewed on 401; client-credential tokens are re-requested.
        if ($s.AuthMethod -ne 'Interactive') { Request-PCloudToken }
        return
    }
    $threshold = 120
    if ($s.RefreshThresholdSec -gt 0) { $threshold = $s.RefreshThresholdSec }
    if ((Get-Date).AddSeconds($threshold) -ge $s.ExpiresAt) {
        Write-Verbose ("Token expires {0:u}; renewing." -f $s.ExpiresAt.ToUniversalTime())
        Request-PCloudToken
    }
}

# ---------------------------------------------------------------------------------------------
# Interactive (StartAuthentication / AdvanceAuthentication)
# ---------------------------------------------------------------------------------------------

function Invoke-PCloudIdentityPost {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][hashtable]$Body,
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,
        [hashtable]$Headers
    )
    $uri = $BaseUrl.TrimEnd('/') + $Path
    Assert-PCloudHttpsUrl -Url $uri -Name 'Identity URL'
    $params = Get-PCloudWebParams
    if ($WebSession) { $params['WebSession'] = $WebSession }
    $params['Method'] = 'Post'
    $params['Uri'] = $uri
    $h = @{ 'X-IDAP-NATIVE-CLIENT' = 'true'; 'Accept' = 'application/json' }
    if ($Headers) { foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] } }
    $params['Headers'] = $h
    $params['ContentType'] = 'application/json; charset=utf-8'
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Body -Depth 5 -Compress))
    $params['Body'] = $bodyBytes
    try {
        $response = Invoke-PCloudHttp -Params $params -Service 'Idira Identity'
    } catch {
        $detail = Get-PCloudErrorDetail -ErrorRecord $_
        $msg = 'Identity sign-in failed at {0}' -f $uri
        if ($detail.StatusCode) { $msg += " | HTTP $($detail.StatusCode)" }
        if ($detail.ErrorMessage) { $msg += " | $($detail.ErrorMessage)" }
        throw $msg
    } finally {
        Clear-PCloudBytes $bodyBytes
        $params = $null
    }
    if (-not $response.success) {
        $m = $response.Message
        if (-not $m) { $m = 'Identity reported the step as unsuccessful.' }
        throw "Identity sign-in failed: $m"
    }
    return $response.Result
}

function Get-PCloudMechanismLabel {
    param($Mechanism)
    $label = $Mechanism.PromptSelectMech
    if (-not $label) { $label = $Mechanism.Name }
    return ('{0} [{1}]' -f $label, $Mechanism.Name)
}

function Select-PCloudMechanism {
    param([Parameter(Mandatory = $true)]$Challenge, [bool]$HavePassword)
    $s = $script:PCloudSession
    $mechs = @($Challenge.Mechanisms)
    if ($mechs.Count -eq 0) { throw 'Identity returned a challenge with no sign-in mechanisms.' }
    if ($mechs.Count -eq 1) { return $mechs[0] }

    if ($HavePassword) {
        $up = @($mechs | Where-Object { $_.Name -eq 'UP' })
        if ($up.Count -gt 0) { return $up[0] }
    }
    foreach ($pref in @($s.PreferredMechanism)) {
        if (-not $pref) { continue }
        $hit = @($mechs | Where-Object { $_.Name -eq $pref })
        if ($hit.Count -gt 0) { return $hit[0] }
    }

    Write-Host 'Choose a sign-in method:'
    for ($i = 0; $i -lt $mechs.Count; $i++) {
        Write-Host ('  {0}) {1}' -f ($i + 1), (Get-PCloudMechanismLabel $mechs[$i]))
    }
    while ($true) {
        $choice = Read-Host ('Enter 1-{0}' -f $mechs.Count)
        $n = 0
        if ([int]::TryParse($choice, [ref]$n) -and $n -ge 1 -and $n -le $mechs.Count) { return $mechs[$n - 1] }
        Write-Host 'Invalid choice.'
    }
}

function Invoke-PCloudInteractiveLogin {
    $s = $script:PCloudSession
    $user = $s.UserName
    if (-not $user -and $s.Credential) { $user = $s.Credential.UserName }
    if (-not $user) { $user = Read-Host 'Identity user name (e.g. jdoe@acme.com)' }

    $havePassword = $false
    if ($s.Credential) {
        if ($s.Credential.Password -and $s.Credential.Password.Length -gt 0) { $havePassword = $true }
    }

    $baseUrl = $s.IdentityUrl
    # Cookie container: Identity keeps the sign-in (and refresh) state in cookies.
    $ws = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    # PlatformTokenResponse asks Identity for a platform token plus a refresh token (as CyberArk's ark-sdk does),
    # so the session can be renewed later without prompting.
    $startBody = [ordered]@{ User = $user; Version = '1.0'; PlatformTokenResponse = $true; MfaRequestor = 'DeviceAgent' }
    # OobIdPAuth asks Identity for what a console needs to finish a SAML (external IdP) sign-in:
    # a short browser URL plus an IdP login session to complete, instead of a browser-only redirect.
    $idpHeaders = @{ 'OobIdPAuth' = 'true' }
    $start = Invoke-PCloudIdentityPost -BaseUrl $baseUrl -Path '/Security/StartAuthentication' -Body $startBody -WebSession $ws -Headers $idpHeaders

    # The tenant may live on another pod; Identity then tells us where to restart.
    if ($start.PodFqdn -and -not $start.SessionId -and -not $start.IdpRedirectUrl -and -not $start.IdpRedirectShortUrl) {
        $baseUrl = 'https://' + $start.PodFqdn
        Write-Verbose "Identity redirected to $baseUrl"
        $start = Invoke-PCloudIdentityPost -BaseUrl $baseUrl -Path '/Security/StartAuthentication' -Body $startBody -WebSession $ws -Headers $idpHeaders
    }
    if ($start.IdpRedirectUrl -or $start.IdpRedirectShortUrl) {
        $result = Invoke-PCloudSamlLogin -Start $start -BaseUrl $baseUrl -WebSession $ws -User $user -Headers $idpHeaders
        return (Complete-PCloudInteractiveLogin -Result $result -WebSession $ws -BaseUrl $baseUrl -User $user)
    }
    if (-not $start.SessionId) { throw 'Identity did not return a sign-in session.' }

    $sessionId = $start.SessionId
    $challenges = @($start.Challenges)
    $index = 0
    $deadline = (Get-Date).AddSeconds($s.MfaTimeoutSec)

    while ($index -lt $challenges.Count) {
        $mech = Select-PCloudMechanism -Challenge $challenges[$index] -HavePassword $havePassword
        $result = $null
        Write-Verbose ("Challenge {0}: {1} ({2})" -f ($index + 1), $mech.Name, $mech.AnswerType)

        if ($mech.AnswerType -eq 'Text') {
            if ($mech.Name -eq 'UP' -and $havePassword) {
                $answer = $s.Credential.GetNetworkCredential().Password
            } else {
                $prompt = $mech.PromptMechChosen
                if (-not $prompt) { $prompt = 'Enter value for ' + $mech.Name }
                # Every typed answer (password, OTP, security answer) is masked and read as a SecureString.
                $answer = ConvertFrom-PCloudSecureString (Read-Host -Prompt $prompt -AsSecureString)
            }
            try {
                $result = Invoke-PCloudIdentityPost -BaseUrl $baseUrl -Path '/Security/AdvanceAuthentication' -WebSession $ws -Body @{
                    SessionId = $sessionId; MechanismId = $mech.MechanismId; Action = 'Answer'; Answer = $answer
                }
            } finally {
                $answer = $null
            }
        } elseif ($mech.AnswerType -eq 'StartTextOob' -or $mech.AnswerType -eq 'StartOob') {
            $result = Invoke-PCloudIdentityPost -BaseUrl $baseUrl -Path '/Security/AdvanceAuthentication' -WebSession $ws -Body @{
                SessionId = $sessionId; MechanismId = $mech.MechanismId; Action = 'StartOOB'
            }
            $prompt = $mech.PromptMechChosen
            if ($prompt) { Write-Host $prompt }

            while ($result.Summary -eq 'OobPending') {
                if ((Get-Date) -gt $deadline) { throw "Timed out waiting for $($mech.Name) approval." }
                if ($mech.AnswerType -eq 'StartTextOob') {
                    # Email/SMS style: the user can type the code, or approve the link and press Enter.
                    $codeSecure = Read-Host 'Enter the code you received, or approve the request and press Enter' -AsSecureString
                    $code = $null
                    if ($codeSecure.Length -gt 0) { $code = ConvertFrom-PCloudSecureString $codeSecure }
                    $codeSecure.Dispose()
                    if ($code) {
                        $result = Invoke-PCloudIdentityPost -BaseUrl $baseUrl -Path '/Security/AdvanceAuthentication' -WebSession $ws -Body @{
                            SessionId = $sessionId; MechanismId = $mech.MechanismId; Action = 'Answer'; Answer = $code
                        }
                        $code = $null
                        continue
                    }
                } else {
                    Start-Sleep -Seconds 2
                }
                $result = Invoke-PCloudIdentityPost -BaseUrl $baseUrl -Path '/Security/AdvanceAuthentication' -WebSession $ws -Body @{
                    SessionId = $sessionId; MechanismId = $mech.MechanismId; Action = 'Poll'
                }
            }
        } else {
            throw "Sign-in mechanism '$($mech.Name)' (answer type '$($mech.AnswerType)') is not supported in a console. Pick another method."
        }

        switch ([string]$result.Summary) {
            'LoginSuccess' {
                return (Complete-PCloudInteractiveLogin -Result $result -WebSession $ws -BaseUrl $baseUrl -User $user)
            }
            'StartNextChallenge' { $index++ }
            'NewPackage' {
                $challenges = @($result.Challenges)
                $index = 0
            }
            default { throw "Identity sign-in stopped with status '$($result.Summary)'." }
        }
    }
    throw 'Identity sign-in ended without a token.'
}

function Complete-PCloudInteractiveLogin {
    # Stores the sign-in state on the session and returns the token and refresh token.
    param($Result, $WebSession, [string]$BaseUrl, [string]$User)
    $s = $script:PCloudSession
    if (-not $Result.Token) { throw 'Identity reported success but returned no token.' }
    Write-Verbose "Signed in as $User"
    $s.IdentityWebSession = $WebSession
    $s.IdentityBaseUrl = $BaseUrl
    # Remember who signed in (shown by Get-PCloudSession; reused if a full sign-in is needed again).
    $s.UserName = $User
    $refresh = $null
    if ($Result.PSObject.Properties.Name -contains 'RefreshToken') { $refresh = [string]$Result.RefreshToken }
    if (-not $refresh) { $refresh = Get-PCloudCookieValue -WebSession $WebSession -BaseUrl $BaseUrl -Name 'refreshToken' }
    if ($refresh) { Write-Verbose 'Identity refresh token captured.' } else { Write-Verbose 'No refresh token returned; renewal will use the Identity session cookie.' }
    return [pscustomobject]@{ Token = [string]$Result.Token; RefreshToken = $refresh }
}

function Invoke-PCloudSamlLogin {
    <#
        SAML (external identity provider) sign-in from the console. Identity returns a short URL for the
        browser and an IdP login session. The browser is opened on that URL; after the user signs in at the
        identity provider, either:
          - Identity shows a PIN in the browser (IdpOobAuthPinRequired): it is typed here, masked, and sent
            to /Security/AdvanceAuthentication with MechanismId OOBAUTHPIN, or
          - this polls /Security/OobAuthStatus every 2 seconds until the browser sign-in completes.
        This is the flow CyberArk's ark-sdk and the IdentityCommand module use. The token never passes
        through the browser; it comes back on the console's own Identity session.
    #>
    param($Start, [string]$BaseUrl, $WebSession, [string]$User, [hashtable]$Headers)
    $s = $script:PCloudSession
    $url = [string]$Start.IdpRedirectShortUrl
    if (-not $url) { $url = [string]$Start.IdpRedirectUrl }
    $idpSession = [string]$Start.IdpLoginSessionId
    if (-not $idpSession) {
        throw "User '$User' signs in through an external identity provider (SAML), but Identity did not return a login session to complete it from the console. Use a service user (-AuthMethod ServiceUser) or a token (-AuthMethod AccessToken)."
    }
    if ($url -notmatch '^https://') { throw 'Identity returned an identity provider URL that is not HTTPS; not opening it.' }

    Write-Host ''
    Write-Host ("'{0}' signs in through your identity provider (SAML)." -f $User) -ForegroundColor Cyan
    Write-Host 'Opening your browser to sign in. If it does not open, go to:'
    Write-Host ('  {0}' -f $url)
    try { Start-Process $url } catch { Write-Host "Couldn't open the browser; open the link above yourself." -ForegroundColor Yellow }

    if ($Start.IdpOobAuthPinRequired) {
        $pin = Read-Host 'After signing in, enter the PIN shown in the browser' -AsSecureString
        $answer = ConvertFrom-PCloudSecureString $pin
        $pin.Dispose()
        try {
            $result = Invoke-PCloudIdentityPost -BaseUrl $BaseUrl -Path '/Security/AdvanceAuthentication' -WebSession $WebSession -Headers $Headers -Body @{
                SessionId = $idpSession; MechanismId = 'OOBAUTHPIN'; Action = 'Answer'; Answer = $answer
            }
        } finally { $answer = $null }
        if ([string]$result.Summary -ne 'LoginSuccess' -or -not $result.Token) {
            throw ("The identity provider sign-in was not accepted (status '{0}')." -f $result.Summary)
        }
        return $result
    }

    Write-Host 'Waiting for you to finish signing in in the browser (Ctrl+C to cancel)...'
    $deadline = (Get-Date).AddSeconds([Math]::Max(120, [int]$s.MfaTimeoutSec))
    while ($true) {
        if ((Get-Date) -gt $deadline) { throw 'Timed out waiting for the identity provider sign-in in the browser.' }
        Start-Sleep -Seconds 2
        $result = Invoke-PCloudIdentityPost -BaseUrl $BaseUrl -Path '/Security/OobAuthStatus' -WebSession $WebSession -Headers $Headers -Body @{ SessionId = $idpSession }
        $state = [string]$result.State
        if ($state -eq 'Success' -or ([string]$result.Summary -eq 'LoginSuccess' -and $result.Token)) { return $result }
        if ($state -match '^(?i)(Fail|Error|Denied|Reject|Expire|Cancel)') {
            throw ("The identity provider sign-in ended with state '{0}'." -f $state)
        }
    }
}

function Get-PCloudCookieValue {
    param($WebSession, [string]$BaseUrl, [string]$Name)
    if (-not $WebSession) { return $null }
    try {
        foreach ($c in $WebSession.Cookies.GetCookies([Uri]$BaseUrl)) {
            # Identity may name it per tenant, e.g. refreshToken-<tenant_id>.
            if ($c.Name -eq $Name -or $c.Name -like ($Name + '-*')) { return $c.Value }
        }
    } catch { }
    return $null
}

function Get-PCloudJwtClaim {
    # Reads one claim from a JWT payload without validating it. Returns $null if unreadable.
    param([string]$Token, [string]$Name)
    if (-not $Token) { return $null }
    $parts = $Token.Split('.')
    if ($parts.Count -lt 2) { return $null }
    try {
        $payload = $parts[1].Replace('-', '+').Replace('_', '/')
        switch ($payload.Length % 4) {
            2 { $payload += '==' }
            3 { $payload += '=' }
        }
        $claims = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
        if ($claims.PSObject.Properties.Name -contains $Name) { return $claims.$Name }
    } catch { }
    return $null
}

function Invoke-PCloudInteractiveRefresh {
    <#
        Renews an interactive token without prompting: POST /OAuth2/RefreshPlatformToken on the Identity
        tenant, sending the refreshToken-<tenant_id> and idToken-<tenant_id> cookies. The new tokens come back
        as cookies with the same names (the method used by CyberArk's ark-sdk-python).
    #>
    $s = $script:PCloudSession
    $token = $null
    $refresh = $null
    if ($s.AccessToken) { $token = ConvertFrom-PCloudSecureString $s.AccessToken }
    if ($s.RefreshToken) { $refresh = ConvertFrom-PCloudSecureString $s.RefreshToken }
    if (-not $refresh -and $s.IdentityWebSession -and $s.IdentityBaseUrl) {
        $refresh = Get-PCloudCookieValue -WebSession $s.IdentityWebSession -BaseUrl $s.IdentityBaseUrl -Name 'refreshToken'
    }
    $tenantId = [string](Get-PCloudJwtClaim -Token $token -Name 'tenant_id')
    try {
        if (-not $refresh) { throw 'no refresh token was issued at sign-in' }
        if (-not $tenantId) { throw 'the token has no tenant_id claim' }

        # Try the pod Identity sent us to at sign-in first, then the tenant URL.
        $bases = @(@($s.IdentityBaseUrl, $s.IdentityUrl) | Where-Object { $_ } | ForEach-Object { ([string]$_).TrimEnd('/') } | Select-Object -Unique)
        $lastError = $null
        foreach ($base in $bases) {
            Assert-PCloudHttpsUrl -Url $base -Name 'Identity URL'
            $u = [Uri]$base
            $ws = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            $ws.Cookies.Add((New-Object System.Net.Cookie(('refreshToken-{0}' -f $tenantId), $refresh, '/', $u.Host)))
            $ws.Cookies.Add((New-Object System.Net.Cookie(('idToken-{0}' -f $tenantId), $token, '/', $u.Host)))

            $params = Get-PCloudWebParams
            $params['Method'] = 'Post'
            $params['Uri'] = $base + '/OAuth2/RefreshPlatformToken'
            $params['WebSession'] = $ws
            $params['Headers'] = @{ 'X-IDAP-NATIVE-CLIENT' = 'true'; 'Accept' = 'application/json' }
            try {
                $null = Invoke-PCloudHttp -Params $params -Raw -Service 'Idira Identity'
            } catch {
                $detail = Get-PCloudErrorDetail -ErrorRecord $_
                $lastError = 'refresh refused'
                if ($detail.StatusCode) { $lastError += " (HTTP $($detail.StatusCode))" }
                if ($detail.ErrorMessage) { $lastError += ": $($detail.ErrorMessage)" }
                $ws = $null
                continue
            } finally {
                $params = $null
            }

            $newToken = $null
            $newRefresh = $null
            foreach ($c in $ws.Cookies.GetCookies($u)) {
                if ($c.Name -eq ('idToken-{0}' -f $tenantId)) { $newToken = $c.Value }
                elseif ($c.Name -eq ('refreshToken-{0}' -f $tenantId)) { $newRefresh = $c.Value }
            }
            $ws = $null
            if (-not $newToken) { $lastError = 'Identity accepted the refresh but returned no new token'; continue }
            if (-not $newRefresh) { $newRefresh = $refresh }
            Set-PCloudSessionToken -Token $newToken -RefreshToken $newRefresh
            $newToken = $null
            $newRefresh = $null
            Write-Verbose 'Interactive token renewed with the refresh token.'
            return
        }
        throw $lastError
    } finally {
        $token = $null
        $refresh = $null
    }
}
