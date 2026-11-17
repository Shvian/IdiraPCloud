#Requires -Version 5.1
# Internal helpers: session state, URL building, request execution, error handling and paging.
# Written for Windows PowerShell 5.1 (no PS7-only operators or parameters).

$script:PCloudSession = $null

function Initialize-PCloudTls {
    # Windows PowerShell 5.1 may still offer SSL3/TLS 1.0/1.1. Allow only TLS 1.2 (and TLS 1.3 where
    # the OS/.NET supports it). Certificate validation is never relaxed by this module.
    try {
        $protocols = [Net.SecurityProtocolType]::Tls12
        $names = [Enum]::GetNames([Net.SecurityProtocolType])
        if ($names -contains 'Tls13') { $protocols = $protocols -bor [Net.SecurityProtocolType]'Tls13' }
        if ([Net.ServicePointManager]::SecurityProtocol -ne $protocols) {
            [Net.ServicePointManager]::SecurityProtocol = $protocols
        }
    } catch {
        Write-Verbose "Could not adjust TLS settings: $($_.Exception.Message)"
    }
}

function Assert-PCloudHttpsUrl {
    # Secrets and tokens are only ever sent over HTTPS.
    param([Parameter(Mandatory = $true)][string]$Url, [string]$Name = 'URL')
    $u = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$u) -or $u.Scheme -ne 'https') {
        throw "$Name must be an https:// URL (got '$Url')."
    }
}

function ConvertTo-PCloudSecureString {
    # Wraps a plain string (e.g. a token from an HTTP response) in a read-only SecureString.
    param([string]$PlainText)
    if (-not $PlainText) { return $null }
    $ss = New-Object System.Security.SecureString
    foreach ($ch in $PlainText.ToCharArray()) { $ss.AppendChar($ch) }
    $ss.MakeReadOnly()
    return $ss
}

function Clear-PCloudBytes {
    # Zeroes a byte buffer that held a request body (may contain secrets).
    param($Bytes)
    if ($Bytes -is [byte[]]) { [Array]::Clear($Bytes, 0, $Bytes.Length) }
}

function Assert-PCloudSession {
    # The idle limit is checked here too, in case the background timer could not run.
    if ($null -ne $script:PCloudSession -and (Invoke-PCloudIdleCheck)) {
        throw 'Signed out after inactivity. Sign in again (New-PCloudSession, or rerun the script).'
    }
    if ($null -eq $script:PCloudSession) {
        throw "No Privilege Cloud session. Run New-PCloudSession first."
    }
    Register-PCloudActivity
}

function ConvertTo-PCloudPathSegment {
    # URL-encode a single path segment (safe names, member names, platform IDs).
    param([Parameter(Mandatory = $true)][string]$Value)
    return [System.Uri]::EscapeDataString($Value)
}

function ConvertTo-PCloudQueryString {
    param([hashtable]$Query)
    if ($null -eq $Query -or $Query.Count -eq 0) { return '' }
    $pairs = New-Object System.Collections.Generic.List[string]
    foreach ($key in $Query.Keys) {
        $value = $Query[$key]
        if ($null -eq $value) { continue }
        if ($value -is [string] -and $value -eq '') { continue }
        if ($value -is [bool]) { $value = $value.ToString().ToLowerInvariant() }
        if ($value -is [System.Management.Automation.SwitchParameter]) { $value = $value.IsPresent.ToString().ToLowerInvariant() }
        $pairs.Add(('{0}={1}' -f [System.Uri]::EscapeDataString([string]$key), [System.Uri]::EscapeDataString([string]$value)))
    }
    if ($pairs.Count -eq 0) { return '' }
    return '?' + ($pairs -join '&')
}

function ConvertFrom-PCloudSecureString {
    param([Parameter(Mandatory = $true)][System.Security.SecureString]$SecureString)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Get-PCloudErrorDetail {
    # Extract status code and the Privilege Cloud ErrorCode/ErrorMessage from a failed web request (PS 5.1).
    param([Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    $statusCode = $null
    $rawBody = $null
    $response = $null
    if ($ErrorRecord.Exception -and ($ErrorRecord.Exception.PSObject.Properties.Name -contains 'Response')) {
        $response = $ErrorRecord.Exception.Response
    }
    if ($null -ne $response) {
        try { $statusCode = [int]$response.StatusCode } catch { $statusCode = $null }
    }

    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        $rawBody = $ErrorRecord.ErrorDetails.Message
    } elseif ($null -ne $response) {
        try {
            $stream = $response.GetResponseStream()
            if ($stream.CanSeek) { $stream.Position = 0 }
            $reader = New-Object System.IO.StreamReader($stream)
            $rawBody = $reader.ReadToEnd()
            $reader.Dispose()
        } catch {
            $rawBody = $null
        }
    }

    $errorCode = $null
    $errorMessage = $null
    if ($rawBody) {
        try {
            $parsed = $rawBody | ConvertFrom-Json -ErrorAction Stop
            if ($parsed.ErrorCode) { $errorCode = $parsed.ErrorCode }
            if ($parsed.ErrorMessage) { $errorMessage = $parsed.ErrorMessage }
            if (-not $errorMessage -and $parsed.error_description) { $errorMessage = $parsed.error_description }
            if (-not $errorMessage -and $parsed.error) { $errorMessage = [string]$parsed.error }
            # Newer platform services (ApiBasicError): { code, message, description, errors[], timestamp }.
            if (-not $errorCode -and $null -ne $parsed.code) { $errorCode = [string]$parsed.code }
            if (-not $errorMessage -and $parsed.message) {
                $errorMessage = [string]$parsed.message
                if ($parsed.description) { $errorMessage += ' - ' + [string]$parsed.description }
                if ($parsed.errors) { $errorMessage += ' | Errors: ' + ((@($parsed.errors) | ForEach-Object { [string]$_ }) -join '; ') }
            }
            # Validation errors (e.g. PASWS167E 'There are some invalid parameters') list the offending fields in Details.
            if ($parsed.Details) {
                $d = ConvertTo-Json -InputObject $parsed.Details -Compress -Depth 5
                if ($d.Length -gt 800) { $d = $d.Substring(0, 800) + '...' }
                if ($errorMessage) { $errorMessage = '{0} | Details: {1}' -f $errorMessage, $d } else { $errorMessage = $d }
            }
        } catch {
            # Not JSON (for example an HTML error page): keep a short plain-text summary.
            $text = $rawBody
            if ($text -match '(?is)<html|<!doctype') {
                $text = $text -replace '(?is)<(script|style)[^>]*>.*?</\1>', ' '
                $text = $text -replace '(?s)<[^>]+>', ' '
            }
            $text = ($text -replace '\s+', ' ').Trim()
            if ($text.Length -gt 300) { $text = $text.Substring(0, 300) + '...' }
            $errorMessage = $text
        }
    }
    if (-not $errorMessage) { $errorMessage = $ErrorRecord.Exception.Message }

    return [pscustomobject]@{
        StatusCode   = $statusCode
        ErrorCode    = $errorCode
        ErrorMessage = $errorMessage
        RawBody      = $rawBody
    }
}

# ---------------------------------------------------------------------------------------------
# Rate limiting (Privilege Cloud and Identity)
# Every HTTP call goes through Invoke-PCloudHttp, which
#   - spaces requests to each host (optional client-side limit, Set-PCloudRateLimit -MaxRequestsPerSecond),
#   - pauses before the server's limit runs out when X-RateLimit-Remaining reaches 0,
#   - on 429 (and 503) waits for Retry-After / X-RateLimit-Reset, or backs off exponentially with jitter,
#     then retries, up to MaxRetries times. 502/504 are retried only for GET/PUT/DELETE, so a POST that
#     may have been processed is never sent twice.
# ---------------------------------------------------------------------------------------------

$script:PCloudRateLimit = @{
    MaxRetries           = 6
    BaseDelaySec         = 2
    MaxDelaySec          = 120
    MaxRequestsPerSecond = 0      # 0 = no client-side spacing
    LastRequest          = @{}    # host -> DateTime of the last request
    NotBefore            = @{}    # host -> DateTime the server asked us to wait until
}
$script:PCloudRandom = New-Object System.Random

# Idira Identity limits (per tenant host, per endpoint, enforced at the gateway; 429 means the request was
# rejected before any processing, so it is always safe to retry):
#   tenant ceiling 1,600/s sustained (3,500 burst); High API group 1,600/s per endpoint (2,000 burst);
#   every other endpoint 90/s per endpoint (150 burst).
# The client stays at about 90% of the sustained per-endpoint rate as a safety net, and backs off briefly on 429.
$script:PCloudIdentityLimits = @{ HighPerSecond = 1400; DefaultPerSecond = 80; TenantPerSecond = 1400; BaseDelaySec = 1; MaxDelaySec = 30 }
$script:PCloudIdentityHighApi = @{}
foreach ($line in @(
    '/applogin/appkey /capweb/api /cbe/checkcredentialchange /cbe/getapps /cbe/getcbeinfooncloud /cbe/getcbesetting /cbe/getcfa'
    '/cdirectoryservice/getuser /cdirectoryservice/refreshtoken /core/getdirectoryservices /core/getiwaurls /core/gettenantconfigbatch'
    '/disasterrecovery/healthcheck /dssintake /endpointagent/getqrcodeforauthentication /endpointagent/getqrcodestatus'
    '/endpointagent/getuserbyname /extdata/getcolumns /federation/getfederatedgroupmembers /folder/checkfoldersharingpermission'
    '/folder/getfolders /integrations/getispconfig /iosapprest/customerinfo /iosapprest/getallapps /iosapprest/getdevicesettingsnocert'
    '/iosapprest/handleclientappcommands /iosapprest/obtaindevsettings /iosapprest/submitmfaauth /iosapprest/updatedevsettings'
    '/licenses/identity /login /mobile/checkmobileappversioncompatiblity /mobile/getsignedservercert /momentumapi /my'
    '/negotiatecertsecurity/sso /oath/getprofilelistfordevice /oauth2/authorize /oauth2/authorize/servicenowoidc /oauth2/introspect'
    '/oauth2/keys /oauth2/platformtoken /oauth2/refreshplatformtoken /oauth2/token /oauth2/userinfo /oidcfederation/callback'
    '/pcloud/getuser /peweb/details.xhtml /peweb/javax.faces.resource/listen.icepush.xml.xhtml /pod_rpc.svc /policy/policychecks'
    '/redrock/query /roles/getrolemembers /run /s/oob /saasmanage/downloadsamlmetadataforapp /saasmanage/getapplication'
    '/saasmanage/getpasswordinsightsettings /saasmanage/getrolemembers /saasmanage/getsharingrestriction /scim/users /secure_rpc.svc'
    '/security/advanceauthentication /security/answeroobchallenge /security/clearcid /security/cspviolation /security/getqrcodestatus'
    '/security/logout /security/oobauthstatus /security/setcid /security/startauthentication /security/startchallenge /security/whoami'
    '/swsapp/authcallback /swsapp/processauthcallback /sysinfo/version /tenantcnames/get /trustv2/.well-known/openid-configuration'
    '/trustv2/mex /trustv2/usernamemixed13 /trustv2/usernamemixed2005 /uprest/getextendedsearchdata /uprest/getresultantappsforuser'
    '/uprest/getsecureditemsdata /uprest/getupdata /uprest/handleappclick /uprest/singlelogout /uprest/taskcheck /user'
    '/usermgmt/directoryservicequery /usermgmt/gettimezones /usermgmt/getuserattributes /usermgmt/getuserinfo /usermgmt/getuserpicture'
    '/usermgmt/getusersrolesandadministrativerights /vfs/sys/tenantloginbackgroundimage /zso/certlogin /zso/issessionauthenticated'
    )) { foreach ($ep in ($line -split ' ')) { if ($ep) { $script:PCloudIdentityHighApi[$ep] = $true } } }

function Test-PCloudIsIdentityHost {
    param([string]$HostName)
    # Identity tenant host patterns (Discovery.ps1), or the session's Identity host (custom domains).
    if (Test-PCloudIdentityHost $HostName) { return $true }
    $sess = $script:PCloudSession
    if ($sess -and $sess.IdentityUrl -and ([Uri]$sess.IdentityUrl).Host -eq $HostName) { return $true }
    if ($sess -and $sess.IdentityBaseUrl -and ([Uri]$sess.IdentityBaseUrl).Host -eq $HostName) { return $true }
    return $false
}

function Get-PCloudIdentityEndpointRate {
    # Per-endpoint sustained limit for an Identity path: High API group (prefix match) or Default.
    param([string]$Path)
    $p = $Path.ToLowerInvariant().TrimEnd('/')
    while ($p) {
        if ($script:PCloudIdentityHighApi.ContainsKey($p)) { return $script:PCloudIdentityLimits.HighPerSecond }
        $i = $p.LastIndexOf('/')
        if ($i -le 0) { break }
        $p = $p.Substring(0, $i)
    }
    return $script:PCloudIdentityLimits.DefaultPerSecond
}

function Get-PCloudResponseHeader {
    param($Response, [string]$Name)
    if ($null -eq $Response) { return $null }
    try {
        $v = $Response.Headers[$Name]
        if ($v -is [array]) { $v = $v[0] }
        if ($null -ne $v -and [string]$v -ne '') { return [string]$v }
    } catch { }
    return $null
}

function ConvertTo-PCloudWaitSeconds {
    # Retry-After (seconds or HTTP date) or X-RateLimit-Reset (epoch seconds, epoch ms, or seconds left).
    param([string]$Value)
    if (-not $Value) { return $null }
    $n = 0.0
    if ([double]::TryParse($Value, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)) {
        if ($n -gt 1e11) { $n = $n / 1000 }
        if ($n -gt 1e9) {
            $epoch = New-Object DateTime 1970, 1, 1, 0, 0, 0, ([DateTimeKind]::Utc)
            $n = ($epoch.AddSeconds($n) - [DateTime]::UtcNow).TotalSeconds
        }
        if ($n -lt 0) { $n = 0 }
        return $n
    }
    $d = [DateTime]::MinValue
    if ([DateTime]::TryParse($Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$d)) {
        $s = ($d - [DateTime]::UtcNow).TotalSeconds
        if ($s -lt 0) { $s = 0 }
        return $s
    }
    return $null
}

function Wait-PCloudPace {
    # Keeps calls under -PerSecond for one key (host, or host + endpoint).
    param([string]$Key, [double]$PerSecond)
    if ($PerSecond -le 0) { return }
    $rl = $script:PCloudRateLimit
    if ($rl.LastRequest.ContainsKey($Key)) {
        $gap = 1000.0 / $PerSecond
        $since = ([DateTime]::UtcNow - $rl.LastRequest[$Key]).TotalMilliseconds
        if ($since -lt $gap) { Start-Sleep -Milliseconds ([int][Math]::Ceiling($gap - $since)) }
    }
    $rl.LastRequest[$Key] = [DateTime]::UtcNow
}

function Wait-PCloudRateSlot {
    param([string]$HostName, [string]$Path)
    $rl = $script:PCloudRateLimit
    if (Test-PCloudIsIdentityHost $HostName) {
        Wait-PCloudPace -Key ('{0}{1}' -f $HostName, $Path.ToLowerInvariant()) -PerSecond (Get-PCloudIdentityEndpointRate $Path)
        Wait-PCloudPace -Key ('tenant:{0}' -f $HostName) -PerSecond $script:PCloudIdentityLimits.TenantPerSecond
    }
    $now = [DateTime]::UtcNow
    if ($rl.NotBefore.ContainsKey($HostName) -and $rl.NotBefore[$HostName] -gt $now) {
        $ms = [int][Math]::Ceiling(($rl.NotBefore[$HostName] - $now).TotalMilliseconds)
        Write-Verbose ('Rate limit: waiting {0} ms before calling {1}' -f $ms, $HostName)
        Start-Sleep -Milliseconds $ms
    }
    if ($rl.MaxRequestsPerSecond -gt 0 -and $rl.LastRequest.ContainsKey($HostName)) {
        $gap = 1000.0 / $rl.MaxRequestsPerSecond
        $since = ([DateTime]::UtcNow - $rl.LastRequest[$HostName]).TotalMilliseconds
        if ($since -lt $gap) { Start-Sleep -Milliseconds ([int][Math]::Ceiling($gap - $since)) }
    }
    $rl.LastRequest[$HostName] = [DateTime]::UtcNow
}

function Update-PCloudRateState {
    # Reads X-RateLimit-Remaining / -Reset from a successful response and pauses the next call if needed.
    param($Response, [string]$HostName)
    $remaining = Get-PCloudResponseHeader $Response 'X-RateLimit-Remaining'
    if ($null -eq $remaining) { return }
    $r = 0
    if ([int]::TryParse($remaining, [ref]$r) -and $r -le 0) {
        $wait = ConvertTo-PCloudWaitSeconds (Get-PCloudResponseHeader $Response 'X-RateLimit-Reset')
        if ($null -eq $wait) { $wait = 1 }
        $wait = [Math]::Min($wait, $script:PCloudRateLimit.MaxDelaySec)
        $script:PCloudRateLimit.NotBefore[$HostName] = [DateTime]::UtcNow.AddSeconds($wait)
    }
}

# ---------------------------------------------------------------- request tracing (-Verbose)
# With -Verbose, every HTTP call is written to the verbose stream: method, URL, headers, body, status and
# response. Nothing secret is written: the Authorization header, cookies, secret-looking JSON values and
# query values are replaced with <redacted>, and bodies are withheld entirely for Identity (sign-in, MFA,
# tokens) and for endpoints that carry or return a credential.
$script:PCloudTrace = @{ MaxBodyChars = 4000 }
$script:PCloudSecretNames = '(?:secret|password|passphrase|passwd|pwd|credential|token|privatekey|sshkey|apikey|assertion)'
$script:PCloudSecretPaths = '(?i)/(Password|Secret|Credentials?|SSHKeys?|PrivateSSHKey|Retrieve|Logon|Logoff|Auth|OAuth2|Security)(/|\?|$)'

function Test-PCloudTraceOn {
    return ($VerbosePreference -eq [System.Management.Automation.ActionPreference]::Continue)
}

function Write-PCloudTrace {
    param([string]$Text)
    Write-Verbose -Message $Text
}

function Hide-PCloudUriSecret {
    # Redacts query-string values whose name looks secret.
    param([string]$Uri)
    return ([regex]::Replace([string]$Uri, ('(?i)([?&][^=&#]*{0}[^=&#]*=)[^&#]*' -f $script:PCloudSecretNames), '$1<redacted>'))
}

function Hide-PCloudJsonSecret {
    # Redacts the value of every JSON property whose name looks secret. The rest of the text is untouched.
    param([string]$Text)
    # secretType only says "password" or "key", so it is shown.
    $pattern = ('(?i)("(?!secretType")[^"\\]*{0}[^"\\]*"\s*:\s*)(?:"(?:[^"\\]|\\.)*"|-?\d[\d.eE+\-]*)' -f $script:PCloudSecretNames)
    return ([regex]::Replace([string]$Text, $pattern, '$1"<redacted>"'))
}

function Format-PCloudTraceBody {
    # Text of a request or response body that is safe to show, or a short note saying why it is withheld.
    param($Body, [string]$Uri, [bool]$IsIdentity, [switch]$Response)
    if ($null -eq $Body) { return $null }
    if ($IsIdentity) { return '<withheld: Identity bodies can hold credentials and tokens>' }
    if ($Uri -match $script:PCloudSecretPaths) { return '<withheld: this endpoint carries a credential>' }
    $text = $null
    if ($Body -is [byte[]]) {
        if ($Body.Length -gt 1048576) { return ('<{0} bytes, not shown>' -f $Body.Length) }
        try { $text = [System.Text.Encoding]::UTF8.GetString($Body) } catch { return ('<{0} bytes, not shown>' -f $Body.Length) }
    } elseif ($Body -is [string]) { $text = $Body }
    else { return '<withheld: not a JSON body>' }
    $trim = $text.Trim()
    if (-not $trim) { return $null }
    if ($trim -notmatch '^[\[\{]') {
        # A bare JSON string is how a retrieved password comes back; never show non-object bodies.
        if ($Response) { return ('<withheld: {0} characters, not a JSON object>' -f $trim.Length) }
        return ('<withheld: {0} characters, not a JSON body>' -f $trim.Length)
    }
    $safe = Hide-PCloudJsonSecret $trim
    $max = [int]$script:PCloudTrace.MaxBodyChars
    if ($max -gt 0 -and $safe.Length -gt $max) { $safe = $safe.Substring(0, $max) + (' ... <{0} more characters; raise with Set-PCloudApiTrace -MaxBodyChars>' -f ($safe.Length - $max)) }
    return $safe
}

function Write-PCloudTraceRequest {
    param([hashtable]$Params, [string]$Method, [bool]$IsIdentity, [int]$Attempt)
    $uri = [string]$Params['Uri']
    $again = ''
    if ($Attempt -gt 1) { $again = '   (attempt {0})' -f $Attempt }
    Write-PCloudTrace ('>>> {0} {1}{2}' -f $Method, (Hide-PCloudUriSecret $uri), $again)
    $headers = $Params['Headers']
    if ($headers -is [System.Collections.IDictionary]) {
        foreach ($k in $headers.Keys) {
            $v = [string]$headers[$k]
            if ([string]$k -match '(?i)^authorization$') {
                $scheme = ($v -split ' ')[0]
                $v = '{0} <redacted>' -f $scheme
            } elseif ([string]$k -match ('(?i){0}|key|cookie|auth' -f $script:PCloudSecretNames)) { $v = '<redacted>' }
            Write-PCloudTrace ('    {0}: {1}' -f $k, $v)
        }
    }
    if ($Params['ContentType']) { Write-PCloudTrace ('    Content-Type: {0}' -f $Params['ContentType']) }
    if ($Params.ContainsKey('WebSession')) { Write-PCloudTrace '    Cookie: <redacted>' }
    $b = Format-PCloudTraceBody -Body $Params['Body'] -Uri $uri -IsIdentity $IsIdentity
    if ($null -ne $b) { Write-PCloudTrace ('    Body: {0}' -f $b) } else { Write-PCloudTrace '    Body: (none)' }
}

function Write-PCloudTraceResponse {
    param($Status, [double]$Ms, [string]$Uri, [bool]$IsIdentity, $Text, [string]$Note)
    Write-PCloudTrace ('<<< HTTP {0}   ({1:N0} ms)' -f $Status, $Ms)
    if ($Note) { Write-PCloudTrace ('    {0}' -f $Note); return }
    $b = Format-PCloudTraceBody -Body $Text -Uri $Uri -IsIdentity $IsIdentity -Response
    if ($null -ne $b) { Write-PCloudTrace ('    Body: {0}' -f $b) } else { Write-PCloudTrace '    Body: (empty)' }
}

function Set-PCloudApiTrace {
    <#
    .SYNOPSIS
        Turns request tracing on or off for the whole module (the task scripts do this for you with -Verbose).
    .DESCRIPTION
        With tracing on, every HTTP call is written to the verbose stream: method, URL, headers, body, status,
        time and response body. Secrets are never written: the Authorization header and cookies are redacted,
        JSON values and query values with secret-looking names are redacted, and bodies are withheld for
        Identity (sign-in, MFA, tokens) and for endpoints that carry or return a credential.
    .PARAMETER MaxBodyChars
        Longest body shown before it is cut (default 4000; 0 = no limit).
    .EXAMPLE
        Set-PCloudApiTrace -Enabled $true; Set-PCloudSafe -SafeName X -ManagingCPM PasswordManager1; Set-PCloudApiTrace -Enabled $false
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][bool]$Enabled,
        [ValidateRange(0, 1000000)][int]$MaxBodyChars = 4000
    )
    $script:PCloudTrace.MaxBodyChars = $MaxBodyChars
    # Module-level preference: every function in the module then writes its verbose messages.
    if ($Enabled) { $script:VerbosePreference = [System.Management.Automation.ActionPreference]::Continue }
    else { $script:VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue }
}

function Invoke-PCloudHttp {
    <#
        Runs Invoke-RestMethod (or Invoke-WebRequest with -Raw) with rate-limit handling. Errors that are
        not retried, or that are still failing after MaxRetries, are rethrown unchanged for the caller.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Params,
        [switch]$Raw,
        [string]$Service = 'Privilege Cloud'
    )
    $rl = $script:PCloudRateLimit
    $uriObj = [Uri][string]$Params['Uri']
    $hostName = $uriObj.Host
    $isIdentity = Test-PCloudIsIdentityHost $hostName
    $baseDelay = $rl.BaseDelaySec
    $maxDelay = $rl.MaxDelaySec
    if ($isIdentity) {
        # Identity limits are per second, so a short back-off is enough.
        $baseDelay = [Math]::Min($baseDelay, $script:PCloudIdentityLimits.BaseDelaySec)
        $maxDelay = [Math]::Min($maxDelay, $script:PCloudIdentityLimits.MaxDelaySec)
    }
    $method = 'GET'
    if ($Params['Method']) { $method = ([string]$Params['Method']).ToUpperInvariant() }
    if (-not $Params.ContainsKey('UseBasicParsing')) { $Params['UseBasicParsing'] = $true }
    if (-not $Params.ContainsKey('ErrorAction')) { $Params['ErrorAction'] = 'Stop' }
    # The trace below replaces Invoke-WebRequest's own verbose lines.
    if (-not $Params.ContainsKey('Verbose')) { $Params['Verbose'] = $false }
    # Bodies are only ever traced for Privilege Cloud itself, never for Identity (sign-in, MFA, tokens).
    $traceHide = $isIdentity -or ($Service -match '(?i)identity')
    $attempt = 0
    while ($true) {
        $attempt++
        Wait-PCloudRateSlot -HostName $hostName -Path $uriObj.AbsolutePath
        $traceOn = Test-PCloudTraceOn
        if ($traceOn) { Write-PCloudTraceRequest -Params $Params -Method $method -IsIdentity $traceHide -Attempt $attempt }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $resp = Invoke-WebRequest @Params
            $sw.Stop()
            Update-PCloudRateState -Response $resp -HostName $hostName
            if ($Raw -or $Params.ContainsKey('OutFile')) {
                if ($traceOn) {
                    $note = 'Body: <not shown: raw response>'
                    if ($Params.ContainsKey('OutFile')) { $note = 'Body: <saved to {0}>' -f $Params['OutFile'] }
                    Write-PCloudTraceResponse -Status ([int]$resp.StatusCode) -Ms $sw.Elapsed.TotalMilliseconds -Uri ([string]$Params['Uri']) -IsIdentity $traceHide -Note $note
                }
                return $resp
            }
            # Decode as UTF-8 ourselves: 5.1 falls back to ISO-8859-1 when the response has no charset.
            $text = $null
            try { if ($resp.RawContentStream) { $text = [System.Text.Encoding]::UTF8.GetString($resp.RawContentStream.ToArray()) } } catch { $text = $null }
            if ($null -eq $text) { $text = $resp.Content }
            if ($text -is [byte[]]) { $text = [System.Text.Encoding]::UTF8.GetString($text) }
            if ($text) { $text = ([string]$text).TrimStart([char]0xFEFF) }
            if ($traceOn) { Write-PCloudTraceResponse -Status ([int]$resp.StatusCode) -Ms $sw.Elapsed.TotalMilliseconds -Uri ([string]$Params['Uri']) -IsIdentity $traceHide -Text ([string]$text) }
            if ([string]::IsNullOrWhiteSpace([string]$text)) { return $null }
            $ctype = [string](Get-PCloudResponseHeader $resp 'Content-Type')
            if ($ctype -match '(?i)json' -or ([string]$text).TrimStart() -match '^[\[\{"]') {
                try { return (ConvertFrom-Json -InputObject $text) } catch { return $text }
            }
            return $text
        } catch {
            $err = $_
            $response = $null
            if ($err.Exception -and ($err.Exception.PSObject.Properties.Name -contains 'Response')) { $response = $err.Exception.Response }
            $status = $null
            if ($null -ne $response) { try { $status = [int]$response.StatusCode } catch { } }
            if ($traceOn) {
                $shown = $status
                if (-not $shown) { $shown = 'none' }
                Write-PCloudTraceResponse -Status $shown -Ms $sw.Elapsed.TotalMilliseconds -Uri ([string]$Params['Uri']) -IsIdentity $traceHide -Note ('Failed: {0}' -f $err.Exception.Message)
            }

            $retry = $false
            if ($status -eq 429 -or $status -eq 503) { $retry = $true }
            elseif (($status -eq 502 -or $status -eq 504) -and @('GET', 'PUT', 'DELETE', 'HEAD') -contains $method) { $retry = $true }
            if (-not $retry -or $attempt -gt $rl.MaxRetries) { throw $err }

            $wait = ConvertTo-PCloudWaitSeconds (Get-PCloudResponseHeader $response 'Retry-After')
            if ($null -eq $wait) { $wait = ConvertTo-PCloudWaitSeconds (Get-PCloudResponseHeader $response 'X-RateLimit-Reset') }
            if ($null -eq $wait) {
                $wait = $baseDelay * [Math]::Pow(2, $attempt - 1)
            }
            # Jitter spreads retries from parallel runs so they don't hit the limit together again.
            $wait = [Math]::Min($wait, $maxDelay) + ($script:PCloudRandom.NextDouble() * 0.5)
            $rl.NotBefore[$hostName] = [DateTime]::UtcNow.AddSeconds($wait)
            $why = 'is busy'
            if ($status -eq 429) { $why = 'is rate limiting requests' }
            Write-Warning ('{0} {1} (HTTP {2}). Waiting {3:N1} s, then retrying ({4} of {5}).' -f $Service, $why, $status, $wait, $attempt, $rl.MaxRetries)
        }
    }
}

function Set-PCloudRateLimit {
    <#
    .SYNOPSIS
        Tunes rate-limit handling for Privilege Cloud and Identity calls.
    .PARAMETER MaxRequestsPerSecond
        Client-side spacing per host (0 = off). Use it to stay under a known tenant limit.
    .PARAMETER MaxRetries
        Retries after HTTP 429/503 (default 6).
    .PARAMETER BaseDelaySec
        First back-off wait when the server gives no Retry-After (doubles each retry; default 2).
    .PARAMETER MaxDelaySec
        Longest single wait (default 120).
    .EXAMPLE
        Set-PCloudRateLimit -MaxRequestsPerSecond 5
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(0, 1000)][double]$MaxRequestsPerSecond = -1,
        [ValidateRange(0, 20)][int]$MaxRetries = -1,
        [ValidateRange(0.1, 600)][double]$BaseDelaySec = -1,
        [ValidateRange(1, 3600)][double]$MaxDelaySec = -1
    )
    $rl = $script:PCloudRateLimit
    if ($PSBoundParameters.ContainsKey('MaxRequestsPerSecond')) { $rl.MaxRequestsPerSecond = $MaxRequestsPerSecond }
    if ($PSBoundParameters.ContainsKey('MaxRetries')) { $rl.MaxRetries = $MaxRetries }
    if ($PSBoundParameters.ContainsKey('BaseDelaySec')) { $rl.BaseDelaySec = $BaseDelaySec }
    if ($PSBoundParameters.ContainsKey('MaxDelaySec')) { $rl.MaxDelaySec = $MaxDelaySec }
    Get-PCloudRateLimit
}

function Get-PCloudRateLimit {
    <#
    .SYNOPSIS
        Shows the current rate-limit settings.
    #>
    [CmdletBinding()]
    param()
    $rl = $script:PCloudRateLimit
    [pscustomobject]@{
        MaxRequestsPerSecond = $rl.MaxRequestsPerSecond
        MaxRetries           = $rl.MaxRetries
        BaseDelaySec         = $rl.BaseDelaySec
        MaxDelaySec          = $rl.MaxDelaySec
    }
}

function Invoke-PCloudRequestCore {
    # Single HTTP call with retry for throttling/transient errors and one re-auth on 401.
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Uri,
        [object]$Body,
        [string]$ContentType = 'application/json; charset=utf-8',
        [string]$OutFile,
        [int]$MaxRetries = 3
    )

    Initialize-PCloudTls
    $attempt = 0
    $reauthDone = $false

    while ($true) {
        $attempt++
        Update-PCloudTokenIfNeeded

        # The token lives in the session as a SecureString; it is decoded only for this request.
        $headers = @{
            'Authorization' = 'Bearer ' + (ConvertFrom-PCloudSecureString $script:PCloudSession.AccessToken)
            'Accept'        = 'application/json'
        }
        $params = @{
            Method          = $Method
            Uri             = $Uri
            Headers         = $headers
            UseBasicParsing = $true
            ErrorAction     = 'Stop'
        }
        if ($script:PCloudSession.TimeoutSec -gt 0) { $params['TimeoutSec'] = $script:PCloudSession.TimeoutSec }
        if ($script:PCloudSession.Proxy) {
            $params['Proxy'] = $script:PCloudSession.Proxy
            if ($script:PCloudSession.ProxyUseDefaultCredentials) { $params['ProxyUseDefaultCredentials'] = $true }
        }
        if ($null -ne $Body) {
            if ($Body -is [byte[]]) {
                $params['Body'] = $Body
            } else {
                if ($Body -is [string]) { $json = $Body } else { $json = ConvertTo-Json -InputObject $Body -Depth 20 -Compress }
                # Send UTF-8 bytes; PS 5.1 otherwise may mangle non-ASCII characters.
                $params['Body'] = [System.Text.Encoding]::UTF8.GetBytes($json)
            }
            $params['ContentType'] = $ContentType
        }

        try {
            if ($OutFile) {
                $params['OutFile'] = $OutFile
                Invoke-PCloudHttp -Params $params | Out-Null
                return (Get-Item -LiteralPath $OutFile)
            }
            # Waits and retries on rate limiting (429/503) and gateway errors are handled in Invoke-PCloudHttp.
            return (Invoke-PCloudHttp -Params $params)
        } catch {
            $detail = Get-PCloudErrorDetail -ErrorRecord $_
            $status = $detail.StatusCode

            if ($status -eq 401 -and -not $reauthDone -and $script:PCloudSession.CanRefresh) {
                Write-Verbose 'Received 401; requesting a new token and retrying once.'
                $reauthDone = $true
                Request-PCloudToken
                $attempt--
                continue
            }
            if ($status -eq 429) {
                $msgPrefix = 'Privilege Cloud is still rate limiting after {0} retries. Wait a minute and run it again, or slow down with Set-PCloudRateLimit -MaxRequestsPerSecond.' -f $script:PCloudRateLimit.MaxRetries
                Write-Warning $msgPrefix
            }

            $msg = "Privilege Cloud API call failed: {0} {1}" -f $Method.ToUpperInvariant(), $Uri
            if ($status) { $msg += " | HTTP $status" }
            if ($detail.ErrorCode) { $msg += " | $($detail.ErrorCode)" }
            if ($detail.ErrorMessage) { $msg += " | $($detail.ErrorMessage)" }

            $exception = New-Object System.Exception($msg, $_.Exception)
            $record = New-Object System.Management.Automation.ErrorRecord($exception, 'PCloudApiError', [System.Management.Automation.ErrorCategory]::InvalidOperation, $Uri)
            $record.ErrorDetails = New-Object System.Management.Automation.ErrorDetails($msg)
            throw $record
        } finally {
            if ($Body -isnot [byte[]]) { Clear-PCloudBytes $params['Body'] }
            $headers = $null
            $params = $null
            $json = $null
        }
    }
}

function Resolve-PCloudUri {
    # Accepts 'Accounts', 'API/Accounts', '/API/Accounts' or a nextLink like 'api/Accounts?offset=50'.
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($Path -match '^(?i)[a-z][a-z0-9+.-]*://') {
        # Absolute URLs (e.g. a nextLink) must point at the same Privilege Cloud host over HTTPS,
        # so the bearer token is never sent anywhere else.
        $target = [Uri]$Path
        $own = [Uri]$script:PCloudSession.PCloudUrl
        if ($target.Scheme -ne 'https' -or $target.Host -ne $own.Host) {
            throw "Refusing to send the session token to '$($target.Scheme)://$($target.Host)'. Only $($own.Host) over HTTPS is allowed."
        }
        return $Path
    }
    $p = $Path.TrimStart('/')
    if ($p -notmatch '^(?i)(api|webservices)/') { $p = 'API/' + $p }
    return $script:PCloudSession.PCloudUrl.TrimEnd('/') + '/' + $p
}
