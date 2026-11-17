#Requires -Version 5.1
# Works out the Identity tenant URL from the Privilege Cloud subdomain, so users only enter the subdomain.

function ConvertTo-PCloudSubdomain {
    # Accepts 'acme', 'acme.cyberark.cloud', 'https://acme.cyberark.cloud/...',
    # 'acme.privilegecloud.cyberark.cloud' or a full PasswordVault URL, and returns 'acme'.
    param([Parameter(Mandatory = $true)][string]$Value)
    $v = $Value.Trim()
    if ($v -match '^(?i)https?://') {
        $v = ([Uri]$v).Host
    }
    $v = ($v -split '/')[0]
    $label = ($v -split '\.')[0]
    if (-not $label) { throw "Could not read a subdomain from '$Value'." }
    return $label.ToLowerInvariant()
}

function New-PCloudHttpRequest {
    param([Parameter(Mandatory = $true)][string]$Uri, [string]$Proxy, [bool]$ProxyUseDefaultCredentials, [int]$TimeoutSec = 30)
    $req = [System.Net.HttpWebRequest]::Create($Uri)
    $req.Method = 'GET'
    $req.AllowAutoRedirect = $false
    $req.UserAgent = 'IdiraPCloud-PowerShell'
    $req.Timeout = $TimeoutSec * 1000
    if ($Proxy) {
        $wp = New-Object System.Net.WebProxy($Proxy)
        if ($ProxyUseDefaultCredentials) { $wp.UseDefaultCredentials = $true }
        $req.Proxy = $wp
    }
    return $req
}

function Test-PCloudIdentityHost {
    param([string]$HostName)
    return ($HostName -match '(?i)^[a-z0-9-]+\.id\.(cyberark|idira)\.[a-z.]+$' -or $HostName -match '(?i)\.my\.idaptive\.app$')
}

function Resolve-PCloudIdentityUrl {
    <#
        1. Follow the redirects from https://<subdomain>.cyberark.cloud/ hop by hop and take the
           first host that is an Identity tenant (<tenant>.id.cyberark.cloud).
        2. Fall back to the platform discovery service.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Subdomain,
        [string]$Proxy,
        [bool]$ProxyUseDefaultCredentials,
        [int]$TimeoutSec = 30
    )
    Initialize-PCloudTls
    $sub = ConvertTo-PCloudSubdomain $Subdomain

    # 1. Redirect chain
    $uri = 'https://{0}.cyberark.cloud/' -f $sub
    for ($hop = 0; $hop -lt 10; $hop++) {
        Write-Verbose "Identity discovery: GET $uri"
        $resp = $null
        try {
            $req = New-PCloudHttpRequest -Uri $uri -Proxy $Proxy -ProxyUseDefaultCredentials $ProxyUseDefaultCredentials -TimeoutSec $TimeoutSec
            $resp = $req.GetResponse()
        } catch [System.Net.WebException] {
            $resp = $_.Exception.Response
            if ($null -eq $resp) { Write-Verbose "Identity discovery: $($_.Exception.Message)"; break }
        } catch {
            Write-Verbose "Identity discovery: $($_.Exception.Message)"
            break
        }
        try {
            $current = [Uri]$uri
            if (Test-PCloudIdentityHost $current.Host) { return ('https://' + $current.Host) }
            $status = [int]$resp.StatusCode
            $location = $resp.Headers['Location']
        } finally {
            $resp.Close()
        }
        if ($status -lt 300 -or $status -ge 400 -or -not $location) { break }
        $next = New-Object Uri($current, $location)
        if (Test-PCloudIdentityHost $next.Host) {
            Write-Verbose "Identity discovery: redirected to $($next.Host)"
            return ('https://' + $next.Host)
        }
        $uri = $next.AbsoluteUri
    }

    # 2. Platform discovery service
    $discoveryUri = 'https://platform-discovery.cyberark.cloud/api/v2/services/subdomain/{0}' -f $sub
    Write-Verbose "Identity discovery: GET $discoveryUri"
    try {
        $p = @{ Method = 'Get'; Uri = $discoveryUri; UseBasicParsing = $true; ErrorAction = 'Stop'; TimeoutSec = $TimeoutSec }
        if ($Proxy) {
            $p['Proxy'] = $Proxy
            if ($ProxyUseDefaultCredentials) { $p['ProxyUseDefaultCredentials'] = $true }
        }
        $d = Invoke-PCloudHttp -Params $p -Service 'Idira platform discovery'
        $candidates = @()
        if ($d.identity_administration) { $candidates += @($d.identity_administration.api, $d.identity_administration.ui) }
        if ($d.identity_user_portal) { $candidates += @($d.identity_user_portal.api, $d.identity_user_portal.ui) }
        foreach ($c in $candidates) {
            if (-not $c) { continue }
            $h = ([Uri]([string]$c)).Host
            if (Test-PCloudIdentityHost $h) { return ('https://' + $h) }
        }
    } catch {
        Write-Verbose "Identity discovery service: $($_.Exception.Message)"
    }

    throw ("Could not find the Identity tenant for subdomain '{0}'. Pass -IdentityUrl (for example https://abc1234.id.cyberark.cloud)." -f $sub)
}
