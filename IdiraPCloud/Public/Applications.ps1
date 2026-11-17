#Requires -Version 5.1
# Applications (Credential Provider / Central Credential Provider application IDs) - Gen 1 Web Services:
#   GET    /PasswordVault/WebServices/PIMServices.svc/Applications?AppID=&Location=&IncludeSublocations=
#   GET    .../Applications/{AppID}
#   POST   .../Applications                         { application: { ... } }
#   DELETE .../Applications/{AppID}
#   GET    .../Applications/{AppID}/Authentications
#   POST   .../Applications/{AppID}/Authentications  { authentication: { ... } }
#   DELETE .../Applications/{AppID}/Authentications/{authID}
# The API has no update call for an application; authentication methods are added and removed.

function Invoke-PCloudAppApi {
    param([string]$Method = 'Get', [string]$SubPath = '', [hashtable]$Query, $Body)
    $p = @{ Generation = 1; Method = $Method; Path = ('PIMServices.svc/Applications{0}' -f $SubPath) }
    if ($Query) { $p['Query'] = $Query }
    if ($PSBoundParameters.ContainsKey('Body')) { $p['Body'] = $Body }
    Invoke-PCloudApi @p
}

function Get-PCloudApplication {
    <#
    .SYNOPSIS
        Lists applications (Credential Provider application IDs), or gets one.
    .PARAMETER AppId
        With -ExactMatch, the one application with this ID. Otherwise a filter: applications whose ID contains it.
    .PARAMETER Location
        Vault location to list, for example '\Applications'. Default: every location.
    .EXAMPLE
        Get-PCloudApplication -AppId billing
    .EXAMPLE
        Get-PCloudApplication -AppId BillingApp -ExactMatch
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName = $true)][string]$AppId,
        [string]$Location,
        [switch]$ExactMatch,
        [bool]$IncludeSublocations = $true
    )
    process {
        if ($ExactMatch) {
            if (-not $AppId) { throw 'AppId is required with -ExactMatch.' }
            $r = Invoke-PCloudAppApi -SubPath ('/{0}' -f (ConvertTo-PCloudPathSegment $AppId))
            if ($null -eq $r) { return }
            if ($r.PSObject.Properties.Name -contains 'application') { return $r.application }
            return $r
        }
        $q = @{ IncludeSublocations = ([string]$IncludeSublocations).ToLowerInvariant() }
        if ($AppId) { $q['AppID'] = $AppId }
        if ($Location) { $q['Location'] = $Location }
        $r = Invoke-PCloudAppApi -SubPath '/' -Query $q
        if ($null -eq $r) { return }
        if ($r.PSObject.Properties.Name -contains 'application') { return @($r.application) }
        return @($r)
    }
}

function New-PCloudApplication {
    <#
    .SYNOPSIS
        Adds an application (POST .../Applications).
    .PARAMETER AccessPermittedFrom
        First hour (0-23) the application may request credentials. Default 0.
    .PARAMETER AccessPermittedTo
        Last hour (0-23) the application may request credentials. Default 23.
    .EXAMPLE
        New-PCloudApplication -AppId BillingApp -Description 'Billing batch jobs' -BusinessOwnerEmail owner@acme.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][ValidateLength(1, 128)][string]$AppId,
        [Parameter(ValueFromPipelineByPropertyName = $true)][string]$Description,
        [Parameter(ValueFromPipelineByPropertyName = $true)][string]$Location = '\',
        [Parameter(ValueFromPipelineByPropertyName = $true)][ValidateRange(0, 23)][int]$AccessPermittedFrom = 0,
        [Parameter(ValueFromPipelineByPropertyName = $true)][ValidateRange(0, 23)][int]$AccessPermittedTo = 23,
        [Parameter(ValueFromPipelineByPropertyName = $true)][Nullable[datetime]]$ExpirationDate,
        [Parameter(ValueFromPipelineByPropertyName = $true)][bool]$Disabled = $false,
        [Parameter(ValueFromPipelineByPropertyName = $true)][string]$BusinessOwnerFName,
        [Parameter(ValueFromPipelineByPropertyName = $true)][string]$BusinessOwnerLName,
        [Parameter(ValueFromPipelineByPropertyName = $true)][string]$BusinessOwnerEmail,
        [Parameter(ValueFromPipelineByPropertyName = $true)][string]$BusinessOwnerPhone
    )
    process {
        $app = [ordered]@{
            AppID               = $AppId
            Location            = $Location
            AccessPermittedFrom = $AccessPermittedFrom
            AccessPermittedTo   = $AccessPermittedTo
            Disabled            = $Disabled
        }
        if ($Description) { $app['Description'] = $Description }
        if ($ExpirationDate) { $app['ExpirationDate'] = $ExpirationDate.Value.ToString('MM-dd-yyyy', [System.Globalization.CultureInfo]::InvariantCulture) }
        foreach ($n in @('BusinessOwnerFName', 'BusinessOwnerLName', 'BusinessOwnerEmail', 'BusinessOwnerPhone')) {
            $v = Get-Variable -Name $n -ValueOnly
            if ($v) { $app[$n] = $v }
        }
        if ($PSCmdlet.ShouldProcess("application $AppId", 'Add application')) {
            Invoke-PCloudAppApi -Method Post -SubPath '/' -Body @{ application = $app } | Out-Null
            Get-PCloudApplication -AppId $AppId -ExactMatch
        }
    }
}

function Remove-PCloudApplication {
    <#
    .SYNOPSIS
        Deletes an application and its authentication methods (DELETE .../Applications/{AppID}).
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$AppId)
    process {
        if ($PSCmdlet.ShouldProcess("application $AppId", 'Delete application')) {
            Invoke-PCloudAppApi -Method Delete -SubPath ('/{0}' -f (ConvertTo-PCloudPathSegment $AppId)) | Out-Null
        }
    }
}

function Get-PCloudApplicationAuthentication {
    <#
    .SYNOPSIS
        Lists an application's authentication methods (path, hash, OS user, machine address, certificate).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$AppId)
    process {
        $r = Invoke-PCloudAppApi -SubPath ('/{0}/Authentications' -f (ConvertTo-PCloudPathSegment $AppId))
        if ($null -eq $r) { return }
        if ($r.PSObject.Properties.Name -contains 'authentication') { return @($r.authentication) }
        return @($r)
    }
}

function Add-PCloudApplicationAuthentication {
    <#
    .SYNOPSIS
        Adds an authentication method to an application (POST .../Applications/{AppID}/Authentications).
    .PARAMETER AuthType
        path, hash, osUser, machineAddress, certificateserialnumber or certificateattr.
    .PARAMETER AuthValue
        The path, hash, OS user (DOMAIN\user), address (IP, host name or range) or certificate serial number.
        Not used for certificateattr, which takes -Subject, -Issuer and/or -SubjectAlternativeName instead.
    .EXAMPLE
        Add-PCloudApplicationAuthentication -AppId BillingApp -AuthType machineAddress -AuthValue 10.0.1.25
    .EXAMPLE
        Add-PCloudApplicationAuthentication -AppId BillingApp -AuthType path -AuthValue 'C:\Billing\run.exe'
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$AppId,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('path', 'hash', 'osUser', 'machineAddress', 'certificateserialnumber', 'certificateattr')][string]$AuthType,
        [Parameter(ValueFromPipelineByPropertyName = $true)][string]$AuthValue,
        [Parameter(ValueFromPipelineByPropertyName = $true)][bool]$IsFolder = $false,
        [Parameter(ValueFromPipelineByPropertyName = $true)][bool]$AllowInternalScripts = $false,
        [Parameter(ValueFromPipelineByPropertyName = $true)][string]$Comment,
        [Parameter(ValueFromPipelineByPropertyName = $true)][string[]]$Subject,
        [Parameter(ValueFromPipelineByPropertyName = $true)][string[]]$Issuer,
        [Parameter(ValueFromPipelineByPropertyName = $true)][string[]]$SubjectAlternativeName
    )
    process {
        $auth = [ordered]@{ AuthType = $AuthType }
        if ($AuthType -eq 'certificateattr') {
            if (-not ($Subject -or $Issuer -or $SubjectAlternativeName)) { throw 'certificateattr needs at least one of Subject, Issuer or SubjectAlternativeName.' }
            if ($Subject) { $auth['Subject'] = @($Subject) }
            if ($Issuer) { $auth['Issuer'] = @($Issuer) }
            if ($SubjectAlternativeName) { $auth['SubjectAlternativeName'] = @($SubjectAlternativeName) }
        } else {
            if (-not $AuthValue) { throw ('AuthValue is required for {0}.' -f $AuthType) }
            $auth['AuthValue'] = $AuthValue
        }
        if ($AuthType -eq 'path') {
            $auth['IsFolder'] = $IsFolder
            $auth['AllowInternalScripts'] = $AllowInternalScripts
        }
        if ($Comment -and $AuthType -in @('hash', 'certificateserialnumber')) { $auth['Comment'] = $Comment }
        $what = $AuthValue
        if (-not $what) { $what = 'certificate attributes' }
        if ($PSCmdlet.ShouldProcess("application $AppId", "Add $AuthType authentication '$what'")) {
            Invoke-PCloudAppApi -Method Post -SubPath ('/{0}/Authentications' -f (ConvertTo-PCloudPathSegment $AppId)) -Body @{ authentication = $auth } | Out-Null
        }
    }
}

function Remove-PCloudApplicationAuthentication {
    <#
    .SYNOPSIS
        Removes one authentication method from an application (by its authID from Get-PCloudApplicationAuthentication).
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$AppId,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$AuthId
    )
    process {
        if ($PSCmdlet.ShouldProcess("application $AppId", "Remove authentication $AuthId")) {
            Invoke-PCloudAppApi -Method Delete -SubPath ('/{0}/Authentications/{1}' -f (ConvertTo-PCloudPathSegment $AppId), (ConvertTo-PCloudPathSegment $AuthId)) | Out-Null
        }
    }
}
