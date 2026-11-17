#Requires -Version 5.1
# Master rotation policy (password verify / change intervals):
#   GET   /api/platforms/master-rotation-policy
#   GET   /api/platforms/master-rotation-policy/exceptions
#   PATCH /api/platforms/master-rotation-policy   { verifyInterval: 1-365|null, changeInterval: 1-365|null }
# These are Gen 3 endpoints: https://<subdomain>.privilegecloud.cyberark.cloud/api/...

function Invoke-PCloudRotationApi {
    param([string]$Method = 'Get', [string]$SubPath = '', [object]$Body)
    $p = @{ Generation = 3; Method = $Method; Path = ('platforms/master-rotation-policy' + $SubPath) }
    if ($null -ne $Body) { $p['Body'] = $Body }
    Invoke-PCloudApi @p
}

function Get-PCloudMasterRotationPolicy {
    <#
    .SYNOPSIS
        Gets the master rotation policy: verifyInterval and changeInterval (days, 1-365, or null),
        who changed it and when, and how many platforms have exceptions.
    #>
    [CmdletBinding()]
    param()
    Invoke-PCloudRotationApi -Method Get
}

function Get-PCloudMasterRotationPolicyException {
    <#
    .SYNOPSIS
        Lists the platforms whose verify or change interval differs from the master rotation policy.
    #>
    [CmdletBinding()]
    param()
    # Response (PlatformsExceptionListResource): { exceptions: [ { platformId, verifyInterval, changeInterval } ], totalCount }
    $r = Invoke-PCloudRotationApi -Method Get -SubPath '/exceptions'
    if ($null -eq $r) { return }
    $list = $r
    if ($r.PSObject.Properties.Name -contains 'exceptions') { $list = $r.exceptions }
    foreach ($e in @($list)) {
        if ($null -eq $e) { continue }
        [pscustomobject]@{ PlatformId = $e.platformId; VerifyInterval = $e.verifyInterval; ChangeInterval = $e.changeInterval }
    }
}

function Set-PCloudMasterRotationPolicy {
    <#
    .SYNOPSIS
        Updates the master rotation policy (PATCH). Only the intervals you pass are changed.
    .PARAMETER VerifyInterval
        Days between automatic verifications, 1-365. Use -ClearVerifyInterval to send null.
    .PARAMETER ChangeInterval
        Days between automatic password changes, 1-365. Use -ClearChangeInterval to send null.
    .EXAMPLE
        Set-PCloudMasterRotationPolicy -ChangeInterval 90 -VerifyInterval 7
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [ValidateRange(1, 365)][int]$VerifyInterval,
        [ValidateRange(1, 365)][int]$ChangeInterval,
        [switch]$ClearVerifyInterval,
        [switch]$ClearChangeInterval
    )
    $body = [ordered]@{}
    if ($PSBoundParameters.ContainsKey('VerifyInterval')) { $body['verifyInterval'] = $VerifyInterval }
    if ($ClearVerifyInterval) { $body['verifyInterval'] = $null }
    if ($PSBoundParameters.ContainsKey('ChangeInterval')) { $body['changeInterval'] = $ChangeInterval }
    if ($ClearChangeInterval) { $body['changeInterval'] = $null }
    if ($body.Count -eq 0) { throw 'Nothing to update. Pass -VerifyInterval and/or -ChangeInterval.' }
    $what = (@($body.Keys | ForEach-Object { '{0}={1}' -f $_, $(if ($null -eq $body[$_]) { 'null' } else { $body[$_] }) })) -join ', '
    if ($PSCmdlet.ShouldProcess('master rotation policy', "Set $what")) {
        Invoke-PCloudRotationApi -Method Patch -Body (ConvertTo-Json -InputObject $body -Compress)
    }
}
