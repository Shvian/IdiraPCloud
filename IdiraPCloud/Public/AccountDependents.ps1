#Requires -Version 5.1
# Account dependents (Windows services, scheduled tasks and similar that use a target account's credentials).
# Gen 3 API: https://<subdomain>.privilegecloud.cyberark.cloud/api/accounts/{account_id}/account-dependents
#   GET    .../account-dependents                         list (extendedDetails, keyword, limit, offset)
#   GET    .../account-dependents/{id}                    one dependent
#   POST   .../account-dependents                         add     { name, platformId, platformDependentProperties, secretManagement }
#   PUT    .../account-dependents/{id}                    update  (same body)
#   DELETE .../account-dependents/{id}
#   POST   .../account-dependents/{id}/link-accounts      { index, accountId }
#   DELETE .../account-dependents/{id}/link-accounts/{index}
# Responses come wrapped as { statusCode, headers, body }; the functions return the body.

function Invoke-PCloudDependentApi {
    param([string]$AccountId, [string]$SubPath = '', [string]$Method = 'Get', [hashtable]$Query, $Body)
    $path = 'accounts/{0}/account-dependents{1}' -f (ConvertTo-PCloudPathSegment $AccountId), $SubPath
    $p = @{ Generation = 3; Method = $Method; Path = $path }
    if ($Query) { $p['Query'] = $Query }
    if ($PSBoundParameters.ContainsKey('Body')) { $p['Body'] = $Body }
    $r = Invoke-PCloudApi @p
    return (ConvertFrom-PCloudEnvelope $r)
}

function ConvertFrom-PCloudEnvelope {
    # { statusCode, headers, body } -> body. Anything else is returned as it is.
    param($Response)
    if ($null -eq $Response -or $Response -is [string]) { return $Response }
    $names = @($Response.PSObject.Properties.Name)
    if (($names -contains 'body') -and ($names -contains 'statusCode')) {
        $code = 0
        if ([int]::TryParse([string]$Response.statusCode, [ref]$code) -and $code -ge 400) {
            throw ('Privilege Cloud returned {0}: {1}' -f $code, [string]$Response.body)
        }
        return $Response.body
    }
    return $Response
}

function ConvertTo-PCloudDependentBody {
    param([string]$Name, [string]$PlatformId, [System.Collections.IDictionary]$Properties,
        $AutomaticManagement, [string]$ManualManagementReason, $DisableParentAutomaticManagement)
    $sm = [ordered]@{}
    if ($null -ne $AutomaticManagement) { $sm['automaticManagementEnabled'] = [bool]$AutomaticManagement }
    if ($ManualManagementReason) { $sm['manualManagementReason'] = $ManualManagementReason }
    if ($null -ne $DisableParentAutomaticManagement) { $sm['disableParentAutomaticManagement'] = [bool]$DisableParentAutomaticManagement }
    $body = [ordered]@{ platformId = $PlatformId }
    if ($Name) { $body['name'] = $Name }
    $props = [ordered]@{}
    if ($Properties) { foreach ($k in $Properties.Keys) { $props[[string]$k] = $Properties[$k] } }
    $body['platformDependentProperties'] = $props
    $body['secretManagement'] = $sm
    return $body
}

function Get-PCloudAccountDependent {
    <#
    .SYNOPSIS
        Lists the dependents of an account (Windows services, scheduled tasks, ...), or gets one.
    .PARAMETER Keyword
        Only dependents that match this text.
    .EXAMPLE
        Get-PCloudAccountDependent -AccountId 12_34
    .EXAMPLE
        Get-PCloudAccountDependent -AccountId 12_34 -DependentId 5
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('id')][string]$AccountId,
        [string]$DependentId,
        [string]$Keyword,
        [switch]$ExtendedDetails,
        [ValidateRange(1, 1000)][int]$PageSize = 100
    )
    process {
        if ($DependentId) {
            $q = @{}
            if ($ExtendedDetails) { $q['extendedDetails'] = 'true' }
            return (Invoke-PCloudDependentApi -AccountId $AccountId -SubPath ('/{0}' -f (ConvertTo-PCloudPathSegment $DependentId)) -Query $q)
        }
        $offset = 0
        while ($true) {
            $q = @{ limit = $PageSize; offset = $offset }
            if ($Keyword) { $q['keyword'] = $Keyword }
            if ($ExtendedDetails) { $q['extendedDetails'] = 'true' }
            $r = Invoke-PCloudDependentApi -AccountId $AccountId -Query $q
            if ($null -eq $r) { return }
            $items = @()
            if ($r.PSObject.Properties.Name -contains 'accountDependents') { $items = @($r.accountDependents | Where-Object { $null -ne $_ }) }
            elseif ($r -is [array]) { $items = @($r) }
            foreach ($i in $items) { $i }
            $total = 0
            if ($r.PSObject.Properties.Name -contains 'totalCount') { [void][int]::TryParse([string]$r.totalCount, [ref]$total) }
            $offset += $items.Count
            if ($items.Count -eq 0 -or $items.Count -lt $PageSize -or $offset -ge $total) { return }
        }
    }
}

function New-PCloudAccountDependent {
    <#
    .SYNOPSIS
        Adds a dependent (for example a Windows service) to an account.
    .PARAMETER PlatformId
        The dependent platform, for example WinService or WinScheduledTask.
    .PARAMETER Properties
        The dependent platform's properties, for example @{ Address = 'srv01'; ServiceName = 'MySvc' }.
    .EXAMPLE
        New-PCloudAccountDependent -AccountId 12_34 -PlatformId WinService -Properties @{ Address = 'srv01'; ServiceName = 'Billing' }
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$AccountId,
        [Parameter(Mandatory = $true)][string]$PlatformId,
        [string]$Name,
        [System.Collections.IDictionary]$Properties,
        [Nullable[bool]]$AutomaticManagement,
        [string]$ManualManagementReason,
        [Nullable[bool]]$DisableParentAutomaticManagement
    )
    $body = ConvertTo-PCloudDependentBody -Name $Name -PlatformId $PlatformId -Properties $Properties -AutomaticManagement $AutomaticManagement -ManualManagementReason $ManualManagementReason -DisableParentAutomaticManagement $DisableParentAutomaticManagement
    if ($PSCmdlet.ShouldProcess("account $AccountId", "Add $PlatformId dependent")) {
        Invoke-PCloudDependentApi -AccountId $AccountId -Method Post -Body $body
    }
}

function Set-PCloudAccountDependent {
    <#
    .SYNOPSIS
        Updates a dependent. Settings you leave out keep their current values (the current dependent is read
        first and the full body is sent).
    .PARAMETER Properties
        Properties to set. A value of $null removes the property.
    .EXAMPLE
        Set-PCloudAccountDependent -AccountId 12_34 -DependentId 5 -Properties @{ ServiceName = 'Billing2' }
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$AccountId,
        [Parameter(Mandatory = $true)][string]$DependentId,
        [string]$Name,
        [string]$PlatformId,
        [System.Collections.IDictionary]$Properties,
        [Nullable[bool]]$AutomaticManagement,
        [string]$ManualManagementReason,
        [Nullable[bool]]$DisableParentAutomaticManagement
    )
    $cur = Get-PCloudAccountDependent -AccountId $AccountId -DependentId $DependentId
    if ($null -eq $cur) { throw ("Dependent {0} of account {1} was not found." -f $DependentId, $AccountId) }
    $props = [ordered]@{}
    if ($cur.platformDependentProperties) { foreach ($p in $cur.platformDependentProperties.PSObject.Properties) { $props[$p.Name] = $p.Value } }
    if ($Properties) {
        foreach ($k in $Properties.Keys) {
            if ($null -eq $Properties[$k]) { $props.Remove([string]$k) } else { $props[[string]$k] = $Properties[$k] }
        }
    }
    $sm = $cur.secretManagement
    $auto = $null; $reason = ''; $disableParent = $null
    if ($sm) {
        if ($sm.PSObject.Properties.Name -contains 'automaticManagementEnabled') { $auto = $sm.automaticManagementEnabled }
        if ($sm.PSObject.Properties.Name -contains 'manualManagementReason') { $reason = [string]$sm.manualManagementReason }
        if ($sm.PSObject.Properties.Name -contains 'disableParentAutomaticManagement') { $disableParent = $sm.disableParentAutomaticManagement }
    }
    if ($PSBoundParameters.ContainsKey('AutomaticManagement')) { $auto = $AutomaticManagement }
    if ($PSBoundParameters.ContainsKey('ManualManagementReason')) { $reason = $ManualManagementReason }
    if ($PSBoundParameters.ContainsKey('DisableParentAutomaticManagement')) { $disableParent = $DisableParentAutomaticManagement }
    if ($auto -eq $true) { $reason = '' }
    $n = [string]$cur.name
    if ($PSBoundParameters.ContainsKey('Name')) { $n = $Name }
    $plat = [string]$cur.platformId
    if ($PlatformId) { $plat = $PlatformId }
    $body = ConvertTo-PCloudDependentBody -Name $n -PlatformId $plat -Properties $props -AutomaticManagement $auto -ManualManagementReason $reason -DisableParentAutomaticManagement $disableParent
    if ($PSCmdlet.ShouldProcess("dependent $DependentId of account $AccountId", 'Update dependent')) {
        Invoke-PCloudDependentApi -AccountId $AccountId -SubPath ('/{0}' -f (ConvertTo-PCloudPathSegment $DependentId)) -Method Put -Body $body
    }
}

function Remove-PCloudAccountDependent {
    <#
    .SYNOPSIS
        Deletes a dependent from an account.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory = $true)][string]$AccountId, [Parameter(Mandatory = $true)][string]$DependentId)
    if ($PSCmdlet.ShouldProcess("dependent $DependentId of account $AccountId", 'Delete dependent')) {
        $null = Invoke-PCloudDependentApi -AccountId $AccountId -SubPath ('/{0}' -f (ConvertTo-PCloudPathSegment $DependentId)) -Method Delete
    }
}

function Add-PCloudAccountDependentLink {
    <#
    .SYNOPSIS
        Links an account (for example a logon account) to a dependent.
    .PARAMETER Index
        The linked account's extra password index (from the dependent platform; 1 is usually the logon account).
    .EXAMPLE
        Add-PCloudAccountDependentLink -AccountId 12_34 -DependentId 5 -Index 1 -LinkedAccountId 12_99
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$AccountId,
        [Parameter(Mandatory = $true)][string]$DependentId,
        [Parameter(Mandatory = $true)][int]$Index,
        [Parameter(Mandatory = $true)][string]$LinkedAccountId
    )
    $body = [ordered]@{ index = [string]$Index; accountId = $LinkedAccountId }
    if ($PSCmdlet.ShouldProcess("dependent $DependentId of account $AccountId", "Link account $LinkedAccountId at index $Index")) {
        $null = Invoke-PCloudDependentApi -AccountId $AccountId -SubPath ('/{0}/link-accounts' -f (ConvertTo-PCloudPathSegment $DependentId)) -Method Post -Body $body
    }
}

function Remove-PCloudAccountDependentLink {
    <#
    .SYNOPSIS
        Unlinks the account at an extra password index from a dependent.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)][string]$AccountId,
        [Parameter(Mandatory = $true)][string]$DependentId,
        [Parameter(Mandatory = $true)][int]$Index
    )
    if ($PSCmdlet.ShouldProcess("dependent $DependentId of account $AccountId", "Unlink index $Index")) {
        $null = Invoke-PCloudDependentApi -AccountId $AccountId -SubPath ('/{0}/link-accounts/{1}' -f (ConvertTo-PCloudPathSegment $DependentId), $Index) -Method Delete
    }
}
