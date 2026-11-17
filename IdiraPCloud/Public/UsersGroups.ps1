#Requires -Version 5.1
# Vault users: /API/Users   Vault groups: /API/UserGroups
# Note: in Privilege Cloud (Shared Services) human users and roles are normally managed in Idira Identity.
# These endpoints cover the vault-side view of users and vault groups.

function Get-PCloudUser {
    <#
    .SYNOPSIS
        Lists vault users (GET /API/Users) or gets one user by numeric ID.
    .PARAMETER Filter
        e.g. "userType eq EPVUser" or "componentUser eq false".
    .EXAMPLE
        Get-PCloudUser -Search 'jdoe'
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'ById', ValueFromPipelineByPropertyName = $true)][Alias('UserId')][int]$Id,
        [Parameter(ParameterSetName = 'List')][string]$Search,
        [Parameter(ParameterSetName = 'List')][string]$Filter,
        [Parameter(ParameterSetName = 'List')][switch]$ExtendedDetails
    )
    process {
        if ($PSCmdlet.ParameterSetName -eq 'ById') {
            return (Invoke-PCloudApi -Method Get -Path ('Users/{0}' -f $Id))
        }
        $query = @{}
        if ($Search) { $query['search'] = $Search }
        if ($Filter) { $query['filter'] = $Filter }
        if ($ExtendedDetails) { $query['ExtendedDetails'] = $true }
        $result = Invoke-PCloudApi -Method Get -Path 'Users' -Query $query
        if ($null -ne $result -and ($result.PSObject.Properties.Name -contains 'Users')) { return $result.Users }
        return $result
    }
}

function Get-PCloudGroup {
    <#
    .SYNOPSIS
        Lists vault user groups (GET /API/UserGroups) or gets one group by numeric ID.
    .EXAMPLE
        Get-PCloudGroup -Search 'Admins' -IncludeMembers
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'ById', ValueFromPipelineByPropertyName = $true)][Alias('GroupId')][int]$Id,
        [Parameter(ParameterSetName = 'List')][string]$Search,
        [Parameter(ParameterSetName = 'List')][ValidateSet('Vault', 'Directory')][string]$GroupType,
        [switch]$IncludeMembers
    )
    process {
        $query = @{}
        if ($IncludeMembers) { $query['includeMembers'] = $true }
        if ($PSCmdlet.ParameterSetName -eq 'ById') {
            return (Invoke-PCloudApi -Method Get -Path ('UserGroups/{0}' -f $Id) -Query $query)
        }
        if ($Search) { $query['search'] = $Search }
        if ($GroupType) { $query['filter'] = ('groupType eq {0}' -f $GroupType) }
        Invoke-PCloudApi -Method Get -Path 'UserGroups' -Query $query -All
    }
}

function New-PCloudGroup {
    <#
    .SYNOPSIS
        Creates a vault group (POST /API/UserGroups).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$GroupName,
        [string]$Description,
        [string]$Location = '\'
    )
    $body = [ordered]@{ groupName = $GroupName; location = $Location }
    if ($Description) { $body['description'] = $Description }
    if ($PSCmdlet.ShouldProcess($GroupName, 'Create vault group')) {
        Invoke-PCloudApi -Method Post -Path 'UserGroups' -Body $body
    }
}

function Set-PCloudGroup {
    <#
    .SYNOPSIS
        Renames a vault group (PUT /API/UserGroups/{id}).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('GroupId')][int]$Id,
        [Parameter(Mandatory = $true)][string]$GroupName
    )
    process {
        if ($PSCmdlet.ShouldProcess("group $Id", "Rename to $GroupName")) {
            Invoke-PCloudApi -Method Put -Path ('UserGroups/{0}' -f $Id) -Body @{ groupName = $GroupName }
        }
    }
}

function Remove-PCloudGroup {
    <#
    .SYNOPSIS
        Deletes a vault group (DELETE /API/UserGroups/{id}).
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('GroupId')][int]$Id)
    process {
        if ($PSCmdlet.ShouldProcess("group $Id", 'Delete vault group')) {
            Invoke-PCloudApi -Method Delete -Path ('UserGroups/{0}' -f $Id) | Out-Null
        }
    }
}

function Add-PCloudGroupMember {
    <#
    .SYNOPSIS
        Adds a member to a vault group (POST /API/UserGroups/{id}/Members).
    .EXAMPLE
        Add-PCloudGroupMember -Id 15 -MemberId 'jdoe'
    .EXAMPLE
        Add-PCloudGroupMember -Id 15 -MemberId 'jdoe' -MemberType domain -DomainName 'acme.local'
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][Alias('GroupId')][int]$Id,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('username')][string]$MemberId,
        [ValidateSet('vault', 'domain')][string]$MemberType = 'vault',
        [string]$DomainName
    )
    process {
        $body = [ordered]@{ memberId = $MemberId; memberType = $MemberType }
        if ($DomainName) { $body['domainName'] = $DomainName }
        if ($PSCmdlet.ShouldProcess("group $Id", "Add member $MemberId")) {
            Invoke-PCloudApi -Method Post -Path ('UserGroups/{0}/Members' -f $Id) -Body $body
        }
    }
}

function Remove-PCloudGroupMember {
    <#
    .SYNOPSIS
        Removes a member from a vault group (DELETE /API/UserGroups/{id}/Members/{memberName}).
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)][Alias('GroupId')][int]$Id,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('username')][string]$MemberName
    )
    process {
        if ($PSCmdlet.ShouldProcess("group $Id", "Remove member $MemberName")) {
            Invoke-PCloudApi -Method Delete -Path ('UserGroups/{0}/Members/{1}' -f $Id, (ConvertTo-PCloudPathSegment $MemberName)) | Out-Null
        }
    }
}
