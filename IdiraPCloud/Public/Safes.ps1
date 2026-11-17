#Requires -Version 5.1
# Safes: /API/Safes   Safe members: /API/Safes/{safeUrlId}/Members

$script:PCloudPermissionNames = @(
    'useAccounts', 'retrieveAccounts', 'listAccounts', 'addAccounts', 'updateAccountContent',
    'updateAccountProperties', 'initiateCPMAccountManagementOperations', 'specifyNextAccountContent',
    'renameAccounts', 'deleteAccounts', 'unlockAccounts', 'manageSafe', 'manageSafeMembers',
    'backupSafe', 'viewAuditLog', 'viewSafeMembers', 'accessWithoutConfirmation', 'createFolders',
    'deleteFolders', 'moveAccountsAndFolders', 'requestsAuthorizationLevel1', 'requestsAuthorizationLevel2'
)

function Get-PCloudSafePermissionSet {
    <#
    .SYNOPSIS
        Returns a full safe-member permission hashtable for a named preset, optionally with overrides.
    .DESCRIPTION
        Presets (module conventions that mirror the common Privilege Cloud UI roles):
          ConnectOnly     - list + use (connect through PSM) only
          ReadOnly        - list, use, retrieve
          Approver        - list, view members, manage members, authorize requests (level 1)
          AccountsManager - full account management, no safe administration
          Full            - everything except authorization level 2
          None            - all false (start from scratch with -Override)
    .EXAMPLE
        Get-PCloudSafePermissionSet -Preset ReadOnly -Override @{ viewAuditLog = $true }
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('None', 'ConnectOnly', 'ReadOnly', 'Approver', 'AccountsManager', 'Full')]
        [string]$Preset = 'ReadOnly',
        [hashtable]$Override
    )
    $perm = [ordered]@{}
    foreach ($n in $script:PCloudPermissionNames) { $perm[$n] = $false }

    $on = @()
    switch ($Preset) {
        'ConnectOnly' { $on = @('listAccounts', 'useAccounts') }
        'ReadOnly' { $on = @('listAccounts', 'useAccounts', 'retrieveAccounts') }
        'Approver' { $on = @('listAccounts', 'viewSafeMembers', 'manageSafeMembers', 'requestsAuthorizationLevel1') }
        'AccountsManager' {
            $on = @('listAccounts', 'useAccounts', 'retrieveAccounts', 'addAccounts', 'updateAccountContent',
                'updateAccountProperties', 'initiateCPMAccountManagementOperations', 'specifyNextAccountContent',
                'renameAccounts', 'deleteAccounts', 'unlockAccounts', 'viewAuditLog', 'viewSafeMembers',
                'manageSafeMembers', 'accessWithoutConfirmation', 'createFolders', 'deleteFolders', 'moveAccountsAndFolders')
        }
        'Full' { $on = $script:PCloudPermissionNames | Where-Object { $_ -ne 'requestsAuthorizationLevel2' } }
    }
    foreach ($n in $on) { $perm[$n] = $true }

    if ($Override) {
        foreach ($k in $Override.Keys) {
            $match = $script:PCloudPermissionNames | Where-Object { $_ -eq $k }
            if (-not $match) { throw "Unknown safe permission '$k'. Valid names: $($script:PCloudPermissionNames -join ', ')" }
            $perm[[string]$match] = [bool]$Override[$k]
        }
    }
    if ($perm['requestsAuthorizationLevel1'] -and $perm['requestsAuthorizationLevel2']) {
        throw 'requestsAuthorizationLevel1 and requestsAuthorizationLevel2 cannot both be true.'
    }
    return $perm
}

function Get-PCloudSafePermissionPreset {
    <#
    .SYNOPSIS
        Names the preset a safe member's permissions match, or the closest preset and the differences.
    .DESCRIPTION
        Compares all 22 permissions with each preset from Get-PCloudSafePermissionSet
        (Full, AccountsManager, Approver, ReadOnly, ConnectOnly, None).
        Returns Preset (the preset name, or 'Custom'), IsExactMatch, ClosestPreset, Added (permissions
        granted beyond the closest preset), Removed (permissions of that preset not granted) and Label,
        e.g. 'ReadOnly' or 'Custom (ReadOnly +viewAuditLog)'.
    .EXAMPLE
        Get-PCloudSafeMember -SafeName 'Linux-Root' | ForEach-Object { Get-PCloudSafePermissionPreset $_.permissions }
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true, ValueFromPipeline = $true)]$Permissions)
    process {
        $actual = @{}
        foreach ($n in $script:PCloudPermissionNames) {
            $v = $false
            if ($Permissions -is [System.Collections.IDictionary]) {
                if ($Permissions.Contains($n)) { $v = [bool]$Permissions[$n] }
            } elseif ($null -ne $Permissions -and ($Permissions.PSObject.Properties.Name -contains $n)) {
                $v = [bool]$Permissions.$n
            }
            $actual[$n] = $v
        }

        $best = $null
        $bestAdded = @()
        $bestRemoved = @()
        foreach ($presetName in @('Full', 'AccountsManager', 'Approver', 'ReadOnly', 'ConnectOnly', 'None')) {
            $set = Get-PCloudSafePermissionSet -Preset $presetName
            $added = @()
            $removed = @()
            foreach ($n in $script:PCloudPermissionNames) {
                if ($actual[$n] -and -not $set[$n]) { $added += $n }
                if (-not $actual[$n] -and $set[$n]) { $removed += $n }
            }
            if ($null -eq $best -or ($added.Count + $removed.Count) -lt ($bestAdded.Count + $bestRemoved.Count)) {
                $best = $presetName
                $bestAdded = $added
                $bestRemoved = $removed
            }
        }

        $exact = (($bestAdded.Count + $bestRemoved.Count) -eq 0)
        if ($exact) {
            $label = $best
        } elseif (($bestAdded.Count + $bestRemoved.Count) -le 3) {
            $parts = @($best) + @($bestAdded | ForEach-Object { '+' + $_ }) + @($bestRemoved | ForEach-Object { '-' + $_ })
            $label = 'Custom ({0})' -f ($parts -join ' ')
        } else {
            $label = 'Custom'
        }
        $presetOut = 'Custom'
        if ($exact) { $presetOut = $best }

        [pscustomobject]@{
            Preset        = $presetOut
            IsExactMatch  = $exact
            ClosestPreset = $best
            Added         = $bestAdded
            Removed       = $bestRemoved
            Label         = $label
        }
    }
}

function Get-PCloudSafe {
    <#
    .SYNOPSIS
        Lists safes (all pages) or gets one safe by name.
    .EXAMPLE
        Get-PCloudSafe -Search 'Linux'
    .EXAMPLE
        Get-PCloudSafe -SafeName 'Linux-Root' -IncludeAccounts
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'ByName', ValueFromPipelineByPropertyName = $true)]
        [string]$SafeName,
        [Parameter(ParameterSetName = 'List')][string]$Search,
        [Parameter(ParameterSetName = 'List')][string]$Sort,
        [Parameter(ParameterSetName = 'List')][ValidateRange(1, 1000)][int]$PageSize = 1000,
        [switch]$IncludeAccounts,
        [Parameter(ParameterSetName = 'List')][switch]$ExtendedDetails
    )
    process {
        if ($PSCmdlet.ParameterSetName -eq 'ByName') {
            $q = @{}
            if ($IncludeAccounts) { $q['includeAccounts'] = $true }
            return (Invoke-PCloudApi -Method Get -Path ('Safes/{0}' -f (ConvertTo-PCloudPathSegment $SafeName)) -Query $q)
        }
        $query = @{ limit = $PageSize }
        if ($Search) { $query['search'] = $Search }
        if ($Sort) { $query['sort'] = $Sort }
        if ($IncludeAccounts) { $query['includeAccounts'] = $true }
        if ($ExtendedDetails) { $query['extendedDetails'] = $true }
        Invoke-PCloudApi -Method Get -Path 'Safes' -Query $query -All
    }
}

function New-PCloudSafe {
    <#
    .SYNOPSIS
        Creates a safe (POST /API/Safes).
    .PARAMETER NumberOfDaysRetention
        Days to keep old versions. Use either this or -NumberOfVersionsRetention.
    .EXAMPLE
        New-PCloudSafe -SafeName 'Linux-Root' -Description 'Root accounts' -ManagingCPM 'PasswordManager' -NumberOfDaysRetention 7
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][ValidateLength(1, 28)][string]$SafeName,
        [Parameter(ValueFromPipelineByPropertyName = $true)][string]$Description,
        [Parameter(ValueFromPipelineByPropertyName = $true)][string]$ManagingCPM,
        [Parameter(ValueFromPipelineByPropertyName = $true)][string]$Location,
        [int]$NumberOfVersionsRetention = 0,
        [int]$NumberOfDaysRetention = 0,
        [switch]$AutoPurgeEnabled
    )
    process {
        if ($NumberOfVersionsRetention -gt 0 -and $NumberOfDaysRetention -gt 0) {
            throw 'Specify -NumberOfVersionsRetention or -NumberOfDaysRetention, not both.'
        }
        # OLAC is deliberately not offered (being deprecated; adds management overhead).
        $body = [ordered]@{ safeName = $SafeName; autoPurgeEnabled = [bool]$AutoPurgeEnabled }
        if ($Description) { $body['description'] = $Description }
        if ($ManagingCPM) { $body['managingCPM'] = $ManagingCPM }
        if ($Location) { $body['location'] = $Location }
        if ($NumberOfVersionsRetention -gt 0) { $body['numberOfVersionsRetention'] = $NumberOfVersionsRetention }
        if ($NumberOfDaysRetention -gt 0) { $body['numberOfDaysRetention'] = $NumberOfDaysRetention }
        if ($NumberOfVersionsRetention -eq 0 -and $NumberOfDaysRetention -eq 0) { $body['numberOfDaysRetention'] = 7 }

        if ($PSCmdlet.ShouldProcess($SafeName, 'Create safe')) {
            Invoke-PCloudApi -Method Post -Path 'Safes' -Body $body
        }
    }
}

function Set-PCloudSafe {
    <#
    .SYNOPSIS
        Updates a safe (PUT /API/Safes/{safeUrlId}). Unspecified settings keep their current values.
    .EXAMPLE
        Set-PCloudSafe -SafeName 'Linux-Root' -Description 'Prod root accounts' -ManagingCPM 'PasswordManager1'
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$SafeName,
        [ValidateLength(1, 28)][string]$NewSafeName,
        [string]$Description,
        [string]$ManagingCPM,
        [string]$Location,
        [int]$NumberOfVersionsRetention = 0,
        [int]$NumberOfDaysRetention = 0
    )
    process {
        $current = Get-PCloudSafe -SafeName $SafeName
        $body = [ordered]@{
            safeName    = $current.safeName
            description = [string]$current.description
            location    = [string]$current.location
            olacEnabled = $current.olacEnabled   # sent unchanged; OLAC is not managed by this module
            managingCPM = [string]$current.managingCPM
        }
        if ($current.numberOfVersionsRetention) { $body['numberOfVersionsRetention'] = $current.numberOfVersionsRetention }
        if ($current.numberOfDaysRetention) { $body['numberOfDaysRetention'] = $current.numberOfDaysRetention }

        if ($NewSafeName) { $body['safeName'] = $NewSafeName }
        if ($PSBoundParameters.ContainsKey('Description')) { $body['description'] = $Description }
        if ($PSBoundParameters.ContainsKey('ManagingCPM')) { $body['managingCPM'] = $ManagingCPM }
        if ($PSBoundParameters.ContainsKey('Location')) { $body['location'] = $Location }
        if ($NumberOfVersionsRetention -gt 0) {
            $body['numberOfVersionsRetention'] = $NumberOfVersionsRetention
            $body.Remove('numberOfDaysRetention')
        }
        if ($NumberOfDaysRetention -gt 0) {
            $body['numberOfDaysRetention'] = $NumberOfDaysRetention
            $body.Remove('numberOfVersionsRetention')
        }

        if ($PSCmdlet.ShouldProcess($SafeName, 'Update safe')) {
            Invoke-PCloudApi -Method Put -Path ('Safes/{0}' -f (ConvertTo-PCloudPathSegment $SafeName)) -Body $body
        }
    }
}

function Remove-PCloudSafe {
    <#
    .SYNOPSIS
        Deletes a safe (DELETE /API/Safes/{safeUrlId}). The safe must be empty of active accounts.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$SafeName
    )
    process {
        if ($PSCmdlet.ShouldProcess($SafeName, 'Delete safe')) {
            Invoke-PCloudApi -Method Delete -Path ('Safes/{0}' -f (ConvertTo-PCloudPathSegment $SafeName)) | Out-Null
        }
    }
}

function Get-PCloudSafeMember {
    <#
    .SYNOPSIS
        Lists the members of a safe, or gets one member.
    .EXAMPLE
        Get-PCloudSafeMember -SafeName 'Linux-Root'
    .EXAMPLE
        Get-PCloudSafe | Get-PCloudSafeMember -MemberType Group
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$SafeName,
        [Parameter(Mandatory = $true, ParameterSetName = 'ByName')][string]$MemberName,
        [Parameter(ParameterSetName = 'List')][string]$Search,
        [Parameter(ParameterSetName = 'List')][ValidateSet('User', 'Group', 'Role')][string]$MemberType,
        [Parameter(ParameterSetName = 'List')][switch]$IncludePredefinedUsers,
        [Parameter(ParameterSetName = 'List')][ValidateRange(1, 1000)][int]$PageSize = 1000
    )
    process {
        $safeSeg = ConvertTo-PCloudPathSegment $SafeName
        if ($PSCmdlet.ParameterSetName -eq 'ByName') {
            return (Invoke-PCloudApi -Method Get -Path ('Safes/{0}/Members/{1}' -f $safeSeg, (ConvertTo-PCloudPathSegment $MemberName)))
        }
        $query = @{ limit = $PageSize }
        if ($Search) { $query['search'] = $Search }
        if ($MemberType) { $query['filter'] = ('memberType eq {0}' -f $MemberType.ToLowerInvariant()) }
        if ($IncludePredefinedUsers) { $query['filter'] = (@($query['filter'], 'includePredefinedUsers eq true') | Where-Object { $_ }) -join ' AND ' }
        Invoke-PCloudApi -Method Get -Path ('Safes/{0}/Members' -f $safeSeg) -Query $query -All
    }
}

function Add-PCloudSafeMember {
    <#
    .SYNOPSIS
        Adds a user, group or role to a safe (POST /API/Safes/{safeUrlId}/Members).
    .PARAMETER SearchIn
        Directory to look the member up in, for example 'Vault' or an Identity directory/domain name.
        Leave empty to use the tenant default.
    .PARAMETER MemberType
        User, Group or Role. Auto (default) checks Identity: an Identity role -> Role, an Identity user or
        a name with '@' -> User, otherwise Group (see Resolve-PCloudSafeMemberType).
    .PARAMETER Permission
        Full permission hashtable. If omitted, -Preset is used (see Get-PCloudSafePermissionSet).
    .EXAMPLE
        Add-PCloudSafeMember -SafeName 'Linux-Root' -MemberName 'unix-admins' -MemberType Group -Preset AccountsManager
    .EXAMPLE
        Add-PCloudSafeMember -SafeName 'Linux-Root' -MemberName 'jdoe@acme.com' -Preset ReadOnly -ExpirationDate (Get-Date).AddDays(30)
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$SafeName,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$MemberName,
        [Parameter(ValueFromPipelineByPropertyName = $true)][ValidateSet('Auto', 'User', 'Group', 'Role')][string]$MemberType = 'Auto',
        [Parameter(ValueFromPipelineByPropertyName = $true)][string]$SearchIn,
        [ValidateSet('None', 'ConnectOnly', 'ReadOnly', 'Approver', 'AccountsManager', 'Full')][string]$Preset = 'ReadOnly',
        [System.Collections.IDictionary]$Permission,
        [datetime]$ExpirationDate,
        [switch]$IsReadOnly
    )
    process {
        if (-not $Permission) { $Permission = Get-PCloudSafePermissionSet -Preset $Preset }
        $type = $MemberType
        if ($type -eq 'Auto') {
            $type = (Resolve-PCloudSafeMemberType -MemberName $MemberName).MemberType
            Write-Verbose "Member type for '$MemberName' resolved to $type"
        }
        $body = [ordered]@{
            memberName  = $MemberName
            memberType  = $type
            isReadOnly  = [bool]$IsReadOnly
            permissions = $Permission
        }
        if ($SearchIn) { $body['searchIn'] = $SearchIn }
        if ($PSBoundParameters.ContainsKey('ExpirationDate')) { $body['membershipExpirationDate'] = ConvertTo-PCloudUnixTime $ExpirationDate }

        if ($PSCmdlet.ShouldProcess("$MemberName ($type) in safe $SafeName", 'Add safe member')) {
            Invoke-PCloudApi -Method Post -Path ('Safes/{0}/Members' -f (ConvertTo-PCloudPathSegment $SafeName)) -Body $body
        }
    }
}

function Set-PCloudSafeMember {
    <#
    .SYNOPSIS
        Replaces a safe member's permissions (PUT /API/Safes/{safeUrlId}/Members/{memberName}).
    .EXAMPLE
        Set-PCloudSafeMember -SafeName 'Linux-Root' -MemberName 'unix-admins' -Preset Full
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$SafeName,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$MemberName,
        [ValidateSet('None', 'ConnectOnly', 'ReadOnly', 'Approver', 'AccountsManager', 'Full')][string]$Preset,
        [System.Collections.IDictionary]$Permission,
        [datetime]$ExpirationDate,
        [switch]$IsReadOnly
    )
    process {
        if (-not $Permission -and -not $Preset) { throw 'Specify -Preset or -Permission.' }
        if (-not $Permission) { $Permission = Get-PCloudSafePermissionSet -Preset $Preset }
        $body = [ordered]@{ isReadOnly = [bool]$IsReadOnly; permissions = $Permission }
        if ($PSBoundParameters.ContainsKey('ExpirationDate')) { $body['membershipExpirationDate'] = ConvertTo-PCloudUnixTime $ExpirationDate }

        if ($PSCmdlet.ShouldProcess("$MemberName in safe $SafeName", 'Update safe member')) {
            Invoke-PCloudApi -Method Put -Path ('Safes/{0}/Members/{1}' -f (ConvertTo-PCloudPathSegment $SafeName), (ConvertTo-PCloudPathSegment $MemberName)) -Body $body
        }
    }
}

function Remove-PCloudSafeMember {
    <#
    .SYNOPSIS
        Removes a member from a safe (DELETE /API/Safes/{safeUrlId}/Members/{memberName}).
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$SafeName,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$MemberName
    )
    process {
        if ($PSCmdlet.ShouldProcess("$MemberName in safe $SafeName", 'Remove safe member')) {
            Invoke-PCloudApi -Method Delete -Path ('Safes/{0}/Members/{1}' -f (ConvertTo-PCloudPathSegment $SafeName), (ConvertTo-PCloudPathSegment $MemberName)) | Out-Null
        }
    }
}
