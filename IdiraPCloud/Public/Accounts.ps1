#Requires -Version 5.1
# Accounts: /API/Accounts

function Get-PCloudAccount {
    <#
    .SYNOPSIS
        Lists accounts (all pages) or gets one account by ID.
    .PARAMETER Search
        Free-text search across account properties (space separated words).
    .PARAMETER SearchType
        contains (default) or startswith.
    .PARAMETER SafeName
        Restricts results to one safe (builds filter "safeName eq <name>").
    .PARAMETER Filter
        Raw filter, e.g. "safeName eq Linux-Root" or "modificationTime gte 1700000000".
    .PARAMETER PageSize
        Records requested per page (max 1000).
    .PARAMETER First
        Stop after this many accounts.
    .EXAMPLE
        Get-PCloudAccount -SafeName 'Win-Domain-Admins'
    .EXAMPLE
        Get-PCloudAccount -Search 'root 10.0.0.5'
    .EXAMPLE
        Get-PCloudAccount -Id 12_34
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'ById', ValueFromPipelineByPropertyName = $true)]
        [Alias('AccountId')]
        [string]$Id,

        [Parameter(ParameterSetName = 'List')][string]$Search,
        [Parameter(ParameterSetName = 'List')][ValidateSet('contains', 'startswith')][string]$SearchType,
        [Parameter(ParameterSetName = 'List')][string]$SafeName,
        [Parameter(ParameterSetName = 'List')][string]$Filter,
        [Parameter(ParameterSetName = 'List')][string]$Sort,
        [Parameter(ParameterSetName = 'List')][ValidateRange(1, 1000)][int]$PageSize = 1000,
        [Parameter(ParameterSetName = 'List')][int]$First = 0
    )
    process {
        if ($PSCmdlet.ParameterSetName -eq 'ById') {
            return (Invoke-PCloudApi -Method Get -Path ('Accounts/{0}' -f (ConvertTo-PCloudPathSegment $Id)))
        }
        $filters = @()
        if ($SafeName) { $filters += ('safeName eq {0}' -f $SafeName) }
        if ($Filter) { $filters += $Filter }
        $query = @{ limit = $PageSize }
        if ($Search) { $query['search'] = $Search }
        if ($SearchType) { $query['searchType'] = $SearchType }
        if ($Sort) { $query['sort'] = $Sort }
        if ($filters.Count -gt 0) { $query['filter'] = ($filters -join ' AND ') }

        $count = 0
        foreach ($acct in (Invoke-PCloudApi -Method Get -Path 'Accounts' -Query $query -All)) {
            $acct
            $count++
            if ($First -gt 0 -and $count -ge $First) { break }
        }
    }
}

function New-PCloudAccount {
    <#
    .SYNOPSIS
        Onboards (adds) an account to a safe.
    .EXAMPLE
        $pw = Read-Host 'Password' -AsSecureString
        New-PCloudAccount -SafeName 'Linux-Root' -PlatformId 'UnixSSH' -Address '10.0.0.5' -UserName 'root' -Secret $pw
    .EXAMPLE
        New-PCloudAccount -SafeName 'Win-Domain' -PlatformId 'WinDomain' -Address 'acme.local' -UserName 'svc_sql' `
            -Secret $pw -PlatformAccountProperties @{ LogonDomain = 'ACME' } -DisableAutomaticManagement -ManualManagementReason 'Service account'
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$SafeName,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$PlatformId,
        [Parameter(ValueFromPipelineByPropertyName = $true)][string]$Address,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$UserName,
        [Parameter(ValueFromPipelineByPropertyName = $true)][string]$Name,
        [Parameter(ValueFromPipelineByPropertyName = $true)][System.Security.SecureString]$Secret,
        [ValidateSet('password', 'key')][string]$SecretType = 'password',
        [hashtable]$PlatformAccountProperties,
        [switch]$DisableAutomaticManagement,
        [string]$ManualManagementReason,
        [string[]]$RemoteMachines,
        [switch]$AccessRestrictedToRemoteMachines
    )
    process {
        $body = [ordered]@{
            safeName   = $SafeName
            platformId = $PlatformId
            userName   = $UserName
            secretType = $SecretType
        }
        if ($Name) { $body['name'] = $Name }
        if ($Address) { $body['address'] = $Address }
        if ($Secret) { $body['secret'] = ConvertFrom-PCloudSecureString $Secret }
        if ($PlatformAccountProperties) { $body['platformAccountProperties'] = $PlatformAccountProperties }

        $sm = [ordered]@{ automaticManagementEnabled = (-not $DisableAutomaticManagement) }
        if ($DisableAutomaticManagement -and $ManualManagementReason) { $sm['manualManagementReason'] = $ManualManagementReason }
        $body['secretManagement'] = $sm

        if ($RemoteMachines) {
            $body['remoteMachinesAccess'] = [ordered]@{
                remoteMachines                   = ($RemoteMachines -join ';')
                accessRestrictedToRemoteMachines = [bool]$AccessRestrictedToRemoteMachines
            }
        }

        $target = '{0}@{1} in safe {2}' -f $UserName, $Address, $SafeName
        if ($PSCmdlet.ShouldProcess($target, 'Add account')) {
            try {
                Invoke-PCloudApi -Method Post -Path 'Accounts' -Body $body
            } finally {
                $body = $null
            }
        }
    }
}

function Set-PCloudAccount {
    <#
    .SYNOPSIS
        Updates account properties with a JSON Patch (PATCH /API/Accounts/{id}).
    .DESCRIPTION
        Use the convenience parameters, or pass -Operation with your own patch operations,
        e.g. @{ op = 'replace'; path = '/platformAccountProperties/Port'; value = '2222' }.
        -Property sets entries under /platformAccountProperties. Set a value to $null to remove it.
    .EXAMPLE
        Set-PCloudAccount -Id 12_34 -Address 'newhost.acme.local'
    .EXAMPLE
        Set-PCloudAccount -Id 12_34 -Property @{ Port = '2222'; Location = $null }
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('AccountId')][string]$Id,
        [string]$Name,
        [string]$Address,
        [string]$UserName,
        [string]$PlatformId,
        [hashtable]$Property,
        [object[]]$Operation
    )
    process {
        $ops = New-Object System.Collections.Generic.List[object]
        if ($PSBoundParameters.ContainsKey('Name')) { $ops.Add([ordered]@{ op = 'replace'; path = '/name'; value = $Name }) }
        if ($PSBoundParameters.ContainsKey('Address')) { $ops.Add([ordered]@{ op = 'replace'; path = '/address'; value = $Address }) }
        if ($PSBoundParameters.ContainsKey('UserName')) { $ops.Add([ordered]@{ op = 'replace'; path = '/userName'; value = $UserName }) }
        if ($PSBoundParameters.ContainsKey('PlatformId')) { $ops.Add([ordered]@{ op = 'replace'; path = '/platformId'; value = $PlatformId }) }
        if ($Property) {
            foreach ($key in $Property.Keys) {
                $p = '/platformAccountProperties/{0}' -f $key
                if ($null -eq $Property[$key]) {
                    $ops.Add([ordered]@{ op = 'remove'; path = $p })
                } else {
                    $ops.Add([ordered]@{ op = 'replace'; path = $p; value = [string]$Property[$key] })
                }
            }
        }
        if ($Operation) { foreach ($o in $Operation) { $ops.Add($o) } }
        if ($ops.Count -eq 0) { throw 'Nothing to update. Pass at least one property or -Operation.' }

        if ($PSCmdlet.ShouldProcess("account $Id", "Update ($($ops.Count) operation(s))")) {
            # -InputObject keeps a single-item list serialized as a JSON array.
            $json = ConvertTo-Json -InputObject @($ops.ToArray()) -Depth 10 -Compress
            Invoke-PCloudApi -Method Patch -Path ('Accounts/{0}' -f (ConvertTo-PCloudPathSegment $Id)) -Body $json
        }
    }
}

function Remove-PCloudAccount {
    <#
    .SYNOPSIS
        Deletes an account. Prompts for confirmation unless -Confirm:$false.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('AccountId')][string]$Id
    )
    process {
        if ($PSCmdlet.ShouldProcess("account $Id", 'Delete')) {
            Invoke-PCloudApi -Method Delete -Path ('Accounts/{0}' -f (ConvertTo-PCloudPathSegment $Id)) | Out-Null
        }
    }
}

function Get-PCloudAccountPassword {
    <#
    .SYNOPSIS
        Retrieves an account's password (POST /API/Accounts/{id}/Password/Retrieve).
    .DESCRIPTION
        Returns a SecureString by default. Use -AsPlainText only when you must.
        The retrieval is audited in the vault with the reason/ticket you supply.
    .EXAMPLE
        $sec = Get-PCloudAccountPassword -Id 12_34 -Reason 'Change window CHG0012345'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('AccountId')][string]$Id,
        [string]$Reason,
        [string]$TicketingSystemName,
        [string]$TicketId,
        [int]$Version = 0,
        [ValidateSet('show', 'copy', 'connect')][string]$ActionType,
        [string]$Machine,
        [switch]$IsUse,
        [switch]$AsPlainText
    )
    process {
        $body = [ordered]@{}
        if ($Reason) { $body['reason'] = $Reason }
        if ($TicketingSystemName) { $body['TicketingSystemName'] = $TicketingSystemName }
        if ($TicketId) { $body['TicketId'] = $TicketId }
        if ($Version -gt 0) { $body['Version'] = $Version }
        if ($ActionType) { $body['ActionType'] = $ActionType }
        if ($Machine) { $body['Machine'] = $Machine }
        if ($IsUse) { $body['isUse'] = $true }

        $result = Invoke-PCloudApi -Method Post -Path ('Accounts/{0}/Password/Retrieve' -f (ConvertTo-PCloudPathSegment $Id)) -Body $body
        $plain = [string]$result
        # Some responses arrive as a quoted JSON string.
        if ($plain.Length -ge 2 -and $plain.StartsWith('"') -and $plain.EndsWith('"')) {
            $plain = $plain | ConvertFrom-Json
        }
        if ($AsPlainText) {
            Write-Warning 'Returning the password as plain text. Avoid storing it in variables, files or logs.'
            return $plain
        }
        $secure = ConvertTo-PCloudSecureString $plain
        $plain = $null
        $result = $null
        return $secure
    }
}

function Invoke-PCloudAccountCredentialAction {
    # Shared implementation for Change / Verify / Reconcile.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][ValidateSet('Change', 'Verify', 'Reconcile')][string]$Action,
        [object]$Body
    )
    $path = 'Accounts/{0}/{1}' -f (ConvertTo-PCloudPathSegment $Id), $Action
    if ($null -ne $Body) {
        Invoke-PCloudApi -Method Post -Path $path -Body $Body | Out-Null
    } else {
        Invoke-PCloudApi -Method Post -Path $path -Body @{} | Out-Null
    }
    [pscustomobject]@{ AccountId = $Id; Action = $Action; Submitted = (Get-Date) }
}

function Invoke-PCloudAccountChange {
    <#
    .SYNOPSIS
        Marks the account for an immediate CPM password change (POST /API/Accounts/{id}/Change).
    .PARAMETER ChangeEntireGroup
        For accounts in an account group, change every member.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('AccountId')][string]$Id,
        [switch]$ChangeEntireGroup
    )
    process {
        if ($PSCmdlet.ShouldProcess("account $Id", 'CPM change')) {
            $body = @{}
            if ($ChangeEntireGroup) { $body['ChangeEntireGroup'] = $true }
            Invoke-PCloudAccountCredentialAction -Id $Id -Action Change -Body $body
        }
    }
}

function Invoke-PCloudAccountVerify {
    <#
    .SYNOPSIS
        Marks the account for CPM verification (POST /API/Accounts/{id}/Verify).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('AccountId')][string]$Id
    )
    process {
        if ($PSCmdlet.ShouldProcess("account $Id", 'CPM verify')) {
            Invoke-PCloudAccountCredentialAction -Id $Id -Action Verify
        }
    }
}

function Invoke-PCloudAccountReconcile {
    <#
    .SYNOPSIS
        Marks the account for CPM reconciliation using its reconcile account (POST /API/Accounts/{id}/Reconcile).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('AccountId')][string]$Id
    )
    process {
        if ($PSCmdlet.ShouldProcess("account $Id", 'CPM reconcile')) {
            Invoke-PCloudAccountCredentialAction -Id $Id -Action Reconcile
        }
    }
}

function Set-PCloudAccountNextPassword {
    <#
    .SYNOPSIS
        Sets the value the CPM will use at the next change (POST /API/Accounts/{id}/SetNextPassword).
    .PARAMETER ChangeImmediately
        Ask the CPM to change to this value now.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('AccountId')][string]$Id,
        [Parameter(Mandatory = $true)][System.Security.SecureString]$NewCredentials,
        [switch]$ChangeImmediately
    )
    process {
        if ($PSCmdlet.ShouldProcess("account $Id", 'Set next password')) {
            $body = @{
                ChangeImmediately = [bool]$ChangeImmediately
                NewCredentials    = (ConvertFrom-PCloudSecureString $NewCredentials)
            }
            try {
                Invoke-PCloudApi -Method Post -Path ('Accounts/{0}/SetNextPassword' -f (ConvertTo-PCloudPathSegment $Id)) -Body $body | Out-Null
            } finally {
                $body = $null
            }
        }
    }
}

function Set-PCloudAccountPasswordInVault {
    <#
    .SYNOPSIS
        Updates the stored password in the vault only, without changing it on the target
        (POST /API/Accounts/{id}/Password/Update).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('AccountId')][string]$Id,
        [Parameter(Mandatory = $true)][System.Security.SecureString]$NewCredentials,
        [switch]$ChangeEntireGroup
    )
    process {
        if ($PSCmdlet.ShouldProcess("account $Id", 'Update password in vault only')) {
            $body = @{
                ChangeEntireGroup = [bool]$ChangeEntireGroup
                NewCredentials    = (ConvertFrom-PCloudSecureString $NewCredentials)
            }
            try {
                Invoke-PCloudApi -Method Post -Path ('Accounts/{0}/Password/Update' -f (ConvertTo-PCloudPathSegment $Id)) -Body $body | Out-Null
            } finally {
                $body = $null
            }
        }
    }
}

function Invoke-PCloudAccountCheckIn {
    <#
    .SYNOPSIS
        Checks in (unlocks) an exclusive account (POST /API/Accounts/{id}/CheckIn).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('AccountId')][string]$Id
    )
    process {
        if ($PSCmdlet.ShouldProcess("account $Id", 'Check in')) {
            Invoke-PCloudApi -Method Post -Path ('Accounts/{0}/CheckIn' -f (ConvertTo-PCloudPathSegment $Id)) -Body @{} | Out-Null
        }
    }
}

function Add-PCloudLinkedAccount {
    <#
    .SYNOPSIS
        Links a logon or reconcile account to an account (POST /API/Accounts/{id}/LinkAccount).
    .PARAMETER ExtraPasswordIndex
        1 = Logon account, 3 = Reconcile account (other indexes are platform specific).
    .EXAMPLE
        Add-PCloudLinkedAccount -Id 12_34 -ExtraPasswordIndex 3 -LinkedSafe 'Recon' -LinkedName 'Operating System-WinDomain-acme.local-svc_recon'
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][Alias('AccountId')][string]$Id,
        [Parameter(Mandatory = $true)][int]$ExtraPasswordIndex,
        [Parameter(Mandatory = $true)][string]$LinkedSafe,
        [Parameter(Mandatory = $true)][string]$LinkedName,
        [string]$Folder = 'Root'
    )
    if ($PSCmdlet.ShouldProcess("account $Id", "Link $LinkedName (index $ExtraPasswordIndex)")) {
        $body = [ordered]@{
            safe               = $LinkedSafe
            extraPasswordIndex = $ExtraPasswordIndex
            name               = $LinkedName
            folder             = $Folder
        }
        Invoke-PCloudApi -Method Post -Path ('Accounts/{0}/LinkAccount' -f (ConvertTo-PCloudPathSegment $Id)) -Body $body | Out-Null
    }
}

function Remove-PCloudLinkedAccount {
    <#
    .SYNOPSIS
        Unlinks a linked account (DELETE /API/Accounts/{id}/LinkAccount/{extraPasswordIndex}).
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)][Alias('AccountId')][string]$Id,
        [Parameter(Mandatory = $true)][int]$ExtraPasswordIndex
    )
    if ($PSCmdlet.ShouldProcess("account $Id", "Unlink index $ExtraPasswordIndex")) {
        Invoke-PCloudApi -Method Delete -Path ('Accounts/{0}/LinkAccount/{1}' -f (ConvertTo-PCloudPathSegment $Id), $ExtraPasswordIndex) | Out-Null
    }
}
