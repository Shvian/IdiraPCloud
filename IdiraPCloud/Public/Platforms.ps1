#Requires -Version 5.1
# Platforms: /API/Platforms, /API/Platforms/Targets

function Get-PCloudPlatform {
    <#
    .SYNOPSIS
        Lists platforms (GET /API/Platforms) or gets one platform's details (GET /API/Platforms/{PlatformId}).
    .EXAMPLE
        Get-PCloudPlatform -Active $true -PlatformType Regular
    .EXAMPLE
        Get-PCloudPlatform -PlatformId 'WinDomain'
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'ById', ValueFromPipelineByPropertyName = $true)][string]$PlatformId,
        [Parameter(ParameterSetName = 'List')][Nullable[bool]]$Active,
        [Parameter(ParameterSetName = 'List')][ValidateSet('Regular', 'Group', 'Rotational')][string]$PlatformType,
        [Parameter(ParameterSetName = 'List')][string]$PlatformName
    )
    process {
        if ($PSCmdlet.ParameterSetName -eq 'ById') {
            return (Invoke-PCloudApi -Method Get -Path ('Platforms/{0}' -f (ConvertTo-PCloudPathSegment $PlatformId)))
        }
        $query = @{}
        if ($null -ne $Active) { $query['Active'] = [bool]$Active }
        if ($PlatformType) { $query['PlatformType'] = $PlatformType }
        if ($PlatformName) { $query['PlatformName'] = $PlatformName }
        $result = Invoke-PCloudApi -Method Get -Path 'Platforms' -Query $query
        if ($null -ne $result -and ($result.PSObject.Properties.Name -contains 'Platforms')) { return $result.Platforms }
        return $result
    }
}

function Get-PCloudTargetPlatform {
    <#
    .SYNOPSIS
        Lists target account platforms (GET /API/Platforms/Targets).
    .PARAMETER Filter
        Raw filter, e.g. "Active eq true" or "SystemType eq Windows".
    .EXAMPLE
        Get-PCloudTargetPlatform -Search 'Unix' -Filter 'Active eq true'
    #>
    [CmdletBinding()]
    param(
        [string]$Search,
        [string]$Filter
    )
    $query = @{}
    if ($Search) { $query['search'] = $Search }
    if ($Filter) { $query['filter'] = $Filter }
    $result = Invoke-PCloudApi -Method Get -Path 'Platforms/Targets' -Query $query
    if ($null -ne $result -and ($result.PSObject.Properties.Name -contains 'Platforms')) { return $result.Platforms }
    return $result
}

function Enable-PCloudTargetPlatform {
    <#
    .SYNOPSIS
        Activates a target platform (POST /API/Platforms/Targets/{ID}/activate). ID is the numeric platform ID.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('ID')][int]$TargetPlatformId)
    process {
        if ($PSCmdlet.ShouldProcess("target platform $TargetPlatformId", 'Activate')) {
            Invoke-PCloudApi -Method Post -Path ('Platforms/Targets/{0}/activate' -f $TargetPlatformId) -Body @{} | Out-Null
        }
    }
}

function Disable-PCloudTargetPlatform {
    <#
    .SYNOPSIS
        Deactivates a target platform (POST /API/Platforms/Targets/{ID}/deactivate).
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('ID')][int]$TargetPlatformId)
    process {
        if ($PSCmdlet.ShouldProcess("target platform $TargetPlatformId", 'Deactivate')) {
            Invoke-PCloudApi -Method Post -Path ('Platforms/Targets/{0}/deactivate' -f $TargetPlatformId) -Body @{} | Out-Null
        }
    }
}

function Copy-PCloudTargetPlatform {
    <#
    .SYNOPSIS
        Duplicates a target platform (POST /API/Platforms/Targets/{ID}/duplicate).
    .EXAMPLE
        Copy-PCloudTargetPlatform -TargetPlatformId 42 -Name 'UnixSSH-Prod' -Description 'Prod Unix policy'
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('ID')][int]$TargetPlatformId,
        [Parameter(Mandatory = $true)][string]$Name,
        [string]$Description
    )
    process {
        $body = [ordered]@{ Name = $Name }
        if ($Description) { $body['Description'] = $Description }
        if ($PSCmdlet.ShouldProcess("target platform $TargetPlatformId", "Duplicate as $Name")) {
            Invoke-PCloudApi -Method Post -Path ('Platforms/Targets/{0}/duplicate' -f $TargetPlatformId) -Body $body
        }
    }
}

function Remove-PCloudTargetPlatform {
    <#
    .SYNOPSIS
        Deletes a target platform (DELETE /API/Platforms/Targets/{ID}).
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('ID')][int]$TargetPlatformId)
    process {
        if ($PSCmdlet.ShouldProcess("target platform $TargetPlatformId", 'Delete')) {
            Invoke-PCloudApi -Method Delete -Path ('Platforms/Targets/{0}' -f $TargetPlatformId) | Out-Null
        }
    }
}

function Export-PCloudPlatform {
    <#
    .SYNOPSIS
        Exports a platform package as a zip (POST /API/Platforms/{PlatformId}/Export).
    .EXAMPLE
        Export-PCloudPlatform -PlatformId 'UnixSSH' -Path 'C:\Temp\UnixSSH.zip'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$PlatformId,
        [Parameter(Mandatory = $true)][string]$Path
    )
    process {
        $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        Invoke-PCloudApi -Method Post -Path ('Platforms/{0}/Export' -f (ConvertTo-PCloudPathSegment $PlatformId)) -OutFile $full
    }
}

function Import-PCloudPlatform {
    <#
    .SYNOPSIS
        Imports a platform package zip (POST /API/Platforms/Import). Returns the new PlatformID.
    .EXAMPLE
        Import-PCloudPlatform -Path 'C:\Temp\UnixSSH.zip'
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    if (-not (Test-Path -LiteralPath $full)) { throw "File not found: $full" }
    $bytes = [System.IO.File]::ReadAllBytes($full)
    if ($bytes.Length -gt 20MB) { throw 'Platform package exceeds the 20 MB import limit.' }
    $body = @{ ImportFile = [Convert]::ToBase64String($bytes) }
    if ($PSCmdlet.ShouldProcess($full, 'Import platform')) {
        Invoke-PCloudApi -Method Post -Path 'Platforms/Import' -Body $body
    }
}

function Resolve-PCloudTargetPlatform {
    <#
    .SYNOPSIS
        Finds a target platform by its PlatformID (e.g. 'WinDomain'), name, or numeric ID.
    .EXAMPLE
        (Resolve-PCloudTargetPlatform 'UnixSSH').ID
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true, ValueFromPipeline = $true)][string]$Platform)
    process {
        $all = @(Get-PCloudTargetPlatform)
        $hit = @($all | Where-Object { [string]$_.PlatformID -eq $Platform })
        if ($hit.Count -eq 0) { $hit = @($all | Where-Object { [string]$_.Name -eq $Platform }) }
        if ($hit.Count -eq 0) { $hit = @($all | Where-Object { [string]$_.ID -eq $Platform }) }
        if ($hit.Count -eq 0) { throw "Target platform '$Platform' was not found." }
        return $hit[0]
    }
}

function Get-PCloudPlatformLinkedAccountType {
    <#
    .SYNOPSIS
        Lists the linked-account types a platform supports (logon, enable, reconcile...) with their
        extraPasswordIndex, read from the platform details (GET /API/Platforms/{PlatformId}).
    .DESCRIPTION
        Known types map to their standard index: LogonAccount = 1, EnableAccount = 2, ReconcileAccount = 3.
        Other types are returned with ExtraPasswordIndex $null (ask the platform owner for the index).
        If the platform details can't be read, Logon and Reconcile are returned with Source 'Default'.
    .EXAMPLE
        Get-PCloudPlatformLinkedAccountType -PlatformId WinDomain
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$PlatformId)
    process {
        $known = @{ logonaccount = 1; enableaccount = 2; reconcileaccount = 3 }
        $types = @()
        try {
            $detail = Get-PCloudPlatform -PlatformId $PlatformId
            $list = $null
            foreach ($n in @('linkedAccounts', 'LinkedAccounts')) {
                if ($detail -and ($detail.PSObject.Properties.Name -contains $n)) { $list = $detail.$n; break }
            }
            foreach ($la in @($list)) {
                if ($null -eq $la) { continue }
                $name = [string]$la.Name
                if (-not $name) { continue }
                $display = [string]$la.DisplayName
                if (-not $display) { $display = $name }
                $idx = $null
                if ($known.ContainsKey($name.ToLowerInvariant())) { $idx = $known[$name.ToLowerInvariant()] }
                $types += [pscustomobject]@{ Name = $name; DisplayName = $display; ExtraPasswordIndex = $idx; Source = 'Platform' }
            }
        } catch {
            Write-Verbose ('Could not read platform {0}: {1}' -f $PlatformId, $_.Exception.Message)
        }
        if ($types.Count -eq 0) {
            $types = @(
                [pscustomobject]@{ Name = 'LogonAccount'; DisplayName = 'Logon Account'; ExtraPasswordIndex = 1; Source = 'Default' },
                [pscustomobject]@{ Name = 'ReconcileAccount'; DisplayName = 'Reconcile Account'; ExtraPasswordIndex = 3; Source = 'Default' }
            )
        }
        $types
    }
}

function Get-PCloudDependentPlatform {
    <#
    .SYNOPSIS
        Lists dependent platforms (GET /API/Platforms/Dependents), for example Windows Service or Scheduled Task.
    #>
    [CmdletBinding()]
    param([string]$Search)
    $q = @{}
    if ($Search) { $q['search'] = $Search }
    $r = Invoke-PCloudApi -Method Get -Path 'Platforms/Dependents' -Query $q
    if ($null -eq $r) { return }
    foreach ($n in @('Platforms', 'platforms', 'value')) {
        if ($r.PSObject.Properties.Name -contains $n) { return @($r.$n) }
    }
    return @($r)
}
