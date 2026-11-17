#Requires -Version 5.1
# PSM servers and platform PSM assignment:
#   GET /API/PSM/Servers
#   GET/PUT /API/Platforms/Targets/{ID}/PrivilegedSessionManagement

function Get-PCloudPSMServer {
    <#
    .SYNOPSIS
        Lists PSM servers (GET /API/PSM/Servers).
    #>
    [CmdletBinding()]
    param()
    $r = Invoke-PCloudApi -Method Get -Path 'PSM/Servers'
    if ($null -eq $r) { return }
    if ($r.PSObject.Properties.Name -contains 'PSMServers') { return @($r.PSMServers) }
    if ($r.PSObject.Properties.Name -contains 'value') { return @($r.value) }
    return @($r)
}

function Get-PCloudPlatformPSMConfig {
    <#
    .SYNOPSIS
        Gets the PSM server and connection components assigned to a target platform.
    .PARAMETER TargetPlatformId
        The numeric target platform ID (the ID property from Get-PCloudTargetPlatform).
    .EXAMPLE
        Get-PCloudTargetPlatform | Where-Object PlatformID -eq 'WinDomain' | Get-PCloudPlatformPSMConfig
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('ID')][int]$TargetPlatformId)
    process {
        Invoke-PCloudApi -Method Get -Path ('Platforms/Targets/{0}/PrivilegedSessionManagement' -f $TargetPlatformId)
    }
}

function Set-PCloudPlatformPSMConfig {
    <#
    .SYNOPSIS
        Sets the PSM server and connection components of a target platform
        (PUT /API/Platforms/Targets/{ID}/PrivilegedSessionManagement).
    .PARAMETER PSMConnectors
        Objects or hashtables with PSMConnectorID and Enabled. This replaces the platform's list.
    .EXAMPLE
        Set-PCloudPlatformPSMConfig -TargetPlatformId 42 -PSMServerId 'PSMServer_abc' -PSMConnectors @(@{ PSMConnectorID = 'PSM-RDP'; Enabled = $true })
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][Alias('ID')][int]$TargetPlatformId,
        [Parameter(Mandatory = $true)][string]$PSMServerId,
        [Parameter(Mandatory = $true)][object[]]$PSMConnectors
    )
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($c in $PSMConnectors) {
        $id = $null; $en = $true
        if ($c -is [System.Collections.IDictionary]) { $id = $c['PSMConnectorID']; if ($c.Contains('Enabled')) { $en = [bool]$c['Enabled'] } }
        else { $id = $c.PSMConnectorID; if ($c.PSObject.Properties.Name -contains 'Enabled') { $en = [bool]$c.Enabled } }
        if ($id) { $list.Add([ordered]@{ PSMConnectorID = [string]$id; Enabled = $en }) }
    }
    $body = [ordered]@{ PSMServerID = $PSMServerId; PSMConnectors = $list.ToArray() }
    if ($PSCmdlet.ShouldProcess("target platform $TargetPlatformId", "Set PSM server $PSMServerId and $($list.Count) connector(s)")) {
        $json = ConvertTo-Json -InputObject $body -Depth 6 -Compress
        Invoke-PCloudApi -Method Put -Path ('Platforms/Targets/{0}/PrivilegedSessionManagement' -f $TargetPlatformId) -Body $json
    }
}
