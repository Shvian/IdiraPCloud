#Requires -Version 5.1
# System health: /API/ComponentsMonitoringSummary, /API/ComponentsMonitoringDetails/{ComponentID}
# Session monitoring: /API/LiveSessions, /API/Recordings

function Get-PCloudSystemHealth {
    <#
    .SYNOPSIS
        Gets the component health summary, or the details for one component type.
    .PARAMETER ComponentId
        PVWA, SessionManagement (PSM), CPM, AIM (Credential Providers) or PTA.
    .EXAMPLE
        Get-PCloudSystemHealth
    .EXAMPLE
        Get-PCloudSystemHealth -ComponentId CPM
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('PVWA', 'SessionManagement', 'CPM', 'AIM', 'PTA')][string]$ComponentId
    )
    if ($ComponentId) {
        $result = Invoke-PCloudApi -Method Get -Path ('ComponentsMonitoringDetails/{0}' -f $ComponentId)
        if ($null -ne $result -and ($result.PSObject.Properties.Name -contains 'ComponentsDetails')) { return $result.ComponentsDetails }
        return $result
    }
    $summary = Invoke-PCloudApi -Method Get -Path 'ComponentsMonitoringSummary'
    if ($null -ne $summary -and ($summary.PSObject.Properties.Name -contains 'Components')) { return $summary.Components }
    return $summary
}

function Get-PCloudOffsetPaged {
    # Internal: pages endpoints that use Offset/Limit with a named collection and Total.
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$CollectionProperty,
        [hashtable]$Query,
        [int]$PageSize = 100,
        [int]$First = 0
    )
    $offset = 0
    $count = 0
    while ($true) {
        $q = @{}
        if ($Query) { foreach ($k in $Query.Keys) { $q[$k] = $Query[$k] } }
        $q['Offset'] = $offset
        $q['Limit'] = $PageSize
        $page = Invoke-PCloudApi -Method Get -Path $Path -Query $q
        if ($null -eq $page) { break }
        $items = @()
        if ($page.PSObject.Properties.Name -contains $CollectionProperty) { $items = @($page.$CollectionProperty) }
        foreach ($i in $items) {
            $i
            $count++
            if ($First -gt 0 -and $count -ge $First) { return }
        }
        $total = 0
        if ($page.PSObject.Properties.Name -contains 'Total') { $total = [int]$page.Total }
        $offset += $items.Count
        if ($items.Count -lt $PageSize -or ($total -gt 0 -and $offset -ge $total)) { break }
    }
}

function Get-PCloudLiveSession {
    <#
    .SYNOPSIS
        Lists active PSM sessions (GET /API/LiveSessions).
    .EXAMPLE
        Get-PCloudLiveSession -Search 'root'
    #>
    [CmdletBinding()]
    param(
        [string]$Search,
        [string]$Safe,
        [datetime]$FromTime,
        [datetime]$ToTime,
        [int]$First = 0
    )
    $q = @{}
    if ($Search) { $q['Search'] = $Search }
    if ($Safe) { $q['Safe'] = $Safe }
    if ($PSBoundParameters.ContainsKey('FromTime')) { $q['FromTime'] = ConvertTo-PCloudUnixTime $FromTime }
    if ($PSBoundParameters.ContainsKey('ToTime')) { $q['ToTime'] = ConvertTo-PCloudUnixTime $ToTime }
    Get-PCloudOffsetPaged -Path 'LiveSessions' -CollectionProperty 'LiveSessions' -Query $q -First $First
}

function Stop-PCloudLiveSession {
    <#
    .SYNOPSIS
        Terminates an active PSM session (POST /API/LiveSessions/{SessionId}/Terminate).
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$SessionId)
    process {
        if ($PSCmdlet.ShouldProcess("session $SessionId", 'Terminate')) {
            Invoke-PCloudApi -Method Post -Path ('LiveSessions/{0}/Terminate' -f (ConvertTo-PCloudPathSegment $SessionId)) -Body @{} | Out-Null
        }
    }
}

function Get-PCloudRecording {
    <#
    .SYNOPSIS
        Lists PSM session recordings (GET /API/Recordings).
    .EXAMPLE
        Get-PCloudRecording -FromTime (Get-Date).AddDays(-1) -Safe 'Linux-Root'
    #>
    [CmdletBinding()]
    param(
        [string]$Search,
        [string]$Safe,
        [datetime]$FromTime,
        [datetime]$ToTime,
        [int]$First = 0
    )
    $q = @{}
    if ($Search) { $q['Search'] = $Search }
    if ($Safe) { $q['Safe'] = $Safe }
    if ($PSBoundParameters.ContainsKey('FromTime')) { $q['FromTime'] = ConvertTo-PCloudUnixTime $FromTime }
    if ($PSBoundParameters.ContainsKey('ToTime')) { $q['ToTime'] = ConvertTo-PCloudUnixTime $ToTime }
    Get-PCloudOffsetPaged -Path 'Recordings' -CollectionProperty 'Recordings' -Query $q -First $First
}
