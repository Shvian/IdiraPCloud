#Requires -Version 5.1
# Vault locations (the folders that hold users and applications, such as \ or \Applications) - Gen 1 Web Services:
#   GET    /PasswordVault/WebServices/PIMServices.svc/Locations
#   POST   .../Locations                 { Name, ParentLocation }
#   PUT    .../Locations/{LocationID}    { Name, ParentLocation }   (rename and/or move)
#   DELETE .../Locations/{LocationID}    (the location must be empty)
# Responses are read defensively: the list may come back as Locations, GetLocationsResult or a bare array,
# and each item's path as FullPath or Name.

function Invoke-PCloudLocationApi {
    param([string]$Method = 'Get', [string]$SubPath = '', $Body)
    $p = @{ Generation = 1; Method = $Method; Path = ('PIMServices.svc/Locations{0}' -f $SubPath) }
    if ($PSBoundParameters.ContainsKey('Body')) { $p['Body'] = $Body }
    Invoke-PCloudApi @p
}

function ConvertTo-PCloudLocationPath {
    # '\Apps\Batch' form: one leading backslash, no trailing one ('\' for the root).
    param([string]$Path)
    $p = ([string]$Path).Trim() -replace '/', '\'
    $p = $p -replace '\\{2,}', '\'
    if (-not $p.StartsWith('\')) { $p = '\' + $p }
    if ($p.Length -gt 1) { $p = $p.TrimEnd('\') }
    return $p
}

function Get-PCloudLocation {
    <#
    .SYNOPSIS
        Lists Vault locations, as objects { FullPath, Name, ParentPath, LocationID, ParentLocationID }.
    .PARAMETER Search
        Only locations whose path contains this text.
    .PARAMETER Path
        The one location with exactly this path (for example \Applications).
    .EXAMPLE
        Get-PCloudLocation
    .EXAMPLE
        Get-PCloudLocation -Path '\Applications'
    #>
    [CmdletBinding()]
    param([string]$Search, [string]$Path)
    $r = Invoke-PCloudLocationApi
    $items = @()
    if ($null -ne $r) {
        if ($r -is [array]) { $items = @($r) }
        else {
            foreach ($prop in @('Locations', 'GetLocationsResult', 'value', 'locations')) {
                if ($r.PSObject.Properties.Name -contains $prop) { $items = @($r.$prop); break }
            }
            if ($items.Count -eq 0 -and ($r.PSObject.Properties.Name -contains 'LocationID')) { $items = @($r) }
        }
    }
    $byId = @{}
    $out = foreach ($i in $items) {
        if ($null -eq $i) { continue }
        $full = [string]$i.FullPath
        if (-not $full) { $full = [string]$i.Name }
        $full = ConvertTo-PCloudLocationPath $full
        $name = ($full -split '\\')[-1]
        if ($full -eq '\') { $name = '\' }
        $parent = '\'
        $idx = $full.LastIndexOf('\')
        if ($idx -gt 0) { $parent = $full.Substring(0, $idx) }
        $o = [pscustomobject]@{
            FullPath         = $full
            Name             = $name
            ParentPath       = $parent
            LocationID       = [string]$i.LocationID
            ParentLocationID = [string]$i.ParentLocationID
        }
        $byId[$o.LocationID] = $o
        $o
    }
    $out = @($out | Sort-Object FullPath)
    if ($Path) { $want = ConvertTo-PCloudLocationPath $Path; return @($out | Where-Object { $_.FullPath -eq $want }) }
    if ($Search) {
        $pattern = '*{0}*' -f [System.Management.Automation.WildcardPattern]::Escape($Search)
        return @($out | Where-Object { $_.FullPath -like $pattern })
    }
    return $out
}

function New-PCloudLocation {
    <#
    .SYNOPSIS
        Adds a Vault location (POST .../Locations).
    .PARAMETER Path
        The full path of the new location, for example \Applications or \Applications\Batch.
        The parent must exist already.
    .EXAMPLE
        New-PCloudLocation -Path '\Applications'
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('FullPath')][string]$Path)
    process {
        $full = ConvertTo-PCloudLocationPath $Path
        if ($full -eq '\') { throw 'The root location \ always exists.' }
        $idx = $full.LastIndexOf('\')
        $name = $full.Substring($idx + 1)
        $parent = '\'
        if ($idx -gt 0) { $parent = $full.Substring(0, $idx) }
        if ($name -match '[\\/:*?"<>|]') { throw ("'{0}' is not a valid location name." -f $name) }
        $body = [ordered]@{ Name = $name; ParentLocation = $parent }
        if ($PSCmdlet.ShouldProcess("location $full", 'Add location')) {
            Invoke-PCloudLocationApi -Method Post -Body $body | Out-Null
            Get-PCloudLocation -Path $full
        }
    }
}

function Set-PCloudLocation {
    <#
    .SYNOPSIS
        Renames and/or moves a Vault location (PUT .../Locations/{LocationID}).
    .PARAMETER Path
        The location's current full path.
    .PARAMETER NewName
        New name (the last part of the path). Leave out to keep the name.
    .PARAMETER NewParent
        New parent path, to move the location. Leave out to keep it where it is.
    .EXAMPLE
        Set-PCloudLocation -Path '\Apps' -NewName 'Applications'
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('FullPath')][string]$Path,
        [string]$NewName,
        [string]$NewParent
    )
    process {
        $loc = @(Get-PCloudLocation -Path $Path)
        if ($loc.Count -eq 0) { throw ("Location '{0}' was not found." -f $Path) }
        $loc = $loc[0]
        if ($loc.FullPath -eq '\') { throw 'The root location cannot be renamed or moved.' }
        $name = $loc.Name
        if ($NewName) { $name = $NewName.Trim() }
        if ($name -match '[\\/:*?"<>|]') { throw ("'{0}' is not a valid location name." -f $name) }
        $parent = $loc.ParentPath
        if ($PSBoundParameters.ContainsKey('NewParent') -and $NewParent) { $parent = ConvertTo-PCloudLocationPath $NewParent }
        if ($parent -eq $loc.FullPath -or $parent.StartsWith($loc.FullPath + '\')) { throw 'A location cannot be moved into itself.' }
        $body = [ordered]@{ Name = $name; ParentLocation = $parent }
        $target = ConvertTo-PCloudLocationPath ('{0}\{1}' -f $parent, $name)
        if ($PSCmdlet.ShouldProcess("location $($loc.FullPath)", "Change to $target")) {
            Invoke-PCloudLocationApi -Method Put -SubPath ('/{0}' -f (ConvertTo-PCloudPathSegment $loc.LocationID)) -Body $body | Out-Null
            Get-PCloudLocation -Path $target
        }
    }
}

function Remove-PCloudLocation {
    <#
    .SYNOPSIS
        Deletes an empty Vault location (DELETE .../Locations/{LocationID}).
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('FullPath')][string]$Path)
    process {
        $loc = @(Get-PCloudLocation -Path $Path)
        if ($loc.Count -eq 0) { throw ("Location '{0}' was not found." -f $Path) }
        $loc = $loc[0]
        if ($loc.FullPath -eq '\') { throw 'The root location cannot be deleted.' }
        if ($PSCmdlet.ShouldProcess("location $($loc.FullPath)", 'Delete location')) {
            Invoke-PCloudLocationApi -Method Delete -SubPath ('/{0}' -f (ConvertTo-PCloudPathSegment $loc.LocationID)) | Out-Null
        }
    }
}
