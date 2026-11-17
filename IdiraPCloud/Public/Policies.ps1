#Requires -Version 5.1
# Master Policy. Privilege Cloud has no Gen 2 Master Policy endpoint (/API/Policies/1 is self-hosted PAM
# only); its master policy is the Gen 3 master rotation policy (see RotationPolicy.ps1).

function Get-PCloudMasterPolicy {
    <#
    .SYNOPSIS
        Gets the Privilege Cloud master policy: the Gen 3 master rotation policy (verify and change
        intervals, exception counts, created/updated by and when). Same as Get-PCloudMasterRotationPolicy.
    #>
    [CmdletBinding()]
    param()
    Get-PCloudMasterRotationPolicy
}

function ConvertTo-PCloudFlatSetting {
    <#
    .SYNOPSIS
        Flattens a nested API object into Setting/Value rows (for reports and CSV export).
    .EXAMPLE
        Get-PCloudMasterPolicy | ConvertTo-PCloudFlatSetting
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][AllowNull()][AllowEmptyString()][AllowEmptyCollection()]$InputObject,
        [string]$Prefix = ''
    )
    process {
        if ($null -eq $InputObject) {
            [pscustomobject]@{ Setting = $Prefix; Value = $null }
            return
        }
        if ($InputObject -is [string] -or $InputObject -is [ValueType]) {
            [pscustomobject]@{ Setting = $Prefix; Value = $InputObject }
            return
        }
        if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [System.Collections.IDictionary])) {
            $items = @($InputObject)
            if ($items.Count -eq 0) { [pscustomobject]@{ Setting = $Prefix; Value = '' }; return }
            $allSimple = $true
            foreach ($it in $items) { if (-not ($null -eq $it -or $it -is [string] -or $it -is [ValueType])) { $allSimple = $false; break } }
            if ($allSimple) { [pscustomobject]@{ Setting = $Prefix; Value = ($items -join '; ') }; return }
            for ($i = 0; $i -lt $items.Count; $i++) {
                ConvertTo-PCloudFlatSetting -InputObject $items[$i] -Prefix ('{0}[{1}]' -f $Prefix, $i)
            }
            return
        }
        $props = @()
        if ($InputObject -is [System.Collections.IDictionary]) {
            foreach ($k in $InputObject.Keys) { $props += [pscustomobject]@{ Name = [string]$k; Value = $InputObject[$k] } }
        } else {
            foreach ($p in $InputObject.PSObject.Properties) { $props += [pscustomobject]@{ Name = $p.Name; Value = $p.Value } }
        }
        foreach ($p in $props) {
            $name = $p.Name
            if ($Prefix) { $name = '{0}.{1}' -f $Prefix, $p.Name }
            ConvertTo-PCloudFlatSetting -InputObject $p.Value -Prefix $name
        }
    }
}
