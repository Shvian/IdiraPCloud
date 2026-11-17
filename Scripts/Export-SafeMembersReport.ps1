#Requires -Version 5.1
<#
.SYNOPSIS
    Exports every safe's members and their permissions to CSV (one row per safe/member).
.EXAMPLE
    .\Export-SafeMembersReport.ps1 -OutputPath .\safe-members.csv
.EXAMPLE
    .\Export-SafeMembersReport.ps1 -Search 'Prod' -IncludePredefinedUsers
#>
[CmdletBinding()]
param(
    # Default: CSVs\PCloud-SafeMembers-<timestamp>.csv in the IdiraPCloud folder. A bare file name also goes there.
    [string]$OutputPath,
    [string]$Search,
    [switch]$IncludePredefinedUsers,
    [string]$IdentityUrl,
    [string]$Subdomain,
    [string]$PCloudUrl,
    [System.Management.Automation.PSCredential]$Credential,
    [ValidateSet('ServiceUser', 'Interactive')][string]$AuthMethod,

    # -Log records the run (screen output and what you type at normal prompts) to Logs\ in the IdiraPCloud folder.
    [switch]$Log,
    [string]$LogPath
)

. (Join-Path $PSScriptRoot '_Common.ps1')
if ($Log -and -not $global:PCloudLogActive) { Invoke-PCloudLogged -ScriptPath $PSCommandPath -Bound $PSBoundParameters -Path $LogPath; return }
if ($OutputPath) { $OutputPath = Resolve-PCloudOutputPath $OutputPath } else { $OutputPath = New-PCloudOutputFile -Name 'SafeMembers' }
Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod

$sp = @{}
if ($Search) { $sp['Search'] = $Search }
$safes = @(Get-PCloudSafe @sp)
$permNames = (Get-PCloudSafePermissionSet -Preset None).Keys

$rows = New-Object System.Collections.Generic.List[object]
$i = 0
foreach ($safe in $safes) {
    $i++
    Write-Progress -Activity 'Reading safe members' -Status $safe.safeName -PercentComplete (($i / [Math]::Max($safes.Count, 1)) * 100)
    try {
        $mp = @{ SafeName = $safe.safeName }
        if ($IncludePredefinedUsers) { $mp['IncludePredefinedUsers'] = $true }
        $members = @(Get-PCloudSafeMember @mp)
    } catch {
        Write-Warning ("{0}: {1}" -f $safe.safeName, $_.Exception.Message)
        continue
    }
    foreach ($m in $members) {
        $row = [ordered]@{
            SafeName       = $safe.safeName
            ManagingCPM    = $safe.managingCPM
            MemberName     = $m.memberName
            MemberType     = (Resolve-PCloudSafeMemberType -MemberName $m.memberName -ReportedType $m.memberType).MemberType
            ApiMemberType  = $m.memberType
            Preset         = (Get-PCloudSafePermissionPreset -Permissions $m.permissions).Label
            IsPredefined   = $m.isPredefinedUser
            IsReadOnly     = $m.isReadOnly
            ExpirationDate = ConvertFrom-PCloudUnixTime $m.membershipExpirationDate
        }
        foreach ($n in $permNames) {
            $v = $null
            if ($m.permissions) { $v = $m.permissions.$n }
            $row[$n] = $v
        }
        $rows.Add([pscustomobject]$row)
    }
}
Write-Progress -Activity 'Reading safe members' -Completed

$rows | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host ("Exported {0} membership row(s) across {1} safe(s) to {2}" -f $rows.Count, $safes.Count, (Resolve-Path -LiteralPath $OutputPath))
