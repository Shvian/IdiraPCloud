#Requires -Version 5.1
# Public helpers.

function ConvertFrom-PCloudUnixTime {
    <#
    .SYNOPSIS
        Converts Unix epoch seconds (or milliseconds/microseconds) from Privilege Cloud to a local DateTime.
    #>
    param($Seconds)
    if ($null -eq $Seconds -or [string]$Seconds -eq '') { return $null }
    $n = 0.0
    if (-not [double]::TryParse([string]$Seconds, [ref]$n) -or $n -le 0) { return $null }
    # Some endpoints return milliseconds or microseconds (e.g. safe lastModificationTime).
    if ($n -gt 1e14) { $n = $n / 1e6 } elseif ($n -gt 1e11) { $n = $n / 1e3 }
    $epoch = New-Object DateTime 1970, 1, 1, 0, 0, 0, ([DateTimeKind]::Utc)
    return $epoch.AddSeconds($n).ToLocalTime()
}

function ConvertTo-PCloudUnixTime {
    <#
    .SYNOPSIS
        Converts a DateTime to Unix epoch seconds.
    #>
    param([datetime]$Date)
    $epoch = New-Object DateTime 1970, 1, 1, 0, 0, 0, ([DateTimeKind]::Utc)
    return [long][Math]::Floor(($Date.ToUniversalTime() - $epoch).TotalSeconds)
}
