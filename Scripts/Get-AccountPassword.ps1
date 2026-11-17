#Requires -Version 5.1
<#
.SYNOPSIS
    Retrieves a password from Privilege Cloud with a reason/ticket and copies it to the clipboard.
.DESCRIPTION
    Finds the account by ID, or by safe + user name (+ address). The retrieval is audited.
    Default: the password is put on the clipboard and cleared after -ClearAfterSeconds (5-300),
    including when you press Ctrl+C. Windows clipboard history (Win+V) and clipboard sync can
    keep copies; the script warns if clipboard history is on. Turn it off for privileged work.
    -PassThru returns a SecureString and never exposes the plain value (the safest option for scripts).
    -Show prints it on screen (not recommended: it can be captured by transcripts or screen sharing);
    the screen is cleared when you press Enter.
.EXAMPLE
    .\Get-AccountPassword.ps1 -SafeName 'Linux-Root' -UserName root -Address 10.0.0.5 -Reason 'CHG0012345'
.EXAMPLE
    $sec = .\Get-AccountPassword.ps1 -AccountId 12_34 -Reason 'Script run' -PassThru
#>
[CmdletBinding(DefaultParameterSetName = 'ById')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'ById')][string]$AccountId,
    [Parameter(Mandatory = $true, ParameterSetName = 'Lookup')][string]$SafeName,
    [Parameter(Mandatory = $true, ParameterSetName = 'Lookup')][string]$UserName,
    [Parameter(ParameterSetName = 'Lookup')][string]$Address,
    [Parameter(Mandatory = $true)][string]$Reason,
    [string]$TicketingSystemName,
    [string]$TicketId,
    [ValidateRange(5, 300)][int]$ClearAfterSeconds = 30,
    [switch]$Show,
    [switch]$PassThru,
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
Connect-PCloudIfNeeded -IdentityUrl $IdentityUrl -Subdomain $Subdomain -PCloudUrl $PCloudUrl -Credential $Credential -AuthMethod $AuthMethod

if ($PSCmdlet.ParameterSetName -eq 'Lookup') {
    $search = (@($UserName, $Address) | Where-Object { $_ }) -join ' '
    $found = @(Get-PCloudAccount -SafeName $SafeName -Search $search | Where-Object {
            $_.userName -eq $UserName -and (-not $Address -or $_.address -eq $Address)
        })
    if ($found.Count -eq 0) { throw "No account found for $UserName in safe $SafeName." }
    if ($found.Count -gt 1) {
        $found | Select-Object id, name, userName, address, platformId | Format-Table -AutoSize | Out-String | Write-Host
        throw 'More than one account matched. Add -Address or use -AccountId.'
    }
    $AccountId = $found[0].id
}

$p = @{ Id = $AccountId; Reason = $Reason }
if ($TicketingSystemName) { $p['TicketingSystemName'] = $TicketingSystemName }
if ($TicketId) { $p['TicketId'] = $TicketId }

if ($PassThru) {
    # SecureString only; the plain value is never returned.
    return (Get-PCloudAccountPassword @p)
}

function Clear-SensitiveClipboard {
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        [System.Windows.Forms.Clipboard]::Clear()
    } catch {
        Set-Clipboard -Value ' '
    }
}

function Test-ClipboardHistoryEnabled {
    try {
        $v = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Clipboard' -Name 'EnableClipboardHistory' -ErrorAction Stop
        return ($v.EnableClipboardHistory -eq 1)
    } catch { return $false }
}

$secure = Get-PCloudAccountPassword @p
$bstr = [IntPtr]::Zero
try {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    if ($Show) {
        Write-Warning 'Displaying a privileged password on screen. Make sure no one can see it and no transcript is running.'
        Write-Host ([Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr))
        Read-Host 'Press Enter to clear the screen' | Out-Null
        Clear-Host
    } else {
        if (Test-ClipboardHistoryEnabled) {
            Write-Warning 'Windows clipboard history is on, so it may keep a copy of this password. Turn it off in Settings > System > Clipboard.'
        }
        Set-Clipboard -Value ([Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr))
        Write-Host "Password for account $AccountId copied to the clipboard. It will be cleared in $ClearAfterSeconds seconds."
        try {
            Start-Sleep -Seconds $ClearAfterSeconds
        } finally {
            # Runs even if the user presses Ctrl+C.
            Clear-SensitiveClipboard
            Write-Host 'Clipboard cleared.'
        }
    }
} finally {
    if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    $secure.Dispose()
}
