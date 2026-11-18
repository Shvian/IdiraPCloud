# IdiraPCloud: PowerShell 5.1 scripts for Idira Privilege Cloud

A PowerShell module and a set of task scripts for the Idira (formerly CyberArk) Privilege Cloud REST API. Everything is written for **Windows PowerShell 5.1**. It uses no PowerShell 7 syntax (no `??`, `?.`, ternary, `&&`/`||`, `-Parallel`, `-SkipCertificateCheck` or `-AsHashtable`), forces TLS 1.2, and sends request bodies as UTF-8 bytes so 5.1 doesn't garble non-ASCII characters.

```
IdiraPCloud\
  IdiraPCloud\              <- the module (Import-Module this folder's .psd1)
    IdiraPCloud.psd1 / .psm1
    Private\Core.ps1        session state, URL building, request/retry/error handling
    Private\Auth.ps1        Identity token request and auto-refresh
    Public\Session.ps1      New/Get/Remove-PCloudSession, Invoke-PCloudApi (generic + paging)
    Public\Accounts.ps1     accounts, password retrieve, change/verify/reconcile, linked accounts
    Public\Safes.ps1        safes, safe members, permission presets
    Public\Platforms.ps1    platforms, target platforms, import/export, platform lookup
    Public\PSM.ps1          PSM servers and the PSM server/connectors assigned to platforms
    Public\Policies.ps1     Master Policy (read only) and a nested-settings flattener
    Public\UsersGroups.ps1  vault users and vault groups
    Public\Monitoring.ps1   system health, live PSM sessions, recordings
    Public\Helpers.ps1      Unix time conversion
  Start-IdiraPCloud.ps1     main menu: sign in once, then pick safes, accounts, platforms, PSM, ...
  Scripts\                  ready-to-run task scripts (use the module)
  Tests\Test-PS51Syntax.ps1 parse check + module load test (no API calls)
```

## URLs and authentication

**You only need the subdomain.** That's the `acme` in `acme.cyberark.cloud`, and a full URL works too. If you leave it out, you're asked for it. The module finds the Identity tenant by following the redirect from `https://<subdomain>.cyberark.cloud/`, and takes the first `<tenant>.id.cyberark.cloud` host it reaches. If that fails, it asks the platform discovery service (`platform-discovery.cyberark.cloud/api/v2/services/subdomain/<subdomain>`). Pass `-IdentityUrl` only to override that. Add `-Verbose` to see which tenant was found.

The Privilege Cloud API base is `https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/`. Every call carries `Authorization: Bearer <token>`, and you choose how to get the token with `New-PCloudSession -AuthMethod`:

| `-AuthMethod` | Who signs in | Identity endpoint | Renewal |
|---|---|---|---|
| `ServiceUser` (default) | Identity service user with OAuth2 client credentials | `POST /oauth2/platformtoken` | Automatic, before expiry (new token from the stored secret) |
| `OAuthApp` | Custom Identity OAuth2 server web app (`-AppId`) | `POST /oauth2/token/<AppId>` | Automatic, before expiry (new token from the stored secret) |
| `Interactive` | Any Identity user, with any sign-in method the policy allows: password, mobile app push, authenticator code, SMS, email, phone call, security question or RADIUS | `POST /Security/StartAuthentication`, then `/Security/AdvanceAuthentication` | Silent, using the Identity refresh token; asks you to sign in again only if that's refused |
| `AccessToken` | A token you already have | none | None |

If you leave out `-AuthMethod`, it's picked for you: `-AccessToken` means `AccessToken`, `-AppId` means `OAuthApp`, and anything else means `ServiceUser`.

**ServiceUser requirements:** the user must be ticked **Is Service User** and **Is OAuth confidential client** in Identity Administration. Sign in with the full name including its suffix (for example `svc-api@acme.com.1234`), and give it a Privilege Cloud role and the safes it needs. A plain interactive user gets `HTTP 400 invalid client creds or client not allowed`.

**Interactive:** each MFA step is handled in the console. When several methods are offered you get a numbered menu, unless `-PreferredMechanism` picks one for you. Mechanism names are `UP` (password), `OTP` (mobile app push), `OATH` (authenticator code), `SMS`, `EMAIL`, `PF` (phone call), `SQ` and `RADIUS`. If you pass `-Credential`, its password answers the password step, so you're only asked for MFA. Pushes, SMS and email are polled for approval for up to `-MfaTimeoutSec` (180 by default), and for SMS and email you can type the code instead. Pod redirects (`PodFqdn`) are followed. Users federated through a SAML provider need a browser, so they can't use this method.

### Token renewal during long scripts

Before every API call, the module checks when the token expires and renews it if it's within `-RefreshThresholdSec` seconds of expiry (120 by default). It reads the expiry from `expires_in`, or from the token's own `exp` claim. So a script that runs for hours keeps working without you doing anything:

| Method | How it renews |
|---|---|
| `ServiceUser`, `OAuthApp` | Client credentials don't come with refresh tokens, so it requests a fresh token with the stored secret. Nothing is asked of you. |
| `Interactive` | It uses the Identity refresh token (`POST /OAuth2/RefreshToken/__idaptive_cybr_user_oidc`, with the sign-in cookies). If Identity refuses, it warns and asks you to sign in again, then carries on. |
| `AccessToken` | It can't renew. You get a warning if the token you supplied has already expired. |

If a call still returns 401, the module renews once and retries that call. `Get-PCloudSession` shows `ExpiresAt`, `LastRenewed` and `RefreshTokenAvailable`. Before a long stretch with no API calls, run `Update-PCloudSession` to renew if the token is close to expiry, or `Update-PCloudSession -Force` to renew now.

```powershell
New-PCloudSession -AuthMethod Interactive -Subdomain acme -UserName jdoe@acme.com -RefreshThresholdSec 300
Update-PCloudSession -Force -Verbose
Get-PCloudSession | Format-List
```

For all methods, calls that return HTTP 429, 502, 503 or 504 are retried with exponential backoff (2, 4 and 8 seconds).

## Quick start

```powershell
# One-time: allow local scripts for your user if needed
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
# If you downloaded the zip, unblock the files so RemoteSigned lets them run
Get-ChildItem C:\Tools\IdiraPCloud -Recurse | Unblock-File

Import-Module C:\Tools\IdiraPCloud\IdiraPCloud\IdiraPCloud.psd1

# Service user (OAuth2 client credentials)
$cred = Get-Credential 'svc-pcloud-api@acme.com.1234'
New-PCloudSession -Subdomain 'acme' -Credential $cred

# ...or yourself, with whatever MFA your policy requires
New-PCloudSession -AuthMethod Interactive -Subdomain 'acme' -UserName 'jdoe@acme.com'

Get-PCloudSafe | Select-Object safeName, managingCPM
Get-PCloudAccount -SafeName 'Linux-Root' | Select-Object id, userName, address, platformId
```

Other ways to connect:

```powershell
# Your URL doesn't follow the standard pattern (the subdomain is read from it)
New-PCloudSession -PCloudUrl https://acme.privilegecloud.cyberark.cloud/PasswordVault -Credential $cred

# Interactive: password from a credential, mobile push chosen automatically
New-PCloudSession -AuthMethod Interactive -Subdomain acme -Credential (Get-Credential jdoe@acme.com) -PreferredMechanism OTP, OATH

# Identity custom OAuth2 web app
New-PCloudSession -AuthMethod OAuthApp -Subdomain acme -Credential $clientCred -AppId 'pcloud-automation' -Scope 'all'

# Skip discovery by giving the Identity tenant yourself
New-PCloudSession -Subdomain acme -IdentityUrl https://abc1234.id.cyberark.cloud -Credential $cred

# Token you already have (no auto-renewal)
New-PCloudSession -AuthMethod AccessToken -Subdomain acme -AccessToken (Read-Host 'Token' -AsSecureString)

# Through a corporate proxy
New-PCloudSession ... -Proxy http://proxy.acme.local:8080 -ProxyUseDefaultCredentials
```

Run `Get-PCloudSession` to see the connection and token expiry. `Remove-PCloudSession` clears the token and credential from memory.

## Commands

Every command has comment-based help, so `Get-Help New-PCloudAccount -Full` shows the parameters and examples. Commands that change something support `-WhatIf` and `-Confirm`. Deletes and other destructive commands always ask for confirmation unless you pass `-Confirm:$false`.

### Accounts (`/API/Accounts`)

| Command | Endpoint |
|---|---|
| `Get-PCloudAccount [-Search] [-SearchType] [-SafeName] [-Filter] [-Sort] [-First]` | `GET /Accounts` (follows every page) |
| `Get-PCloudAccount -Id 12_34` | `GET /Accounts/{id}` |
| `New-PCloudAccount` | `POST /Accounts` |
| `Set-PCloudAccount -Id … [-Name] [-Address] [-UserName] [-PlatformId] [-Property @{}] [-Operation]` | `PATCH /Accounts/{id}` (JSON Patch). Platform properties are sent as one `{"op":"add","path":"/platformaccountproperties","value":{"Name":"value"}}` operation; removals use `"op":"remove"` with a `null` value |
| `New-PCloudAccountPropertyOperation -Set @{} -Remove @()` | Builds those platform property operations for `-Operation` |
| `Remove-PCloudAccount` | `DELETE /Accounts/{id}` |
| `Get-PCloudAccountPassword -Reason … [-TicketId] [-AsPlainText]` | `POST /Accounts/{id}/Password/Retrieve` |
| `Invoke-PCloudAccountChange [-ChangeEntireGroup]` | `POST /Accounts/{id}/Change` |
| `Invoke-PCloudAccountVerify` | `POST /Accounts/{id}/Verify` |
| `Invoke-PCloudAccountReconcile` | `POST /Accounts/{id}/Reconcile` |
| `Set-PCloudAccountNextPassword [-ChangeImmediately]` | `POST /Accounts/{id}/SetNextPassword` |
| `Set-PCloudAccountPasswordInVault` | `POST /Accounts/{id}/Password/Update` |
| `Invoke-PCloudAccountCheckIn` | `POST /Accounts/{id}/CheckIn` |
| `Add-PCloudLinkedAccount` / `Remove-PCloudLinkedAccount` | `POST/DELETE /Accounts/{id}/LinkAccount` |

```powershell
$pw = Read-Host 'Password' -AsSecureString
New-PCloudAccount -SafeName 'Linux-Root' -PlatformId 'UnixSSH' -Address '10.0.0.5' -UserName 'root' -Secret $pw

Set-PCloudAccount -Id 12_34 -Address 'web01.acme.local' -Property @{ Port = '2222' }

# Password retrieval returns a SecureString unless you ask for plain text
$sec = Get-PCloudAccountPassword -Id 12_34 -Reason 'CHG0012345'

# Pipeline works with the id property
Get-PCloudAccount -SafeName 'Linux-Root' | Invoke-PCloudAccountVerify -WhatIf
```

### Safes and safe members (`/API/Safes`)

| Command | Endpoint |
|---|---|
| `Get-PCloudSafe [-Search] [-IncludeAccounts] [-ExtendedDetails]` / `-SafeName` | `GET /Safes`, `GET /Safes/{safeUrlId}` |
| `New-PCloudSafe` | `POST /Safes` |
| `Set-PCloudSafe` (keeps settings you leave out) | `PUT /Safes/{safeUrlId}` |
| `Remove-PCloudSafe` | `DELETE /Safes/{safeUrlId}` |
| `Get-PCloudSafeMember [-MemberType] [-IncludePredefinedUsers]` / `-MemberName` | `GET /Safes/{id}/Members[/{member}]` |
| `Add-PCloudSafeMember -Preset … \| -Permission @{}` | `POST /Safes/{id}/Members` |
| `Set-PCloudSafeMember` | `PUT /Safes/{id}/Members/{member}` |
| `Remove-PCloudSafeMember` | `DELETE /Safes/{id}/Members/{member}` |
| `Get-PCloudSafePermissionSet -Preset … [-Override @{}]` | builds a full permission set locally |

The permission presets are this module's own shortcuts, modelled on the common UI roles:

| Preset | Grants |
|---|---|
| `ConnectOnly` | list, use |
| `ReadOnly` | list, use, retrieve |
| `Approver` | list, view members, manage members, authorize requests (level 1) |
| `AccountsManager` | full account management, no safe administration |
| `Full` | everything except authorization level 2 |

```powershell
New-PCloudSafe -SafeName 'Linux-Root' -Description 'Root accounts' -ManagingCPM 'PasswordManager' -NumberOfDaysRetention 7
Add-PCloudSafeMember -SafeName 'Linux-Root' -MemberName 'unix-admins' -MemberType Group -Preset AccountsManager
Add-PCloudSafeMember -SafeName 'Linux-Root' -MemberName 'jdoe@acme.com' -Preset ReadOnly -ExpirationDate (Get-Date).AddDays(30)
Set-PCloudSafeMember -SafeName 'Linux-Root' -MemberName 'jdoe@acme.com' -Permission (Get-PCloudSafePermissionSet -Preset ReadOnly -Override @{ viewAuditLog = $true })
```

### Platforms (`/API/Platforms`)

`Get-PCloudPlatform`, `Get-PCloudTargetPlatform`, `Enable-PCloudTargetPlatform`, `Disable-PCloudTargetPlatform`, `Copy-PCloudTargetPlatform`, `Remove-PCloudTargetPlatform`, `Export-PCloudPlatform -Path x.zip` and `Import-PCloudPlatform -Path x.zip`. The target-platform commands take the numeric `ID`; get, export and import use the string `PlatformId`.

```powershell
Get-PCloudTargetPlatform -Filter 'Active eq true' | Select-Object ID, PlatformID, Name
Export-PCloudPlatform -PlatformId 'UnixSSH' -Path C:\Temp\UnixSSH.zip
(Resolve-PCloudTargetPlatform 'WinDomain').ID     # PlatformID, name or numeric ID -> the platform
```

### PSM assignment (`/API/PSM/Servers`, `/API/Platforms/Targets/{ID}/PrivilegedSessionManagement`)

`Get-PCloudPSMServer` lists the PSM servers. `Get-PCloudPlatformPSMConfig -TargetPlatformId <ID>` returns a platform's `PSMServerID` and its `PSMConnectors` (each with `PSMConnectorID` and `Enabled`). `Set-PCloudPlatformPSMConfig -TargetPlatformId <ID> -PSMServerId <id> -PSMConnectors <list>` replaces both, so send the full list you want to keep.

```powershell
$p = Resolve-PCloudTargetPlatform 'WinDomain'
$cfg = Get-PCloudPlatformPSMConfig -TargetPlatformId $p.ID
Set-PCloudPlatformPSMConfig -TargetPlatformId $p.ID -PSMServerId $cfg.PSMServerID -PSMConnectors (@($cfg.PSMConnectors) + @{ PSMConnectorID = 'PSM-RDPConsole'; Enabled = $true })
```

### Applications (Credential Provider, Gen 1 `/WebServices/PIMServices.svc/Applications`)

`Get-PCloudApplication` lists applications (`-AppId` filters by part of the ID, `-Location` by Vault location), or returns one with `-AppId X -ExactMatch`. `New-PCloudApplication` adds one (location `\` and access hours 0-23 by default, plus optional expiration date, disabled flag and business owner). `Remove-PCloudApplication` deletes one. `Get-PCloudApplicationAuthentication`, `Add-PCloudApplicationAuthentication` and `Remove-PCloudApplicationAuthentication` manage the authentication methods: `path` (with `-IsFolder` and `-AllowInternalScripts`), `hash`, `osUser`, `machineAddress`, `certificateserialnumber`, and `certificateattr` (with `-Subject`, `-Issuer` and `-SubjectAlternativeName`). The Applications API has no update call, so a method is changed by adding the new one and removing the old one.

### Vault locations (self-hosted only)

Locations are deprecated in the Privilege Cloud API, so no menu uses them. The functions are kept for self-hosted Vaults (Gen 1 `/WebServices/PIMServices.svc/Locations`): `Get-PCloudLocation` lists them as `FullPath`, `Name`, `ParentPath` and `LocationID` (`-Search`, `-Path`), `New-PCloudLocation -Path '\Applications'` adds one, `Set-PCloudLocation -Path X -NewName Y` renames or `-NewParent Z` moves, and `Remove-PCloudLocation -Path X` deletes an empty one.

### Master rotation policy (`/api/platforms/master-rotation-policy`)

`Get-PCloudMasterRotationPolicy` returns `verifyInterval` and `changeInterval` (days, 1-365, or null), the exception counts, and who created or updated the policy and when. `Get-PCloudMasterRotationPolicyException` lists the platforms with their own intervals (`PlatformId`, `VerifyInterval`, `ChangeInterval`). `Set-PCloudMasterRotationPolicy -VerifyInterval 7 -ChangeInterval 90` sends a PATCH with only the intervals you give, and `-ClearVerifyInterval` or `-ClearChangeInterval` sends null. These are Gen 3 endpoints, at `https://<subdomain>.privilegecloud.cyberark.cloud/api/`. Errors in the newer `{ code, message, description, errors }` format are shown in full.

### Master Policy

Privilege Cloud has no Gen 2 Master Policy endpoint. `/API/Policies/1` exists only in self-hosted PAM. In Privilege Cloud, the master policy is the Gen 3 master rotation policy above, and `Get-PCloudMasterPolicy` returns that. `ConvertTo-PCloudFlatSetting` turns any nested API object into `Setting`/`Value` rows.

### Users and groups (`/API/Users`, `/API/UserGroups`)

`Get-PCloudUser`, `Get-PCloudGroup [-IncludeMembers]`, `New-PCloudGroup`, `Set-PCloudGroup`, `Remove-PCloudGroup`, `Add-PCloudGroupMember` and `Remove-PCloudGroupMember`.

In Privilege Cloud Shared Services, people and roles are normally managed in **Idira Identity**, not in the vault. These commands cover the vault-side users and vault groups. To give an Identity user or role access to a safe, use `Add-PCloudSafeMember` with that user or role name.

### Monitoring

| Command | Endpoint |
|---|---|
| `Get-PCloudSystemHealth [-ComponentId CPM\|SessionManagement\|AIM\|PTA\|PVWA]` | `GET /ComponentsMonitoringSummary`, `/ComponentsMonitoringDetails/{id}` |
| `Get-PCloudLiveSession`, `Stop-PCloudLiveSession` | `GET /LiveSessions`, `POST /LiveSessions/{id}/Terminate` |
| `Get-PCloudRecording` | `GET /Recordings` |

### Anything else: `Invoke-PCloudApi`

For any endpoint without its own command, `Invoke-PCloudApi` adds auth, retries, error handling and paging. `-Path` is relative to `/PasswordVault/`, and `API/` is added for you (Gen 2). Add `-Generation 3` for Gen 3 endpoints under `https://<subdomain>.privilegecloud.cyberark.cloud/api/`, or `-Generation 1` for `/PasswordVault/WebServices/`.

```powershell
Invoke-PCloudApi -Method Get -Path 'Accounts' -Query @{ search = 'admin'; limit = 500 } -All
Invoke-PCloudApi -Method Get -Path 'Platforms/Groups'
```

With `-All`, any response shaped `{ value: [...], nextLink: "..." }` is followed page by page and the items are streamed out. Accounts, safes, safe members and groups use this format.

## Main menu (`Start-IdiraPCloud.ps1`)

The easiest way in. It signs you in once, then offers Safes, Accounts, Platforms, PSM assignment, Applications, Master Policy, System health and Reports. Reports opens a submenu with the account inventory and safe members reports. Each area opens its own menu. Pressing Q there brings you back to the main menu, and a failure in an area shows the error and returns you there too. S shows the session, L starts or stops a session log (see [Logging a session](#logging-a-session--log)), and X logs out and quits. The main menu has no plain quit, so leaving it always logs out. See [Log out and clearing the session](#log-out-and-clearing-the-session).

```powershell
cd C:\Tools\IdiraPCloud
.\Start-IdiraPCloud.ps1
```

## Task scripts (`Scripts\`)

Each script loads the module itself and reuses any active session, for example one you opened with `New-PCloudSession`. **If there's no active session, or the session's token has expired and can't be renewed, the script prompts you to sign in:**

1. It asks for the sign-in method, **Interactive** (your Identity user with MFA, the default) or **Service user**, unless you passed `-AuthMethod`.
2. It asks for the subdomain, unless you passed `-Subdomain` or `-PCloudUrl`. The Identity tenant is then found automatically.
3. It asks for your user name and each MFA step (Interactive), or for the service user's credential, unless you passed `-Credential`.

So `.\Export-AccountInventory.ps1` on its own is enough. Pass the parameters to skip the prompts, for example `-AuthMethod ServiceUser -Subdomain acme -Credential $cred` for an unattended run. All the scripts that change something support `-WhatIf`.

| Script | Purpose |
|---|---|
| `Import-AccountsFromCsv.ps1` | Bulk onboarding from CSV, with `-SkipExisting` and a results CSV |
| `Export-AccountInventory.ps1` | Account inventory with CPM status and last change/verify/reconcile times (`-FailedOnly`) |
| `Invoke-BulkCredentialAction.ps1` | Change, verify or reconcile many accounts by safe, search, IDs or failures only |
| `Get-AccountPassword.ps1` | Audited retrieval by ID or by safe + user + address, copied to the clipboard and cleared after 30 seconds |
| `Export-SafeMembersReport.ps1` | Every safe's members and each permission as columns |
| `Grant-SafeAccess.ps1` | Add, update or revoke a member across many safes with a preset |
| `Manage-Safes.ps1` | Safe management: get safes, get safe details, add or update a safe, add or update safe members. Each works on one item or on every row of a CSV (see below). |
| `Manage-Accounts.ps1` | Account management: get accounts and details, add, update (menu), delete, CPM change/verify/reconcile, retrieve a password (see below). |
| `Manage-Platforms.ps1` | Platform management: get platforms and details, activate, deactivate, duplicate, delete, export, import. |
| `Manage-PlatformPSM.ps1` | PSM servers, and the PSM server and connection components assigned to each platform (update menu). |
| `Manage-Applications.ps1` | Credential Provider applications: list, details, add, delete, authentication methods, and safe access for the application and its Providers (see below). |
| `Manage-MasterPolicy.ps1` | Master Policy and master rotation policy: view, list rotation exceptions, update the verify and change intervals. |
| `Get-MasterPolicy.ps1` | Shows the Master Policy as Setting/Value rows, with CSV or JSON export. Read only. |
| `Get-SystemHealth.ps1` | Component summary, then every component's user, version, IP, status and last logon, with offline ones highlighted. Use `-OutputPath` for a CSV, or `-SummaryOnly` for just the summary. |

```powershell
cd C:\Tools\IdiraPCloud\Scripts
.\Import-AccountsFromCsv.ps1 -Path .\accounts.csv -Subdomain acme -WhatIf
.\Invoke-BulkCredentialAction.ps1 -Action Reconcile -SafeName 'Win-Servers' -FailedOnly
.\Grant-SafeAccess.ps1 -SafeSearch 'Prod' -MemberName 'jdoe@acme.com' -Preset ReadOnly -ExpirationDate (Get-Date).AddDays(7)
```

### Safe management (`Manage-Safes.ps1`)

Run it with no parameters to pick an action from a menu. The menu signs you in once, then **keeps looping until you press Q**. Nothing in menu mode exits the script. A safe name that doesn't exist, or a CSV path that isn't found, shows the error and asks again (leave it blank, or enter B, to go back). Any failed action shows the error and returns you to the main menu, and the update menu keeps your pending changes as described below. Otherwise pass `-Action` along with either single-item parameters or `-CsvPath`. Every write action supports `-WhatIf`.

**CSV export (GetSafes, GetSafeDetails, GetSafeMembers):** add `-ExportCsv` to save to `PCloud-<Action>-<timestamp>.csv` in the `CSVs` folder (see Output files), or use `-OutputPath <file>` to choose the file. From the menu, you're asked whether to save the results. The exports contain no secrets, but they do describe privileged access, so keep them somewhere only you can read. Sample CSVs are in `Scripts\samples\`.

| `-Action` | Single item | CSV sample | Notes |
|---|---|---|---|
| `GetSafes` | nothing (every safe), `-SafeName` or `-Search` | `safes-get.csv` (`SafeName`, `Search`) | With nothing specified, it returns every safe. |
| `GetSafeDetails` | `-SafeName` | `safes-names.csv` | Settings plus the account and member counts and names. |
| `GetSafeMembers` | nothing (every safe), `-SafeName [-MemberName]`, `-IncludePredefinedUsers` | `safe-members-get.csv` (`SafeName`, optional `MemberName`) | One row per member, with all 22 permissions as true/false columns and a `Preset` column (see below). |
| `AddSafe` | `-SafeName -Description -ManagingCPM -Location -NumberOfDaysRetention` or `-NumberOfVersionsRetention`, `-AutoPurgeEnabled` | `safes-add.csv` | Retention defaults to 7 days. |
| `UpdateSafe` | `-SafeName` plus any of `-NewSafeName -Description -ManagingCPM -Location`, retention | `safes-update.csv` | Blank cells are left unchanged. For a single safe with no settings given (`-Action UpdateSafe -SafeName X`, or from the menu), a menu shows the current values and lets you pick what to change: name, description, managing CPM, location or retention. It summarizes the changes and asks for confirmation before applying them. If the update fails, it shows the error, removes the setting that caused it (it asks you which one if the error doesn't say), and returns to the menu with the other changes still pending. **Managing CPM** (option 3) opens a submenu. You can pick from the CPM users that System Health reports, shown as online or offline (if System Health isn't available, the list falls back to CPMs already used by safes). You can also choose **No managing CPM**, which warns first, type a name, or add **read-only CPM access**. That last option adds one or more CPMs as safe members with list, retrieve and access-without-confirmation permissions, so a CPM can use a linked logon or reconcile account stored in this safe without managing it. It can be combined with a managing CPM change or done on its own, and a CPM that already manages the safe is skipped. After any managing CPM change (menu, parameters or CSV), the script reads the safe back and reports what Privilege Cloud now shows as the managing CPM, and warns if it isn't the one you asked for. The update adds the new CPM to the safe members but does not remove an earlier one, and the portal can keep showing that earlier CPM as the assigned CPM even though the API reports the new one. So the script then looks for any other CPM that is still a member with CPM management permissions: the menu asks whether to remove it, and `-RemoveOldCPM` does it for parameter and CSV runs (otherwise the result row names it). CPMs that only have read-only access are left alone. The CPM submenu also lists other CPMs that are members of the safe, marked as management or read-only, and option 5 removes one. OLAC is deliberately not offered anywhere in the module, since it's being deprecated and adds management overhead. Existing OLAC settings are left as they are. |
| `AddSafeMember` | `-SafeName -MemberName [-MemberType User/Group/Role] [-SearchIn] -Preset [-Permission @{}] [-ExpirationDate] [-IsReadOnly true]` | `safe-members-add.csv` | The preset defaults to ReadOnly. Permission columns override the preset. |
| `UpdateSafeMember` | `-SafeName -MemberName` plus `-Preset` and/or `-Permission @{}`, `-ExpirationDate`, `-IsReadOnly` | `safe-members-update.csv` | With a preset, permissions are replaced by the preset plus overrides. Without one, the current permissions stay and only the values you give change. The current expiration date is kept unless you set a new one. |

**Users, groups and roles:** the safe members API can report Idira Identity **roles** as `Group`. GetSafeMembers, GetSafeDetails and `Export-SafeMembersReport.ps1` check each name against the Identity role list (read once per session from `/Redrock/query`). `MemberType` shows the real type, `ApiMemberType` shows what the API returned, and `TypeSource` says which one won (`Identity` or `API`). When adding members, `MemberType` defaults to **Auto**: an Identity role becomes `Role`, an Identity user (or a name with `@`) becomes `User`, and anything else becomes `Group`. The menu shows the detected type and lets you accept or override it. In CSVs, leave `MemberType` blank or set it to `Auto`. This needs an Identity sign-in that can read roles. Without it, the API's value is kept and the script says so. `Resolve-PCloudSafeMemberType` exposes the same logic.

**Preset matching (GetSafeMembers):** each member's 22 permissions are compared with the module's presets (Full, AccountsManager, Approver, ReadOnly, ConnectOnly and None). For an exact match, `Preset` holds the preset's name. Otherwise it reads `Custom (ReadOnly +viewAuditLog -useAccounts)`, which names the closest preset and the differences when there are 3 or fewer, or just `Custom` when there are more. `ClosestPreset` and `IsExactMatch` are separate columns so you can filter on them. The same `Preset` column now appears in `Export-SafeMembersReport.ps1`. You can call the matcher yourself with `Get-PCloudSafePermissionPreset`. The presets are this module's definitions (see the presets table above), not names returned by Privilege Cloud.

In member CSVs, any permission name can be a column (`retrieveAccounts`, `viewAuditLog`, `manageSafeMembers` and so on) holding `true` or `false`. A blank cell means no change. True/false values also accept `yes`/`no` and `1`/`0`.

```powershell
.\Manage-Safes.ps1 -Action GetSafes -ExportCsv
.\Manage-Safes.ps1 -Action GetSafeMembers -ExportCsv
.\Manage-Safes.ps1 -Action GetSafeMembers -SafeName 'Linux-Root' -OutputPath .\linux-root-members.csv
.\Manage-Safes.ps1 -Action GetSafeDetails -SafeName 'Linux-Root'
.\Manage-Safes.ps1 -Action AddSafe -CsvPath .\samples\safes-add.csv -WhatIf
.\Manage-Safes.ps1 -Action UpdateSafeMember -SafeName 'Linux-Root' -MemberName 'jdoe@acme.com' -Permission @{ retrieveAccounts = $false }
```

### How the Manage-*.ps1 menus work

`Manage-Accounts.ps1`, `Manage-Platforms.ps1` and `Manage-PlatformPSM.ps1` follow the same design as `Manage-Safes.ps1`, and share their prompts through `Scripts\_Menu.ps1`:

- Run with no parameters for the menu. It signs you in once and **loops until Q**. Nothing in menu mode exits the script: an unknown safe, account, platform or file is shown in red and asked again, B (or a blank answer where it says so) goes back, and a failed action returns you to the main menu.
- Each action asks for a CSV first. Leave it blank to work on one item.
- Safes, platforms, PSM servers, connectors and accounts can be typed or **picked from a numbered list**. Lists longer than 30 ask for filter text first, and F filters again.
- Read actions ask whether to save a CSV (`-ExportCsv` or `-OutputPath` skip the question). Exports never contain passwords.
- **Output files** all default to the `CSVs` folder in the main IdiraPCloud folder (next to `Scripts` and the module): results and exports from every Manage-*.ps1 script, the inventory and safe members reports, the system health CSV, the Master Policy JSON, import results and platform packages. A bare file name (`-OutputPath report.csv`, or typed at the prompt) goes there too. A path with a folder in it (`.\report.csv`, `C:\Reports\x.csv`) is used as given. The folder is created on first use with access limited to you, SYSTEM and Administrators, since the files describe privileged access.
- **Update menus** (UpdateAccount, UpdatePlatformPSM) show the current values, let you queue changes, summarize them and ask before applying. All the changes go in one request. If it fails, the change that caused it is removed (you're asked which one if the error doesn't say) and the menu comes back with the rest still pending.
- Deletes ask you to type `DELETE` (or pass `-Force`). Every write action supports `-WhatIf`.
- Pass `-Action` with single-item parameters or `-CsvPath` to run once without the menu, for example in a scheduled task.

### Account management (`Manage-Accounts.ps1`)

| `-Action` | Single item | CSV sample | Notes |
|---|---|---|---|
| `GetAccounts` | nothing (every account), `-SafeName` and/or `-Search` | `accounts-get.csv` | Includes automatic management, CPM status and last modified/verified/reconciled times. |
| `GetAccountDetails` | `-AccountId`, or `-SafeName -UserName [-Address]` | `accounts-ids.csv` | Every field, with each platform property as a column named after it (for example `Notes`). A property whose name matches an account column, such as `Name`, keeps the `prop_` prefix. The file can be edited and used as an UpdateAccount CSV. |
| `AddAccount` | `-SafeName -PlatformId -UserName [-Address -Name -PlatformAccountProperties @{} -DisableAutomaticManagement -ManualManagementReason]`, `-Secret <SecureString>` or `-PromptForPasswords` (single account only) | `accounts-add.csv` | From the menu, the safe is checked, the platform is picked from the active platforms, properties are asked one by one and the password is a masked prompt (Enter leaves it empty for the CPM to reconcile). Platform property names (menu, CSV `prop_<Name>` columns and `-PlatformAccountProperties`) are checked against the platform's required and optional properties. A display name is changed to the property's own name, and a property the platform doesn't define stops that account with the list of valid names, because the API refuses it (`PASWS125E`). In the update menu, you pick the property from the platform's list. **CSV onboarding never asks for passwords.** If the CSV has a `Secret` column (a `Password` column also works), each value becomes a SecureString as it is read and the plain text is cleared. A row with no secret is still created without one, and the output and results CSV note it. Delete a CSV with passwords securely afterwards. |
| `UpdateAccount` | `-AccountId` (or lookup) plus any of `-NewName -NewAddress -NewUserName -NewPlatformId -AutomaticManagement true/false -ManualManagementReason -PlatformAccountProperties @{}` | `accounts-update.csv` | With no new values, opens the update menu: name, address, user name, platform (from the list), platform properties (add, change or remove) and automatic management on or off with a reason. In CSVs, a platform property can be a column named after it (`Notes`) or with the prefix (`prop_Notes`). A value adds or changes it, `(remove)` removes it, and blank cells change nothing. Any column the script doesn't otherwise use is treated as a platform property and checked against the platform, so a misspelled column name is reported rather than ignored. A row with nothing to change fails and lists the columns it read. CSVs saved with semicolons (Excel in some regions) are read too. **Multi-line values:** in a CSV, put the value in double quotes (Excel does this for cells with line breaks) and every line is kept. At a menu prompt for a property value, paste the lines (all of them are kept) or end a typed line with `\` to continue on the next one. |
| `LinkAccount` | `-AccountId` (or lookup) `-LinkType` plus `-LinkedAccountId`, or `-LinkedSafe -LinkedName [-LinkedFolder]` | `accounts-link.csv` | From the menu: choose the account, pick the link type from the ones its platform offers (logon, enable, reconcile... with their index), then find the linked account by ID, by searching a safe, or with N to type the safe and object name. `-LinkType` takes a name such as `LogonAccount` or `ReconcileAccount`, or the index number. |
| `UnlinkAccount` | `-AccountId` (or lookup) `-LinkType` | `accounts-unlink.csv` | Removes that linked account from the account. |
| `DeleteAccount` | `-AccountId` or lookup | `accounts-ids.csv` | Type `DELETE` to confirm. |
| `ChangeCredential`, `VerifyCredential`, `ReconcileCredential` | `-AccountId` or lookup | `accounts-ids.csv` | Marks the accounts for the CPM. |
| `RetrievePassword` | `-AccountId` or lookup, `-Reason` (asked if missing), `-TicketingSystemName -TicketId` | none | Runs `Get-AccountPassword.ps1`: audited, clipboard cleared automatically. One account at a time; bulk retrieval is deliberately not offered. |
| `AccountDependents` | optional `-AccountId` | see below | Opens the account dependents submenu (Manage-AccountDependents.ps1). |

Accounts can be given by ID or found by safe plus user name (plus address when the user name isn't unique). **From the menu, type an account ID or any keywords**: user name, address, account name, safe or platform, in any order, with partial words allowed (for example `admin 10.0.0` or `svc sql prod`). Every keyword has to appear in one of those fields. The search covers every safe you can see. Enter S to limit it to one safe first. One match asks you to confirm it, and several give you a list to pick from. `-Search` on GetAccounts works the same way.

### Account dependents (`Manage-AccountDependents.ps1`)

Dependents are the Windows services, scheduled tasks and other resources that use a target account's password, so the CPM updates them when it changes the password. Open them from **AccountDependents** in the Accounts menu, or run the script on its own. From the menu you choose the main account first, by ID or keywords, then work on its dependents until you go back, and **ChooseAnotherAccount** switches accounts. These use the Gen 3 API, `/api/accounts/{id}/account-dependents`.

| `-Action` | Single item | CSV sample | Notes |
|---|---|---|---|
| `GetDependents` | `-AccountId` plus optional `-Keyword` | `account-dependents-ids.csv` | ID, platform, name, management, linked accounts and each property as a `prop_` column. |
| `GetDependentDetails` | `-AccountId -DependentId` | `account-dependents-ids.csv` | Every field as `Setting`/`Value` rows. |
| `AddDependent` | `-AccountId -PlatformId` plus `-Name`, `-DependentProperties @{}`, `-AutomaticManagement`, `-ManualManagementReason`, `-DisableParentAutomaticManagement` | `account-dependents-add.csv` | The menu lists the dependent platforms (`GET /API/Platforms/Dependents`) and asks for each of the platform's properties, marking the required ones. Extra properties can be typed as Name=Value. |
| `UpdateDependent` | as `AddDependent` plus `-DependentId` | `account-dependents-update.csv` | Blank cells keep the current value. `(remove)` in a `prop_` column removes the property, or `-` at the menu prompt. The current dependent is read first and the full body sent, so nothing you didn't touch changes. |
| `DeleteDependent` | `-AccountId -DependentId` | `account-dependents-ids.csv` | Type DELETE to confirm, or `-Force`. |
| `LinkDependentAccount` | `-AccountId -DependentId -LinkIndex -LinkedAccountId` | `account-dependents-link.csv` | The menu shows the dependent platform's link types and their index, then you find the account to link by ID or keywords. 1 is usually the logon account. |
| `UnlinkDependentAccount` | `-AccountId -DependentId -LinkIndex` | `account-dependents-link.csv` | The menu lists the dependent's linked accounts to pick from. Type DELETE to confirm. |

Module functions: `Get-PCloudAccountDependent`, `New-PCloudAccountDependent`, `Set-PCloudAccountDependent`, `Remove-PCloudAccountDependent`, `Add-PCloudAccountDependentLink`, `Remove-PCloudAccountDependentLink` and `Get-PCloudDependentPlatform`. Responses wrapped as `{ statusCode, headers, body }` are unwrapped to the body.

### Platform management (`Manage-Platforms.ps1`)

| `-Action` | Single item | CSV sample | Notes |
|---|---|---|---|
| `GetPlatforms` | nothing (every target platform), `-Search`, `-Active true/false` | none (`Search` column) | Shows CPM auto change/verify/reconcile, dual control, exclusive and one-time access, and the PSM server. |
| `GetPlatformDetails` | `-PlatformId` | `platforms-ids.csv` | Every setting as `PlatformID`/`Setting`/`Value` rows. |
| `ActivatePlatform`, `DeactivatePlatform` | `-PlatformId` | `platforms-ids.csv` | Platforms already in that state are reported and skipped. |
| `DuplicatePlatform` | `-PlatformId -NewName [-Description]` | `platforms-duplicate.csv` | |
| `DeletePlatform` | `-PlatformId` | `platforms-ids.csv` | Type `DELETE` to confirm. |
| `ExportPlatform` | `-PlatformId [-Path file.zip or folder]` | `platforms-export.csv` | Defaults to `.\<PlatformID>.zip`. An existing file isn't overwritten without `-Force`. |
| `ImportPlatform` | `-Path package.zip` | `platforms-import.csv` | Imported platforms start inactive. |

`-PlatformId` takes the platform ID (`WinDomain`), its name or its numeric ID.

### PSM assignment (`Manage-PlatformPSM.ps1`)

| `-Action` | Single item | CSV sample | Notes |
|---|---|---|---|
| `GetPSMServers` | nothing | none | ID and name of each PSM server. |
| `GetPlatformPSM` | nothing (every platform) or `-PlatformId` | `platform-psm-get.csv` | PSM server ID and name, enabled and disabled connectors. |
| `UpdatePlatformPSM` | `-PlatformId` plus any of `-PSMServerId` (ID or name), `-EnableConnectors`, `-DisableConnectors`, `-AddConnectors`, `-RemoveConnectors` | `platform-psm-update.csv` | With no changes given, opens the PSM menu: choose the PSM server from the list, enable, disable, add or remove connectors, then apply. To add, type L to pick one or more from the known connectors (every connector used on any of your platforms, plus the built-in PSM-RDP, PSM-SSH, PSM-WinSCP and similar, each with how many platforms use it), or type part of an ID to search them. An exact ID that isn't in use anywhere yet can still be added after a confirmation. The known list is read once per run and cached. The script sends the full server and connector list built from the current settings plus your changes, so nothing you didn't touch is lost. CSV lists are separated by `;`. |

### Applications (`Manage-Applications.ps1`)

| `-Action` | Single item | CSV sample | Notes |
|---|---|---|---|
| `GetApplications` | nothing (every application), `-Search` (part of the ID), `-Location` | none | ID, description, location, disabled, access hours, expiration and business owner. |
| `GetApplicationDetails` | `-AppId` | `applications-ids.csv` | Every setting and each authentication method as `Setting`/`Value` rows. |
| `AddApplication` | `-AppId` plus `-Description -Location -AccessPermittedFrom -AccessPermittedTo -ExpirationDate -Disabled -BusinessOwnerFName -BusinessOwnerLName -BusinessOwnerEmail -BusinessOwnerPhone` | `applications-add.csv` | Location defaults to the root `\` and the hours to 0-23. Locations are deprecated in Privilege Cloud, so the menu doesn't ask for one. `-Location` and the CSV column are still passed through for self-hosted Vaults. Dates are `yyyy-MM-dd`. The menu checks the ID is free and re-prompts invalid hours or dates. |
| `DeleteApplication` | `-AppId` | `applications-ids.csv` | Type DELETE to confirm, or `-Force`. |
| `GetAuthentications` | `-AppId` | `applications-ids.csv` | AuthID, type, value and the path, hash and certificate options. |
| `AddAuthentication` | `-AppId -AuthType` plus `-AuthValue`, or `-Subject -Issuer -SubjectAlternativeName` (`;`-separated) for `certificateattr` | `applications-auth-add.csv` | The menu picks the type from a list and asks only for what that type needs, then offers to add another. A method that's already there is reported, not added twice. |
| `RemoveAuthentication` | `-AppId` plus `-AuthId`, or `-AuthType` and `-AuthValue` | `applications-auth-remove.csv` | The menu lists the methods to pick from. Type DELETE to confirm. Warns when the application has none left. |
| `GrantSafeAccess` | `-AppId -SafeName` plus optional `-Providers` (`;`-separated) | `applications-safe-access.csv` | Adds the application as a Vault user member with only List and Retrieve accounts. Providers (for example `Prov_SERVER01`) also get View safe members. The menu takes part of a safe name and offers more safes. |
| `RevokeSafeAccess` | `-AppId -SafeName` plus optional `-Providers` | `applications-safe-access.csv` | Removes them from the safe after a confirmation. Providers are removed only if you list them, since other applications may use them. |

From the menu, an application is chosen by its exact ID, part of the ID or description, or L for the full list.

```powershell
.\Manage-Applications.ps1
.\Manage-Applications.ps1 -Action GetApplications -Search billing -ExportCsv
.\Manage-Applications.ps1 -Action AddAuthentication -AppId BillingApp -AuthType machineAddress -AuthValue 10.0.1.25
.\Manage-Applications.ps1 -Action GrantSafeAccess -CsvPath .\samples\applications-safe-access.csv -WhatIf
```

### Master Policy (`Manage-MasterPolicy.ps1`)

| `-Action` | Parameters | Notes |
|---|---|---|
| `GetRotationPolicy` | | Verify and change intervals, exception counts, and last updated by and when. |
| `GetRotationExceptions` | | Platforms with their own intervals, beside the master values. |
| `UpdateRotationPolicy` | `-VerifyInterval`, `-ChangeInterval` (days 1-365, or `none`) | With no values, a menu shows the current intervals. It asks before applying, warns that the change affects every platform without an exception, and drops a failing change while keeping the other pending. Supports `-WhatIf`. |

`Get-MasterPolicy.ps1` is still there as a read-only shortcut:

Read only. Shows every Master Policy setting as a `Setting`/`Value` row and asks whether to save a CSV and the full JSON. Use `-ExportCsv`, `-OutputPath`, `-JsonPath`, `-Filter <text>` or `-PassThru -NoPrompt` to skip the questions.

```powershell
.\Manage-Accounts.ps1
.\Manage-Accounts.ps1 -Action UpdateAccount -AccountId 12_34
.\Manage-Accounts.ps1 -Action AddAccount -CsvPath .\samples\accounts-add.csv -WhatIf
.\Manage-Platforms.ps1 -Action GetPlatforms -Active true -ExportCsv
.\Manage-Platforms.ps1 -Action ExportPlatform -CsvPath .\samples\platforms-export.csv
.\Manage-PlatformPSM.ps1 -Action GetPlatformPSM -ExportCsv
.\Manage-PlatformPSM.ps1 -Action UpdatePlatformPSM -PlatformId UnixSSH -AddConnectors PSM-SSH -DisableConnectors PSM-WinSCP
.\Get-MasterPolicy.ps1 -OutputPath .\master-policy.csv
```

Sample CSV for onboarding (`Scripts\accounts-sample.csv`). Any `prop_` column, or any column the script doesn't otherwise use, becomes a platform account property. Without a `Secret` column the new accounts are created empty for the CPM to reconcile. With a `Secret` column (a `Password` column also works), each row with a value is created with that secret and rows without one are created without a secret (noted in the output); delete the file securely afterwards. To type a password instead, add that account on its own from the Accounts menu.

```csv
SafeName,PlatformId,Address,UserName,AutomaticManagement,ManualManagementReason,prop_LogonDomain,prop_Port
Win-Servers,WinServerLocal,srv01.acme.local,Administrator,true,,,
Linux-Root,UnixSSH,10.0.0.5,root,true,,,2222
Win-Domain,WinDomain,acme.local,svc_sql,false,Service account,ACME,
```

## Security model

The module treats credentials and other sensitive data with security as the first priority:

- **Credentials and secrets are SecureStrings end to end.** Sign-in uses `PSCredential` (from `Get-Credential`), and supplied tokens use `-AccessToken` as a `SecureString`. Account secrets (`-Secret`, `-NewCredentials`) and retrieved passwords are SecureStrings too. A secret becomes plain text only while the HTTPS request body is being built, and that variable is cleared straight afterwards.
- **Tokens are stored as SecureStrings in memory.** That covers the access token and the Identity refresh token. The bearer header is decoded per request and then dropped, and replaced tokens are disposed.
- **The session keeps its own copy of your credential.** `Remove-PCloudSession` disposes that copy, the tokens and the Identity cookies, and leaves your `$cred` object untouched. Starting a new session disposes the previous one first.
- **Every prompt is masked.** Passwords, OTP and SMS/email codes, and security answers are all read with `Read-Host -AsSecureString`.
- **Request buffers are zeroed after each call.** Bodies are sent as UTF-8 byte arrays, and those are wiped once the call finishes.
- **Transport is locked down.** The session uses TLS 1.2 (and 1.3 where the OS supports it), and SSL3/TLS 1.0/1.1 are switched off for the session. Every URL must be `https://`. Certificate validation is never turned off.
- **The token only goes to your tenant.** Absolute URLs, such as paging `nextLink` values, are only followed when they point at your own Privilege Cloud host over HTTPS.
- **Logs and output contain no secrets.** `-Verbose` and error messages show URLs, status codes and server error text, never request bodies, tokens or passwords. `Get-PCloudSession` never shows the token. Result CSVs never contain secrets.
- **CSV passwords are held as SecureString.** When a CSV has a `Secret` column (a `Password` column also works), `Manage-Accounts.ps1` and `Import-AccountsFromCsv.ps1` move each value into a read-only SecureString, clear it from the row, dispose it after the row, never write it to results, and remind you to delete the file securely. Rows without a secret are created without one and noted in the output.
- **Password retrieval is careful by default.** `Get-AccountPassword.ps1` clears the clipboard after 5 to 300 seconds (even on Ctrl+C) and warns if Windows clipboard history is on. `-PassThru` returns only a SecureString. `-Show` warns first and clears the screen when you press Enter. `Get-PCloudAccountPassword -AsPlainText` warns as well.
- **Deletes and other destructive actions** ask for confirmation, and every write supports `-WhatIf`.

What you should still do:

- Use a dedicated service user with only the roles and safes it needs.
- Don't keep plain-text tokens or passwords in scripts, files or environment variables.
- Keep exported reports (inventory, safe members) in a folder only you can read, since they describe privileged accounts.
- Turn off clipboard history while doing privileged work.
- Don't run password retrieval while `Start-Transcript` or screen recording is active.

PowerShell strings can't be wiped from memory, so a decoded secret may stay in memory until .NET garbage-collects it. The module keeps that window as short as it can.

## Rate limiting

Every call to Privilege Cloud and Idira Identity, including sign-in, token renewal, discovery and the Identity directory lookups, goes through the same handler:

- **HTTP 429 (rate limited) and 503:** it waits for the time the server gives in `Retry-After` or `X-RateLimit-Reset`. Without either, it backs off 2, 4, 8, 16... seconds, with a little random jitter. It then retries, up to 6 times, with no single wait longer than 120 seconds. A yellow warning shows each wait, so a pause isn't mistaken for a hang.
- **When `X-RateLimit-Remaining` reaches 0** on a successful response, the next call to that host waits for the reset first.
- **502/504** are retried only for GET, PUT and DELETE. A POST or PATCH that might already have been processed, such as adding an account, is never sent twice.
- **Idira Identity limits** (per tenant host and per endpoint, enforced at the gateway): 1,600 requests/s for the tenant, 1,600/s per endpoint in the High API group, and 90/s per endpoint for everything else. Every Identity endpoint the module uses (StartAuthentication, AdvanceAuthentication, oauth2/platformtoken, oauth2/token, oauth2/refreshplatformtoken, Redrock/query) is in the High group. The module keeps each endpoint at about 90% of its limit as a safety net, so a normal sequential script never gets close. Identity rejects a request with 429 before processing it, so any Identity call, sign-in steps included, is safe to retry. Identity retries use a short back-off: 1, 2, 4 seconds and so on, up to 30 seconds.
- **Client-side pacing (optional):** `Set-PCloudRateLimit -MaxRequestsPerSecond 5` spaces calls to each host to stay under a known limit. That's useful for big CSV runs.

```powershell
Get-PCloudRateLimit
Set-PCloudRateLimit -MaxRequestsPerSecond 5 -MaxRetries 8 -MaxDelaySec 300
```

## Idle sign-out

A session is signed out after **15 minutes with no API call and no input**. The access and refresh tokens are disposed and cleared from memory, and the PowerShell window is cleared the same way as a log out (see below).

- **At a script prompt:** every key you type counts as activity. When the limit passes, the running script stops with a message. Under `Start-IdiraPCloud.ps1` you're back at the main menu, and picking an area asks you to sign in again.
- **At the PowerShell prompt** (after an area script quit with Q, or when you use the module directly): a background check every 30 seconds signs you out.
- **Commands run directly** (for example `Get-PCloudSafe` an hour later): the next call signs out and fails with "Signed out after inactivity" rather than using the old session.
- **Long jobs:** reports and bulk actions make API calls as they go, so they aren't interrupted.

`Set-PCloudIdleTimeout -Minutes 10` changes the limit for the current PowerShell window, `-Minutes 0` turns it off, and `Get-PCloudIdleTimeout` shows the limit and the time left. The timed prompts need the normal PowerShell console. In the ISE, VS Code or with redirected input, prompts don't time out, but the 30-second check and the next-call check still apply.

## Log out and clearing the session

Logging out signs you out of Privilege Cloud and clears what the session left in the PowerShell window, which can hold privileged data. It happens when you pick **X) Log out and quit** in the main menu, run `Disconnect-PCloudSession`, or are signed out for inactivity. It:

- disposes the access token, refresh token and stored credential
- removes the global variables created since the module loaded, such as `$accounts = Get-PCloudAccount ...`, and disposes any SecureString first
- clears `$Error`, which can hold API responses, and the command history (`Get-History` and PSReadLine's in-memory history)
- clears the screen, plus the scrollback in Windows Terminal
- runs garbage collection

It leaves alone the PSReadLine history file on disk, files the scripts wrote (`CSVs`, `Logs`), and a `-Log` transcript, which you asked for. The clipboard isn't touched either: `Get-AccountPassword.ps1` already clears what it copies. Q in an area menu goes back without logging out, and `Remove-PCloudSession` still only signs out. Use `Remove-PCloudSession -ClearPowerShellSession` or `Clear-PCloudPowerShellSession` on its own to clear the window too.

## Logging a session (`-Log`)

**From the main menu:** pick **L** to start recording the session to `Logs\IdiraPCloud-session-<timestamp>.log`. Everything shown and typed from then on is recorded, including the areas you open. Pick L again to stop, and the menu shows where the file is. Opening areas from the menu doesn't stop it, so their actions are recorded too. A log started with L stops only when you pick L again or when `Start-IdiraPCloud.ps1` ends (X, an error or the idle sign-out). A log started with `-Log` can also be stopped with L. Masked prompts aren't recorded, tokens never appear and the `-Verbose` trace is redacted, but the log can still describe privileged access, so the `Logs` folder is limited to you, SYSTEM and Administrators.

Add `-Log` to any script, including `Start-IdiraPCloud.ps1`, to record the run to `Logs\IdiraPCloud-<script>-<timestamp>.log` in the main IdiraPCloud folder. `-LogPath <file>` picks the file, and a bare file name also goes into `Logs`. The log starts before sign-in and stops when the script ends, however it ends: Q, an error, Ctrl+C or the idle sign-out. Everything opened from the main menu is recorded in the same log.

```powershell
.\Start-IdiraPCloud.ps1 -Log
.\Scripts\Manage-Safes.ps1 -Action UpdateSafe -SafeName MySafe -ManagingCPM PasswordManager1 -Log -Verbose
```

The log is a PowerShell transcript: everything shown on screen, plus what you type at normal prompts. Passwords and MFA codes are asked with masked prompts, so they are never recorded. Tokens never appear, and with `-Verbose` the API trace in the log is redacted as described below. Retrieved passwords go to the clipboard only, never to the screen. The `Logs` folder is created with access for you, SYSTEM and Administrators only.

## Seeing the exact API calls (`-Verbose`)

Add `-Verbose` to any script, including `Start-IdiraPCloud.ps1`, to see every call it sends: method, URL, headers, request body, HTTP status, time taken and response body.

```powershell
.\Scripts\Manage-Safes.ps1 -Action UpdateSafe -SafeName MySafe -ManagingCPM PasswordManager1 -Verbose
```

```
VERBOSE: >>> PUT https://acme.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/MySafe
VERBOSE:     Authorization: Bearer <redacted>
VERBOSE:     Accept: application/json
VERBOSE:     Content-Type: application/json; charset=utf-8
VERBOSE:     Body: {"safeName":"MySafe","description":"","location":"\\","olacEnabled":false,"managingCPM":"PasswordManager1"}
VERBOSE: <<< HTTP 200   (412 ms)
VERBOSE:     Body: {"safeUrlId":"MySafe","safeName":"MySafe", ...}
```

The trace never contains a secret, so it is safe to copy into a ticket:

- The `Authorization` header and cookies are always `<redacted>`.
- JSON values and query values whose name contains secret, password, credential, token, key material and similar are `<redacted>`.
- Bodies are withheld completely for Idira Identity calls (sign-in, MFA, tokens) and for endpoints that carry or return a credential, such as password retrieval. You still see the method, URL and status.
- Bodies longer than 4,000 characters are cut. Raise that with `Set-PCloudApiTrace -Enabled $true -MaxBodyChars 20000`.

When using the module directly, `Set-PCloudApiTrace -Enabled $true` turns the trace on for every command and `-Enabled $false` turns it off. To keep a copy, run the script inside `Start-Transcript` / `Stop-Transcript`.

## Error handling

A failed call throws a terminating error that gives the method, URL, HTTP status, and the Privilege Cloud `ErrorCode` and `ErrorMessage` (for example `PASWS013E`). Wrap calls in `try/catch` and read `$_.Exception.Message`. Add `-Verbose` to any command to see every request URL and the token renewals.

## Checking 5.1 compatibility

```powershell
powershell.exe -NoProfile -File .\Tests\Test-PS51Syntax.ps1
```

This parses every file with the 5.1 parser, validates the manifest and imports the module. It makes no API calls.

## Notes

- Safe names and member names are URL-encoded in paths for you, so names with spaces or `@` work.
- Most timestamps come back as Unix epoch seconds. Use `ConvertFrom-PCloudUnixTime` to read them.
- Secrets are passed as `SecureString` and turned into plain text only while the request body is being built.
- Endpoint paths follow the documented Privilege Cloud (Gen 2, `/PasswordVault/API/`) REST API. Test in a non-production tenant before you run the bulk scripts.
