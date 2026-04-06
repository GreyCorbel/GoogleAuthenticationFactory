# GoogleAuthenticationFactory

PowerShell authentication provider for Google REST APIs.

## Purpose

This module provides authentication helpers for Google REST APIs. It supports:

- Google service account JSON credentials
  - With optional user impersonation (domain-wide delegation)
- Azure AD federated credentials flow
  - With optional service account impersonation


## Features

- Create and register reusable Google authentication factories
- Retrieve Google OAuth access tokens
- Return tokens as an Authorization header hashtable for REST calls
- Force token refresh when needed
- Inspect issued token content for troubleshooting
- Optional Application Insights dependency logging via `-AiLogger`
  - Logger can be created with [AiLogging](https://github.com/GreyCorbel/AiLogging) module

## Requirements

- PowerShell 7.2 or higher

The module requires .NET cryptography support for PKCS8 keys, which is not available in Desktop edition of PowerShell.

## Public Commands

- `New-GoogleAuthenticationFactory`
- `Get-GoogleAuthenticationFactory`
- `Get-GoogleAccessToken`
- `Test-GoogleAccessToken`

## Helper Commands

The module also contains helper commands used internally by the public commands:

- `Get-GoogleData`
- `Invoke-GoogleWithRetry`

These helpers are included in the source for composition and testing scenarios.

## Command Help

Use built-in PowerShell help to inspect parameters and examples:

```powershell
Get-Help New-GoogleAuthenticationFactory -Detailed
Get-Help Get-GoogleAuthenticationFactory -Detailed
Get-Help Get-GoogleAccessToken -Detailed
Get-Help Test-GoogleAccessToken -Detailed
```

## Usage

### Service account (no impersonation)

```powershell
Import-Module GoogleAuthenticationFactory

$jsonData = Get-Content -Path 'C:\path\to\your\service-account.json' -Raw

New-GoogleAuthenticationFactory `
    -GoogleAccessJson $jsonData `
    -Scopes @(
        'https://www.googleapis.com/auth/admin.directory.customer.readonly',
        'https://www.googleapis.com/auth/admin.directory.user.readonly'
    ) `
    -Name 'googleAdminApi'

$token = Get-GoogleAccessToken
Test-GoogleAccessToken
```

### Service account with user impersonation

```powershell
Import-Module GoogleAuthenticationFactory

$jsonData = Get-Content -Path 'C:\path\to\your\service-account.json' -Raw

New-GoogleAuthenticationFactory `
    -GoogleAccessJson $jsonData `
    -Scopes @('https://www.googleapis.com/auth/chat.admin.spaces.readonly') `
    -ImpersonationEmail 'myuser@myorganization.com' `
    -Name 'chatAdminApi'

$token = Get-GoogleAccessToken -Factory 'chatAdminApi'
Test-GoogleAccessToken -Factory 'chatAdminApi'
```

### Azure AD federated credentials

Before using this flow, configure Entra ID and Google Workload Identity Federation:
#### Entra ID
1. Create an Entra ID application that publishes an API.
2. In the Entra ID app manifest, set:

```json
"accessTokenAcceptedVersion": 2
```
3. Give your Entra ID SPN permission to retrieve tokens for the app created above
#### Google
1. Create a Google Workload Identity Pool.
2. Create a provider in the pool with:
     - Issuer URL: `https://login.microsoftonline.com/<TENANT-ID>/v2.0`
     - Allowed audience: the Entra ID app client ID from step 1
     - Attribute mapping:
         - `attribute.tid` -> `assertion.tid`
         - `attribute.sub` -> `assertion.sub`
3. Create a Google service account and grant required Google API permissions/roles.
4. On the Google service account, grant principal access to the principal below, with roles
    - Service Account Token Creator (for impersonation of service account)
    - Workload Identity User (for federation with workload identity pool)

```text
principalSet://iam.googleapis.com/projects/<PROJECT-NUMBER>/locations/global/workloadIdentityPools/<POOL-ID>/attribute.tid/<TENANT-ID>
```

__Note__: Principal to add permissions to: seems to be any principal coming from federated Entra ID tenant, however additional conditions that limit access are in place:
- on Entra ID side: only SPNs with access to the app created in step 1 can request tokens with the right audience
- on Google side: only SPNs with client id name in `AllowedAudience` of the provider can federate 

```powershell
Import-Module AadAuthenticationFactory
$aadFactory = New-AadAuthenticationFactory -UseManagedIdentity -Name 'uami' -DefaultScopes '<APP-ID-URI-of-app-created-in-step-1>/.default'
Import-Module GoogleAuthenticationFactory

New-GoogleAuthenticationFactory `
    -AadAuthenticationFactory $aadFactory `
    -WorkloadIdentityProviderResourceId '//iam.googleapis.com/projects/132546827814/locations/global/workloadIdentityPools/my-pool/providers/entra-id-mytenant-com' `
    -ImpersonationEmail 'service-account@project-id.iam.gserviceaccount.com' `
    -Scopes @('https://www.googleapis.com/auth/cloud-platform') `
    -Name 'federatedApi'

$token = Get-GoogleAccessToken -Factory 'federatedApi'
Test-GoogleAccessToken -Factory 'federatedApi'
```

### Get Authorization header for REST calls

```powershell
$headers = Get-GoogleAccessToken -Factory 'chatAdminApi' -AsHashTable
$response = Invoke-RestMethod -Uri 'https://chat.googleapis.com/v1/spaces' -Headers $headers
$response.spaces
```

### Force refresh token

```powershell
$token = Get-GoogleAccessToken -Factory 'chatAdminApi' -ForceRefresh
```

### Helper command: Get-GoogleData (automatic paging)

```powershell
# Return all users across pages from Google Admin SDK
$users = Get-GoogleData `
    -Uri 'https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=100' `
    -DataProperty 'users'

$users.Count
```

### Helper command: Invoke-GoogleWithRetry (custom request)

```powershell
# Execute a custom Google API GET request with retry behavior
$response = Invoke-GoogleWithRetry `
    -Uri 'https://chat.googleapis.com/v1/spaces?pageSize=50' `
    -Method Get

$response.spaces
```

### With Application Insights logging

```powershell
Import-Module AiLogging
Import-Module GoogleAuthenticationFactory

$AiLogger = Connect-AiLogger `
    -ConnectionString $env:ApplicationInsightsConnectionString `
    -Application 'MyTestScript' `
    -Component 'MyTestComponent' `
    -Instance $env:ComputerName

$jsonData = Get-Content -Path 'C:\path\to\your\service-account.json' -Raw

New-GoogleAuthenticationFactory `
    -GoogleAccessJson $jsonData `
    -Scopes @('https://www.googleapis.com/auth/chat.admin.spaces.readonly') `
    -ImpersonationEmail 'myuser@myorganization.com' `
    -Name 'chatAdminApi' `
    -AiLogger $AiLogger
```

## Notes

- `-ImpersonationEmail` is used for both flows:
    - service account JSON flow: user email to impersonate
    - Azure AD federated flow: Google service account email to impersonate
- `-TargetUserEmail` is still supported as an alias for backward compatibility.
- `-WorkloadIdentityProviderResourceId` must start with `//`.


