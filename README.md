# GoogleAuthenticationFactory

PowerShell authentication provider for Google REST APIs.

## Purpose

This module provides authentication helpers for Google REST APIs. It supports:

- Google service account JSON credentials
- User impersonation (domain-wide delegation)
- Azure AD federated credentials flow

## Features

- Create and register reusable Google authentication factories
- Retrieve Google OAuth access tokens
- Return tokens as an Authorization header hashtable for REST calls
- Force token refresh when needed
- Inspect issued token content for troubleshooting
- Optional Application Insights dependency logging via `-AiLogger`
  - Logger can be created with [AiLogging](https://github.com/GreyCorbel/AiLogging)

## Requirements

- PowerShell 7.3 or higher

The module requires .NET cryptography support for PKCS8 keys, which is not available in older runtime combinations.

## Public Commands

- `New-GoogleAuthenticationFactory`
- `Get-GoogleAuthenticationFactory`
- `Get-GoogleAccessToken`
- `Test-GoogleAccessToken`

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
    -TargetUserEmail 'myuser@myorganization.com' `
    -Name 'chatAdminApi'

$token = Get-GoogleAccessToken -Factory 'chatAdminApi'
Test-GoogleAccessToken -Factory 'chatAdminApi'
```

### Azure AD federated credentials

```powershell
Import-Module GoogleAuthenticationFactory

New-GoogleAuthenticationFactory `
    -AadAuthenticationFactory $aadFactory `
    -WorkloadIdentityProviderResourceId '//iam.googleapis.com/projects/132546827814/locations/global/workloadIdentityPools/my-pool/providers/entra-id-mytenant-com' `
    -ServiceAccountEmail 'service-account@project-id.iam.gserviceaccount.com' `
    -Scopes @('https://www.googleapis.com/auth/cloud-platform') `
    -Name 'federatedApi'

$token = Get-GoogleAccessToken -Factory 'federatedApi'
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
    -TargetUserEmail 'myuser@myorganization.com' `
    -Name 'chatAdminApi' `
    -AiLogger $AiLogger
```


