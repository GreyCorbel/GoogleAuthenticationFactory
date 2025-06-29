# GoogleAuthenticationFactory
Powershell authentication provider for Google REST APIs

# Purpose
This module provides a way to authenticate against Google REST APIs using service accounts or user credentials. It supports both service account authentication and allows user impersonation.

# Features
- Authenticate using service account credentials.
- Impersonate a user by providing their email address.
- Retrieve access tokens for Google APIs
- Getting content of issued token for easy ptroubleshooting of authentication issues
- Optional ApplicationInsights logging for debugging and monitoring purposes.
  - Activated by setting the `$AiLogger` parameter in `New-GoogleAuthenticationFactory` command.
  - for details, see module [AiLogging](https://github.com/GreyCorbel/AiLogging)

Module is supported on PowerShell 7.3 and higner because lask of cryptography support for PKCS8 in lower versions of .NET.

# Usage
## Simple use without impersonation:
```powershell
# Import the module
Import-Module GoogleAuthenticationFactory

#load service account credentials from a JSON file
$jsonData = [System.IO.File]::ReadAllText('C:\path\to\your\service-account.json')

# Create a new authentication factory
New-GoogleAuthenticationFactory `
	-GoogleAccessJson $jsonData `
	-Scopes  @('https://www.googleapis.com/auth/admin.directory.customer.readonly','https://www.googleapis.com/auth/admin.directory.user.readonly') `
    -Name 'googleAdminApi'

#get the access token from kmost recently created authentication factory
$token = Get-GoogleAccessToken

#display data from the token
Test-GoogleAccessToken
```

## Use with user impersonation:
```powershell
# Import the module
Import-Module GoogleAuthenticationFactory

#load service account credentials from a JSON file
$jsonData = get-content -Path 'C:\path\to\your\service-account.json' -Raw

# Create a new authentication factory
New-GoogleAuthenticationFactory `
	-GoogleAccessJson $jsonData `
	-Scopes  @('https://www.googleapis.com/auth/chat.admin.spaces.readonly') `
    -TargetUserEmail 'myuser@myorganization.com' `
    -Name 'chatAdminApi'

#get the access token from kmost recently created authentication factory
$token = Get-GoogleAccessToken -Factory 'chatAdminApi'

#display data from the token
Test-GoogleAccessToken -Factory 'chatAdminApi'
```
## Use with AppInsights logging
```powershell
import-module AiLogging

$AiLogger = Connect-AiLogger `
    -ConnectionString $env:ApplicationInsightsConnectionString `
    -Application 'MyTestScript' `
    -Component 'MyTestComponent' `
    -Instance $env:ComputerName

# Import the module
Import-Module GoogleAuthenticationFactory
New-GoogleAuthenticationFactory `
	-GoogleAccessJson $jsonData `
	-Scopes  @('https://www.googleapis.com/auth/chat.admin.spaces.readonly') `
    -TargetUserEmail 'myuser@myorganization.com' `
    -Name 'chatAdminApi' `
    -AiLogger $AiLogger

$headers = Get-GoogleAccessToken -Factory 'chatAdminApi' -AsHashTable
$esponse = Invoke-RestMethod -Uri 'https://chat.googleapis.com/v1/spaces' -Headers $headers
$response.spaces
```


