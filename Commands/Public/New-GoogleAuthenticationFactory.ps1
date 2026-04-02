<#
.SYNOPSIS
Creates a Google authentication factory for acquiring access tokens.

.DESCRIPTION
Creates a new GoogleTokenProvider instance from service account JSON content and
requested scopes. Optionally configures user impersonation, registers the factory
under a name for later retrieval, and enables Application Insights logging.

.PARAMETER GoogleAccessJson
The raw JSON content of the Google service account credentials.

.PARAMETER Scopes
One or more Google API scopes to request when acquiring access tokens.

.PARAMETER TargetUserEmail
The email address of the user to impersonate. If omitted, no impersonation is used.

.PARAMETER Name
An optional name used to register the factory in the module-level factory dictionary.

.PARAMETER AiLogger
Optional logger instance used for Application Insights logging.

.EXAMPLE
PS> $jsonData = Get-Content -Path 'C:\service-account.json' -Raw
PS> New-GoogleAuthenticationFactory -GoogleAccessJson $jsonData -Scopes 'https://www.googleapis.com/auth/admin.directory.user.readonly'

Creates a new factory and makes it the current default factory.

.EXAMPLE
PS> New-GoogleAuthenticationFactory -GoogleAccessJson $jsonData -Scopes 'https://www.googleapis.com/auth/chat.admin.spaces.readonly' -TargetUserEmail 'user@contoso.com' -Name 'chatAdminApi'

Creates a named factory that uses user impersonation.

.OUTPUTS
GoogleTokenProvider
#>
function New-GoogleAuthenticationFactory
{
	param
	(
		[Parameter(Mandatory)]
		[string]
			#Google access JSON file content
		$GoogleAccessJson,
		
		[Parameter(Mandatory)]
		[string[]]
			#Scopes requested to be granted
		$Scopes,
		
		[Parameter()]
		[string]
			#Impersonated user email address
			# If not specified, impoersonation will not be used
		$TargetUserEmail,
		
		[Parameter()]
		[string]
			#Name of the factory instance
			# If specified, the factory will be registered in the global dictionary of Google authentication providers
		$Name,
		[Parameter()]
			#AI logger to use for logging to Application insights
			#Instance of this logger can be obtained via module AiLogging
		$AiLogger
	)

	process
	{
		if(-not [string]::IsNullOrEmpty($TargetUserEmail))
		{
			Write-Verbose "Using impersonation for user $TargetUserEmail"
		}
		$script:GoogleTokenProvider = [GoogleTokenProvider]::new($GoogleAccessJson, $scopes, $TargetUserEmail, $Name, $AiLogger)
		$script:GoogleTokenProvider
		if(-not [string]::IsNullOrEmpty($Name))
		{
			$script:GoogleAuthenticationProviders[$Name] = $script:GoogleTokenProvider
			Write-Verbose "Registered Google authentication provider with name '$Name'"
		}
	}
}
