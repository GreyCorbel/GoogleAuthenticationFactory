<#
.SYNOPSIS
Creates a Google authentication factory for acquiring access tokens.

.DESCRIPTION
Creates a new GoogleTokenProvider instance using either service account JSON
credentials or Azure AD federated credentials, then stores it as the current
module-level default provider. Optionally registers the provider by name and
enables Application Insights logging. You can optionally enable impersonation by
supplying `-ImpersonationEmail`.

.PARAMETER GoogleAccessJson
The raw JSON content of the Google service account credentials.

Used by parameter set: ClientSecret.

.PARAMETER AadAuthenticationFactory
An Azure AD authentication factory configured for workload identity federation.

Used by parameter set: AadFederated.

.PARAMETER WorkloadIdentityProviderResourceId
The full Google workload identity provider resource identifier configured for
federated identity.

Must start with `//`.

Used by parameter set: AadFederated.

.PARAMETER ImpersonationEmail
The email address to impersonate.

For service account JSON credentials, this is the user email to impersonate.
For Azure AD federated credentials, this is the Google service account email to
impersonate. If omitted, no impersonation is used.

`TargetUserEmail` is supported as an alias for backward compatibility.

.PARAMETER Scopes
One or more Google API scopes to request when acquiring access tokens.

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

.EXAMPLE
PS> New-GoogleAuthenticationFactory -AadAuthenticationFactory $aadFactory -WorkloadIdentityProviderResourceId '//iam.googleapis.com/projects/132546827814/locations/global/workloadIdentityPools/my-pool/providers/entra-id-mytenant-com' -ImpersonationEmail 'service-account@project-id.iam.gserviceaccount.com' -Scopes 'https://www.googleapis.com/auth/cloud-platform' -Name 'federatedApi'

Creates a named factory using Azure AD federated credentials.

.EXAMPLE
PS> New-GoogleAuthenticationFactory -AadAuthenticationFactory $aadFactory -WorkloadIdentityProviderResourceId '//iam.googleapis.com/projects/132546827814/locations/global/workloadIdentityPools/my-pool/providers/entra-id-mytenant-com' -Scopes 'https://www.googleapis.com/auth/cloud-platform' -Name 'federatedApi'

Creates a named factory that uses the federated token directly without service-account exchange.

.OUTPUTS
GoogleTokenProvider
#>
function New-GoogleAuthenticationFactory
{
	param
	(
		[Parameter(Mandatory, ParameterSetName='ClientSecret')]
		[string]
			#Google access JSON file content
		$GoogleAccessJson,
		
		[Parameter()]
		[Alias('TargetUserEmail')]
		[string]
			#For authentication with GoogleAccessJson, it's email address of user to impersonate.
			#For authentication with AAD federated credentials, it's email address of service account to impersonate.
			#Important: For service account impersonation, the federated identity must have "Service Account Token Creator" role on the target service account
			#If not specified, the factory will use:
			#- For GoogleAccessJson authentication: the service account itself without impersonation
			#- For AAD federated authentication: the federated token directly without exchanging for a service account token
		$ImpersonationEmail,

		[Parameter(Mandatory, ParameterSetName='AadFederated')]
		[object]
			#instance of AAD Authentication Factory configured for federated credentials
		$AadAuthenticationFactory,

		[Parameter(Mandatory, ParameterSetName='AadFederated')]
		[ValidatePattern('^//')]
		[string]
			#Resource ID of the Google workload identity provider configured in Azure AD
			#Example: //iam.googleapis.com/projects/132546827814/locations/global/workloadIdentityPools/my-pool/providers/entra-id-mytenant-com
		$WorkloadIdentityProviderResourceId,

		[Parameter(Mandatory)]
		[string[]]
			#Scopes requested to be granted
		$Scopes,
		
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
		$script:AiLogger = $AiLogger
		
		switch($PSCmdlet.ParameterSetName)
		{
			'AadFederated'
			{
				if(-not [string]::IsNullOrEmpty($ImpersonationEmail))
				{
					Write-Verbose "Using impersonation for service account $ImpersonationEmail"
				}
				Write-Verbose "Creating Google authentication factory using Azure AD federated credentials"
				$script:GoogleTokenProvider = [GoogleTokenProvider]::new($AadAuthenticationFactory, $WorkloadIdentityProviderResourceId, $ImpersonationEmail, $Scopes, $Name, $AiLogger)
				break;
			}
			'ClientSecret'
			{
				if(-not [string]::IsNullOrEmpty($ImpersonationEmail))
				{
					Write-Verbose "Using impersonation for user $ImpersonationEmail"
				}
				Write-Verbose "Creating Google authentication factory using JSON credentials"
				$script:GoogleTokenProvider = [GoogleTokenProvider]::new($GoogleAccessJson, $Scopes, $ImpersonationEmail, $Name, $AiLogger)
				break;
			}
			default
			{
				throw "Invalid parameter set: $($PSCmdlet.ParameterSetName)"
			}
		}
		if(-not [string]::IsNullOrEmpty($Name))
		{
			$script:GoogleAuthenticationProviders[$Name] = $script:GoogleTokenProvider
			Write-Verbose "Registered Google authentication provider with name '$Name'"
		}
		$script:GoogleTokenProvider
	}
}
