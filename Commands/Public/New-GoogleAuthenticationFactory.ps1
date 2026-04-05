<#
.SYNOPSIS
Creates a Google authentication factory for acquiring access tokens.

.DESCRIPTION
Creates a new GoogleTokenProvider instance using either service account JSON
credentials or Azure AD federated credentials, then stores it as the current
module-level default provider. Optionally registers the provider by name and
enables Application Insights logging.

.PARAMETER GoogleAccessJson
The raw JSON content of the Google service account credentials.

Used by parameter set: ClientSecret.

.PARAMETER AadAuthenticationFactory
An Azure AD authentication factory configured for workload identity federation.

Used by parameter set: AadFederated.

.PARAMETER WorkloadIdentityProviderResourceId
The full Google workload identity provider resource identifier configured for
federated identity.

Used by parameter set: AadFederated.

.PARAMETER ServiceAccountEmail
The Google service account email to impersonate for federated credentials.

Used by parameter set: AadFederated.

.PARAMETER Scopes
One or more Google API scopes to request when acquiring access tokens.

.PARAMETER TargetUserEmail
The email address of the user to impersonate. If omitted, no impersonation is used.

Used by parameter set: ClientSecret.

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
PS> New-GoogleAuthenticationFactory -AadAuthenticationFactory $aadFactory -WorkloadIdentityProviderResourceId '//iam.googleapis.com/projects/132546827814/locations/global/workloadIdentityPools/my-pool/providers/entra-id-mytenant-com' -ServiceAccountEmail 'service-account@project-id.iam.gserviceaccount.com' -Scopes 'https://www.googleapis.com/auth/cloud-platform' -Name 'federatedApi'

Creates a named factory using Azure AD federated credentials.

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
		
		[Parameter(ParameterSetName='ClientSecret')]
		[string]
			#Impersonated user email address
			# If not specified, impoersonation will not be used
		$TargetUserEmail,

		[Parameter(Mandatory, ParameterSetName='AadFederated')]
		[object]
			#instance of AAD Authentication Factory configured for federated credentials
		$AadAuthenticationFactory,

		[Parameter(Mandatory, ParameterSetName='AadFederated')]
		[string]
			#Resource ID of the Google workload identity provider configured in Azure AD
			#Example: //iam.googleapis.com/projects/132546827814/locations/global/workloadIdentityPools/my-pool/providers/entra-id-mytenant-com
		$WorkloadIdentityProviderResourceId,

		[Parameter(ParameterSetName='AadFederated')]
		[string]
			#Resource ID of the Google workload identity provider configured in Azure AD
			#Example: //iam.googleapis.com/projects/132546827814/locations/global/workloadIdentityPools/my-pool/providers/entra-id-mytenant-com
		$ServiceAccountEmail,
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
		switch($PSCmdlet.ParameterSetName)
		{
			'AadFederated'
			{
				Write-Verbose "Creating Google authentication factory using Azure AD federated credentials"
				$script:GoogleTokenProvider = [GoogleTokenProvider]::new($AadAuthenticationFactory, $WorkloadIdentityProviderResourceId, $ServiceAccountEmail, $Scopes, $Name, $AiLogger)
				break;
			}
			'ClientSecret'
			{
				if(-not [string]::IsNullOrEmpty($TargetUserEmail))
				{
					Write-Verbose "Using impersonation for user $TargetUserEmail"
				}
				Write-Verbose "Creating Google authentication factory using JSON credentials"
				$script:GoogleTokenProvider = [GoogleTokenProvider]::new($GoogleAccessJson, $Scopes, $TargetUserEmail, $Name, $AiLogger)
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
