#region Public commands
<#
.SYNOPSIS
Gets an OAuth access token from a Google authentication factory.

.DESCRIPTION
Retrieves an access token from the supplied factory instance, the named factory,
or the most recently created factory stored in the module scope. Use -AsHashTable
to return an Authorization header that can be passed directly to Invoke-RestMethod
or Invoke-WebRequest.

.PARAMETER AsHashTable
Returns a hashtable containing the Authorization header instead of the raw token object.

.PARAMETER Factory
The authentication factory instance to use. You can pass a factory object or the
name of a registered factory. If omitted, the current module-level default factory
is used.

.PARAMETER ForceRefresh
Forces acquisition of a new token instead of reusing a cached valid token.

.EXAMPLE
PS> Get-GoogleAccessToken

Gets the access token from the most recently created factory.

.EXAMPLE
PS> Get-GoogleAccessToken -Factory 'googleAdminApi' -AsHashTable

Gets the access token from the named factory and returns it as an Authorization header hashtable.

.EXAMPLE
PS> Get-GoogleAccessToken -Factory 'googleAdminApi' -ForceRefresh

Forces a fresh token retrieval from the named factory.

.OUTPUTS
System.Collections.Hashtable
Google access token object
#>
function Get-GoogleAccessToken
{
	param
	(
		[switch]$AsHashTable,
		[Parameter()]
		$Factory = $script:GoogleTokenProvider,
		[switch]$ForceRefresh
	)

	process
	{
        if($Factory -is [string])
        {
            #name of factory has been passed
            $Factory = Get-GoogleAuthenticationFactory -Name $Factory
        }
		$token = $Factory.GetAccessToken($ForceRefresh)
		if($AsHashTable)
		{
			@{
				Authorization = "$($token.token_type) $($token.access_token)"
			}
		}
		else
		{
			$token
		}
	}
}
<#
.SYNOPSIS
Gets one or more registered Google authentication factories.

.DESCRIPTION
Returns a registered factory by name, all registered factories, or the current
default factory when no parameters are specified.

.PARAMETER Name
The name of a registered factory to retrieve.

.PARAMETER All
Returns all registered factories instead of only the current default factory.

.EXAMPLE
PS> Get-GoogleAuthenticationFactory

Returns the current default Google authentication factory.

.EXAMPLE
PS> Get-GoogleAuthenticationFactory -Name 'chatAdminApi'

Returns the registered factory with the specified name.

.EXAMPLE
PS> Get-GoogleAuthenticationFactory -All

Returns all registered Google authentication factories.

.OUTPUTS
GoogleTokenProvider
System.Object[]
#>

function Get-GoogleAuthenticationFactory
{
	param
	(
		[Parameter()]
		[string]$Name,
		[switch]$All
	)

	process
	{
		if(-not [string]::IsNullOrEmpty($Name))
		{
			if($script:GoogleAuthenticationProviders.ContainsKey($Name))
			{
				return $script:GoogleAuthenticationProviders[$Name]
			}
			else
			{
				Write-Warning "No Google authentication provider registered with name '$Name'"
				return $null
			}
		}
		else
		{
			if($all)
			{
				return $script:GoogleAuthenticationProviders.Values
			}
			else
			{
				return $script:GoogleTokenProvider
			}
		}
	}
}
<#
.SYNOPSIS
Creates a Google authentication factory for acquiring access tokens.

.DESCRIPTION
Creates a new GoogleTokenProvider instance using either service account JSON
credentials or Azure AD federated credentials, then stores it as the current
module-level default provider. Optionally registers the provider by name and
enables Application Insights logging. In the federated flow, you can optionally
exchange the federated token for a service-account access token by supplying
`-ServiceAccountEmail`.

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
The Google service account email used to exchange the federated token for a
native Google service-account access token. If omitted, the factory uses the
federated token directly.

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
			#email address of the service account to impersonate. If not specified, the factory will use the federated token directly without exchanging for a service account token.
			#Important: to be able to impersonate, the federated identity must have "Service Account Token Creator" role on the target service account
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
<#
.SYNOPSIS
Displays diagnostic information about a Google access token.

.DESCRIPTION
Calls the factory's token test routine to inspect the current access token. The
factory can be provided directly, looked up by name, or taken from the current
module-level default factory. Direct federated tokens are not supported by the
Google token inspection endpoint used by this command; in that case the command
returns `$null` and writes a warning.

.PARAMETER Factory
The authentication factory instance to test. You can pass a factory object or the
name of a registered factory. If omitted, the current module-level default factory
is used.

.EXAMPLE
PS> Test-GoogleAccessToken

Tests the access token for the current default factory.

.EXAMPLE
PS> Test-GoogleAccessToken -Factory 'googleAdminApi'

Tests the access token for the named factory.

.EXAMPLE
PS> Test-GoogleAccessToken -Factory 'federatedApi'

Tests the token for the named factory when the factory is configured to exchange
the federated token for a service-account token.

.OUTPUTS
System.Object
System.Management.Automation.WarningRecord
#>
function Test-GoogleAccessToken {
    [CmdletBinding()]
	param
	(
		[Parameter()]
		$Factory = $script:GoogleTokenProvider
	)

    process
    {
        if($Factory -is [string])
        {
            #name of factory has been passed
            $Factory = Get-GoogleAuthenticationFactory -Name $GoogleTokenProvider
        }
        $Factory.TestAccessToken()
    }
}
#endregion Public commands
#region Internal commands
<#
.SYNOPSIS
Internal token provider used by the module public commands.

.DESCRIPTION
`GoogleTokenProvider` encapsulates token acquisition, caching, refresh logic,
and token diagnostics for Google APIs. It supports two authentication flows:

- `ClientSecret`: Service account JSON private key flow (optionally with user impersonation).
- `AadFederated`: Azure AD token exchange with Google STS (optionally followed by
	service account access token generation).

The class is internal to the module and is created by `New-GoogleAuthenticationFactory`.
#>
class GoogleTokenProvider
{
    [string] $Name
	[string[]] $Scopes
	[string] $FlowType
	hidden $token
	hidden [PSCustomObject]$Configuration

	# Initializes provider configuration for service-account JSON authentication.
	# The JSON must contain `client_email` and `private_key` fields.
	GoogleTokenProvider([string]$googleAccessJson , [string[]]$scopes, $TargetUserEmail, $Name, $AiLogger = $null)
	{
		$this.FlowType = 'ClientSecret'
		$this.Name = $Name
		$this.Scopes = $scopes
		$Credential = ConvertFrom-Json -InputObject $GoogleAccessJson -Depth 10
		$this.Configuration = [PSCustomObject]@{
			AiLogger = $AiLogger
			ServiceAccountEmail = $Credential.client_email
			TargetUserEmail = $TargetUserEmail
			PrivateKey = $Credential.private_key -replace '-----BEGIN PRIVATE KEY-----\n' -replace '\n-----END PRIVATE KEY-----\n' -replace '\n'
		}
	}
	
	# Initializes provider configuration for Azure AD federated authentication.
	# The provider can optionally exchange the federated token for a native
	# service-account token when ServiceAccountEmail is supplied.
	GoogleTokenProvider([object]$aadFactory , [string]$workloadIdentityProviderResourceId, [string]$saEmail,  [string[]]$scopes, $Name, $AiLogger = $null)
	{
		$this.FlowType = 'AadFederated'
		$this.Name = $Name
		$this.Scopes = $scopes
		$this.Configuration = [PSCustomObject]@{
			AiLogger = $AiLogger
			ServiceAccountEmail = $saEmail
			AadFactory = $aadFactory
			WorkloadIdentityProviderResourceId = $workloadIdentityProviderResourceId
		}
	}

	# Returns a cached token when valid, otherwise acquires a new one.
	# Set ForceRefresh to bypass cache and always request a new token.
	[PSCustomObject]GetAccessToken([bool]$ForceRefresh)
	{
		if($null -eq $this.token -or $this.token.expiration_time -lt ([DateTime]::UtcNow) -or $ForceRefresh)
		{
			switch($this.FlowType)
			{
				'AadFederated'
				{
					$tokenUri = "https://sts.googleapis.com/v1/token"
					Write-Verbose "Getting Google access token using Azure AD federated credentials"
					$aadToken = Get-AadToken -factory $this.Configuration.AadFactory
					$payload = @{
						grant_type         = "urn:ietf:params:oauth:grant-type:token-exchange"
						audience           = $this.Configuration.WorkloadIdentityProviderResourceId
						subject_token_type = "urn:ietf:params:oauth:token-type:jwt"
						subject_token      = $aadToken.AccessToken
						scope              = ($this.Scopes -join " ")
						requested_token_type = 'urn:ietf:params:oauth:token-type:access_token'
					}
					Write-Verbose "Calling Google API to get access token: $tokenUri"
					$this.token = $this.CallGoogleTokenApi($tokenUri, 'POST', $null, ($payload | ConvertTo-Json), "application/json")

					if(-not [string]::IsNullOrEmpty($this.Configuration.ServiceAccountEmail))
					{
						#try to exchange federated token for native google token
						Write-Verbose "Exchanging federated token for native Google access token with service account email $($this.Configuration.ServiceAccountEmail)"
						$tokenUri = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$($this.Configuration.ServiceAccountEmail)`:generateAccessToken"
						$payload = @{
							"scope"= $this.Scopes
							"lifetime"= "3600s"
						}
						$headers = @{
							Authorization = "$($this.token.token_type) $($this.token.access_token)"
						}
						$finaltoken = $this.CallGoogleTokenApi($tokenUri, 'POST', $headers, ($payload | ConvertTo-Json)	, "application/json")
						#token comes in different shape from this endpoint, we need to map it back to the same shape as the original token for caching and later use
						$this.token.access_token = $finaltoken.accessToken
						$this.token.expiration_time = $finaltoken.expireTime
					}
					break;
				}
				'ClientSecret'
				{
					Write-Verbose "Getting Google access token using client secret flow"
		            Write-Verbose "Fetching new access token for Google API"
					$tokenUri = "https://oauth2.googleapis.com/token"
					$header = @{
						alg = "RS256"
						typ = "JWT"
					}
					$headerBase64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($header | ConvertTo-Json)))
					$timestamp = [Math]::Round((Get-Date -UFormat %s))
					
					$claimSet = @{
						iss   = $this.Configuration.ServiceAccountEmail
						scope = ($this.Scopes -join " ")
						aud   = "https://oauth2.googleapis.com/token"
						exp   = $timestamp + 3600
						iat   = $timestamp
					}
					if(-not [string]::IsNullOrEmpty($this.Configuration.TargetUserEmail))
					{
						$claimSet.sub =$this.Configuration.TargetUserEmail
					}
					$claimSetBase64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($claimSet | ConvertTo-Json)))
					$signatureInput = $headerBase64 + "." + $claimSetBase64
					$signatureBytes = [System.Text.Encoding]::UTF8.GetBytes($signatureInput)
					$privateKeyBytes = [System.Convert]::FromBase64String($this.Configuration.PrivateKey)
					$rsaProvider = [System.Security.Cryptography.RSA]::Create()
					$bytesRead = $null
					$rsaProvider.ImportPkcs8PrivateKey($privateKeyBytes, [ref]$bytesRead)
					$signature = $rsaProvider.SignData($signatureBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
					$signatureBase64 = [System.Convert]::ToBase64String($signature)
					$jwt = $headerBase64 + "." + $claimSetBase64 + "." + $signatureBase64
					$body = @{
						grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"
						assertion  = $jwt
					}
					Write-Verbose "Calling Google API to get access token: $tokenUri"
					$this.token = $this.CallGoogleTokenApi($tokenUri, 'POST', $null, $body, "application/x-www-form-urlencoded")
					
					break;
				}
				default
				{
					throw "Unsupported flow type: $($this.FlowType)"
				}
			}
		}
		return $this.Token
	}

	# Validates the current token by calling Google's tokeninfo endpoint.
	# Returns token metadata when validation succeeds.
    [PSCustomObject]TestAccessToken()
    {
		if($this.FlowType -eq 'AadFederated' -and [string]::IsNullOrEmpty($this.Configuration.ServiceAccountEmail))
		{
			Write-Warning "Test-GoogleAccessToken is not supported for Federated access tokens"
			return $null
		}
		$t = $this.GetAccessToken($false)
		$headers = @{
			Authorization = "$($t.token_type) $($t.access_token)"
		}
        $tokenUri = 'https://www.googleapis.com/oauth2/v3/tokeninfo'
        Write-Verbose "Calling Google API to test access token: $tokenUri"
        $requestStart = Get-Date -AsUTC
		$response = Invoke-WebRequest -Uri $tokenUri -Headers $headers -SkipHttpErrorCheck
        if($this.AiLogger)
        {
            Write-AiDependency -Target 'GoogleAuth' -DependencyType 'HTTP' -Name 'TestAccessToken' `
				-Data $tokenUri -Start $requestStart `
				-ResultCode $response.StatusCode.ToString() `
				-Success ($response.StatusCode -eq [System.Net.HttpStatusCode]::OK) `
				-Connection $this.AiLogger
        }
		if($response.StatusCode -ne [System.Net.HttpStatusCode]::OK)
		{
			$ex = new-object System.Net.Http.HttpRequestException( $response.Content, $null, $response.StatusCode )
			throw $ex
		}
		return ($response.Content | ConvertFrom-Json)
    }

	# Executes token-related HTTP calls and normalizes successful responses
	# into the module's `Google.AccessToken` shape.
	hidden [PSCustomObject] CallGoogleTokenApi($uri, $method,  $headers, $body, $contentType)
	{
		Write-Verbose "Calling Google API: $uri"
		$requestStart = Get-Date -AsUTC
		$response = Invoke-WebRequest `
						-Uri $uri `
						-Method $method `
						-Body $body `
						-Headers $headers `
						-ContentType $contentType `
						-SkipHttpErrorCheck
		if($response.StatusCode -eq [System.Net.HttpStatusCode]::OK)
		{
			if($this.AiLogger)
			{
				Write-AiDependency -Target 'GoogleAuth' -DependencyType 'HTTP' -Name 'GetAccessToken' -Data $uri -Start $requestStart -ResultCode 'Ok' -Success $true -Connection $this.AiLogger
			}
			#when succeeded, response is the token object, we add the expiration_time property to it for easier caching and check later
			$responseToken = $response.Content | ConvertFrom-Json 
			$responseToken | Add-Member -MemberType NoteProperty -Name expiration_time -Value ([DateTime]::UtcNow.AddSeconds($responseToken.expires_in))
			$responseToken.psobject.TypeNames.Insert(0,"Google.AccessToken")
			return $responseToken
		}
		else
		{
			if($this.AiLogger)
			{
				Write-AiDependency -Target 'GoogleAuth' -DependencyType 'HTTP' -Name 'GetAccessToken' -Data $uri -Start $requestStart -ResultCode $response.StatusCode.ToString() -Success $false -Connection $this.AiLogger
			}
			
			$ex = new-object System.Net.Http.HttpRequestException( $response.Content, $null, $response.StatusCode )
			throw $ex
		}
	}
}
#endregion Internal commands
#region Module initialization
$script:GoogleAuthenticationProviders = @{}
#endregion Module initialization
