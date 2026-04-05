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

.EXAMPLE
PS> Get-GoogleAccessToken

Gets the access token from the most recently created factory.

.EXAMPLE
PS> Get-GoogleAccessToken -Factory 'googleAdminApi' -AsHashTable

Gets the access token from the named factory and returns it as an Authorization header hashtable.

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
<#
.SYNOPSIS
Displays diagnostic information about a Google access token.

.DESCRIPTION
Calls the factory's token test routine to inspect the current access token. The
factory can be provided directly, looked up by name, or taken from the current
module-level default factory.

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

.OUTPUTS
System.Object
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
class GoogleTokenProvider
{
	hidden [PSCustomObject]$credential
	hidden $token
	hidden $AiLogger
	hidden $AadFactory
	hidden $WorkloadIdentityProviderResourceId
	hidden $saEmail
	hidden [string] $flowType
    [string] $Name
	[string[]] $scopes
	[string] $TargetUserEmail

	GoogleTokenProvider([string]$googleAccessJson , [string[]]$scopes, $TargetUserEmail, $Name, $AiLogger = $null)
	{
		$this.scopes = $scopes
		$this.TargetUserEmail = $TargetUserEmail
        $this.Name = $Name
		$this.credential = ConvertFrom-Json -InputObject $GoogleAccessJson -Depth 10
		$this.AiLogger = $AiLogger
		$this.flowType = 'ClientSecret'
	}
	
	GoogleTokenProvider([object]$aadFactory , [string]$workloadIdentityProviderResourceId, [string]$saEmail,  [string[]]$scopes, $Name, $AiLogger = $null)
	{
		$this.scopes = $scopes
        $this.Name = $Name
		$this.AadFactory = $aadFactory
		$this.WorkloadIdentityProviderResourceId = $workloadIdentityProviderResourceId
		$this.saEmail = $saEmail
		$this.AiLogger = $AiLogger
		$this.flowType = 'AadFederated'
	}

	[PSCustomObject]GetAccessToken([bool]$ForceRefresh)
	{
		if($null -eq $this.token -or $this.token.expiration_time -lt ([DateTime]::UtcNow) -or $ForceRefresh)
		{
			$response = $null
			$requestStart = Get-Date -AsUTC
			$tokenUri = $null
			switch($this.flowType)
			{
				'AadFederated'
				{
					$tokenUri = "https://sts.googleapis.com/v1/token"
					Write-Verbose "Getting Google access token using Azure AD federated credentials"
					$aadToken = Get-AadToken -factory $this.AadFactory
					$payload = @{
						grant_type         = "urn:ietf:params:oauth:grant-type:token-exchange"
						audience = $this.WorkloadIdentityProviderResourceId
						subject_token_type = "urn:ietf:params:oauth:token-type:jwt"
						subject_token = $aadToken.AccessToken
						scope              = ($this.Scopes -join " ")
						requested_token_type = 'urn:ietf:params:oauth:token-type:access_token'
					}
					Write-Verbose "Calling Google API to get access token: $tokenUri"
					$this.token = $this.CallGoogleTokenApi($tokenUri, 'POST', $null, ($payload | ConvertTo-Json), "application/json")

					if(-not [string]::IsNullOrEmpty($this.saEmail))
					{
						#try to exchange federated token for native google token
						Write-Verbose "Exchanging federated token for native Google access token with service account email $($this.saEmail)"
						$tokenUri = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$($this.saEmail):generateAccessToken"
						$body = @{
							"scope"= $this.scopes
							"lifetime"= "3600s"
						} | ConvertTo-Json
						$headers = @{
							Authorization = "$($this.token.token_type) $($this.token.access_token)"
						}
						$finaltoken = $this.CallGoogleTokenApi($tokenUri, 'POST', $headers, $body, "application/json")
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
					$ServiceAccountEmail = $this.credential.client_email
					Write-Verbose "Extracting private key from credential"
					$PrivateKey = $this.credential.private_key -replace '-----BEGIN PRIVATE KEY-----\n' -replace '\n-----END PRIVATE KEY-----\n' -replace '\n'
					$header = @{
						alg = "RS256"
						typ = "JWT"
					}
					$headerBase64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($header | ConvertTo-Json)))
					$timestamp = [Math]::Round((Get-Date -UFormat %s))
					
					$claimSet = @{
						iss   = $ServiceAccountEmail
						scope = ($this.Scopes -join " ")
						aud   = "https://oauth2.googleapis.com/token"
						exp   = $timestamp + 3600
						iat   = $timestamp
					}
					if(-not [string]::IsNullOrEmpty($this.TargetUserEmail))
					{
						$claimSet.sub =$this.TargetUserEmail
					}
					$claimSetBase64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($claimSet | ConvertTo-Json)))
					$signatureInput = $headerBase64 + "." + $claimSetBase64
					$signatureBytes = [System.Text.Encoding]::UTF8.GetBytes($signatureInput)
					$privateKeyBytes = [System.Convert]::FromBase64String($PrivateKey)
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
					throw "Unsupported flow type: $($this.flowType)"
				}
			}
		}

		return $this.Token
	}

    [PSCustomObject]TestAccessToken()
    {
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
			$ex = new-object System.Net.Http.HttpRequestException( $response, $null, $response.StatusCode )
			throw $ex
		}
		return ($response.Content | ConvertFrom-Json)
    }

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
			
			$ex = new-object System.Net.Http.HttpRequestException( $response, $null, $response.StatusCode )
			throw $ex
		}
	}
}
#endregion Internal commands
#region Module initialization
$script:GoogleAuthenticationProviders = @{}
#endregion Module initialization
