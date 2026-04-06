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
						$claimSet.sub = $this.Configuration.TargetUserEmail
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
