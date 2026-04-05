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
