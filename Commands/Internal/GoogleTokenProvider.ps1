class GoogleTokenProvider
{
	hidden [PSCustomObject]$credential
	hidden $token
	hidden $AiLogger
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
	}
	
	[PSCustomObject]GetAccessToken()
	{
		if($null -eq $this.token -or $this.token.expiration_time -lt ([DateTime]::UtcNow))
		{
            Write-Verbose "Fetching new access token for Google API"
			$ServiceAccountEmail = $this.credential.client_email
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
			$requestStart = Get-Date
            $tokenUri = "https://oauth2.googleapis.com/token"
			$response = Invoke-RestMethod -Uri $tokenUri -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"
			if($this.AiLogger)
			{
				Write-AiDependency -Target 'GoogleAuth' -DependencyType 'HTTP' -Name 'GetAccessToken' -Data $tokenUri -Start $requestStart -ResultCode 'Ok' -Success $true -Connection $this.AiLogger
			}

			$response | Add-Member -MemberType NoteProperty -Name expiration_time -Value ([DateTime]::UtcNow.AddSeconds($response.expires_in)) -PassThru
            $response.psobject.TypeNames.Insert(0,"Google.AccessToken")
			$this.Token = $response
		}
		return $this.token
	}

    [PSCustomObject]TestAccessToken()
    {
		$t = $this.GetAccessToken()
		$headers = @{
			Authorization = "$($t.token_type) $($t.access_token)"
		}
        $tokenUri = 'https://www.googleapis.com/oauth2/v3/tokeninfo'
        $requestStart = Get-Date
		$response = Invoke-RestMethod -Uri $tokenUri -Headers $headers
        if($this.AiLogger)
        {
            Write-AiDependency -Target 'GoogleAuth' -DependencyType 'HTTP' -Name 'TestAccessToken' -Data $tokenUri -Start $requestStart -ResultCode 'Ok' -Success $true -Connection $this.AiLogger
        }

		return $response
    }
}
