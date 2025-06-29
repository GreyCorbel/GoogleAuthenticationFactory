#region Public commands
function Get-GoogleAccessToken
{
	param
	(
		[switch]$AsHashTable,
		[Parameter()]
		$Factory = $script:GoogleTokenProvider
	)

	process
	{
        if($Factory -is [string])
        {
            #name of factory has been passed
            $Factory = Get-GoogleAuthenticationFactory -Name $Factory
        }
		$token = $Factory.GetAccessToken()
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
#endregion Internal commands
#region Module initialization
$script:GoogleAuthenticationProviders = @{}
#endregion Module initialization
