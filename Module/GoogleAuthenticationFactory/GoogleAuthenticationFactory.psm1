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
            Write-Verbose "Extracting private kay from credential"
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
			$requestStart = Get-Date -AsUTC
            $tokenUri = "https://oauth2.googleapis.com/token"
            Write-Verbose "Calling Google API to get access token: $tokenUri"
			$response = Invoke-WebRequest -Uri $tokenUri -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -SkipHttpErrorCheck
			if($response.StatusCode -eq [System.Net.HttpStatusCode]::OK)
			{
				if($this.AiLogger)
				{
					Write-AiDependency -Target 'GoogleAuth' -DependencyType 'HTTP' -Name 'GetAccessToken' -Data $tokenUri -Start $requestStart -ResultCode 'Ok' -Success $true -Connection $this.AiLogger
				}
				#when succeeded, response is the token object, we add the expiration_time property to it for easier caching and check later
				$responseToken = $response.Content | ConvertFrom-Json 
				$responseToken | Add-Member -MemberType NoteProperty -Name expiration_time -Value ([DateTime]::UtcNow.AddSeconds($responseToken.expires_in))
	            $responseToken.psobject.TypeNames.Insert(0,"Google.AccessToken")
				$this.Token = $responseToken
			}
			else
			{
				if($this.AiLogger)
				{
					Write-AiDependency -Target 'GoogleAuth' -DependencyType 'HTTP' -Name 'GetAccessToken' -Data $tokenUri -Start $requestStart -ResultCode $response.StatusCode.ToString() -Success $false -Connection $this.AiLogger
				}
				
				$ex = new-object System.Net.Http.HttpRequestException( $response, $null, $response.StatusCode )
				throw $ex
			}
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
}
#endregion Internal commands
#region Module initialization
$script:GoogleAuthenticationProviders = @{}
#endregion Module initialization
