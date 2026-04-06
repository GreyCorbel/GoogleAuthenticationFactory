<#
.SYNOPSIS
Invokes a Google REST API request with retry logic for transient failures.

.DESCRIPTION
Sends an authenticated HTTP request to a Google endpoint using the provided (or
default) authentication factory. The command retries transient failures up to
10 times for status codes `500`, `502`, `503`, `504`, and `429`.

For `Post`, `Put`, and `Patch`, the request body is sent from `-Payload` with
the specified `-ContentType`.

.PARAMETER Uri
The Google API request URI.

.PARAMETER Method
The HTTP method to use. Supported values: `Get`, `Post`, `Put`, `Delete`,
`Patch`.

.PARAMETER Payload
Request body payload used for `Post`, `Put`, or `Patch` requests.

.PARAMETER ContentType
The HTTP content type for body requests.

Defaults to `application/json`.

.PARAMETER Factory
The authentication factory instance used to acquire the Authorization header.

If omitted, the current default factory returned by
`Get-GoogleAuthenticationFactory` is used.

.EXAMPLE
PS> Invoke-GoogleWithRetry -Uri 'https://chat.googleapis.com/v1/spaces'

Performs an authenticated GET request and retries on transient errors.

.EXAMPLE
PS> $payload = '{"displayName":"My Space"}'
PS> Invoke-GoogleWithRetry -Uri 'https://chat.googleapis.com/v1/spaces' -Method Post -Payload $payload -ContentType 'application/json'

Creates a Google Chat space using an authenticated POST request with retry behavior.

.OUTPUTS
System.Object
#>
function Invoke-GoogleWithRetry
{
	param
	(
		[Parameter(Mandatory)]
		[string]$Uri,
		[Parameter()]
		[ValidateSet('Get', 'Post', 'Put', 'Delete','Patch')]
		$Method = 'Get',
		[Parameter()]
		[string]$Payload = [string]::Empty,
		[Parameter()]
		[string]$ContentType = 'application/json',
		[PSCustomObject]$factory = (Get-GoogleAuthenticationFactory)
	)

	begin
	{
        if($null -eq $factory)
		{
			throw "Token provider is not set. Please call New-GoogleAuthenticationFactory first"
		}
		$maxRetries = 10
		$retryableStatusCodes = @(500, 502, 503, 504, 429)
	}

	process
	{
		#for logging - we need to remove query params from the URI
		$uriBuilder = new-object UriBuilder($uri)
        $baseUri  = "$($uriBuilder.scheme)://$($uriBuilder.host)$($uriBuilder.path)"

		$retries = 0
		$headers = Get-GoogleAccessToken -AsHashTable -Factory $factory
		do
		{
			$resultCode = 'Ok'
			try
			{
				$requestStart = Get-Date -AsUTC
				switch($Method)
				{
					{$_ -in @('Get', 'Delete')} {
						$response = Invoke-RestMethod -Uri $Uri -Method $Method -Headers $headers -ErrorAction Stop
						break;
					}
					{$_ -in @('Post', 'Patch', 'Put')} {
						$response = Invoke-RestMethod -Uri $Uri -Method $Method -Body $Payload -Headers $headers -ContentType $ContentType -ErrorAction Stop
						break;
					}
				}
				$response
				break;
			}
			catch
			{
				$e = $_
				$retryable = $false
				if($null -ne $e.exception.statusCode)
				{
					$retryable = ($e.exception.statusCode -in $retryableStatusCodes)
					$resultCode = $e.exception.statusCode.ToString()
				}
				else
				{
					$resultCode = 'Unknown'
				}

				if($retryable -eq $false -or $retries -ge $maxRetries)
				{
					throw
				}
				#let's retry
				$details = $e.ErrorDetails | ConvertFrom-json -ErrorAction SilentlyContinue
				if($null -ne $details.Error.Code)
				{
					$errorMessage = "$($details.Error.Code) - $($details.Error.Message)"
				}
				else
				{
					$errorMessage = "$($e.Exception.Message)"
				}

				$retries++
				Write-Verbose "Retrying due to status code $($e.exception.statusCode) - $errorMessage"
				Start-Sleep -Seconds (10 * $retries)
			}
			finally
			{
				if($null -ne $script:AiLogger)
				{
					Write-AiDependency `
					-Target 'GoogleApi' `
					-DependencyType 'HTTP' `
					-Name 'InvokeGoogleWithRetry' `
					-Data $baseUri `
					-Start $requestStart `
					-ResultCode $resultCode `
					-Success ($resultCode -eq 'Ok') `
					-Connection $script:AiLogger
				}
			}
		}while($true)
	}
}
