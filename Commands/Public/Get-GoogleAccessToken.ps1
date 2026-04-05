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
