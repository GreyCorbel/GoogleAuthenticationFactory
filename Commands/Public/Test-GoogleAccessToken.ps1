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