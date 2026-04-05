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