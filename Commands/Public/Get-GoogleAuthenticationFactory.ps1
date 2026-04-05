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
