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
