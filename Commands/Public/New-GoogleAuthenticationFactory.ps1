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
