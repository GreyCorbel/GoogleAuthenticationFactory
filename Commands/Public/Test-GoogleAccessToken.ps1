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