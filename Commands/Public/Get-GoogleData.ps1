<#
.SYNOPSIS
Retrieves paged data from a Google REST endpoint.

.DESCRIPTION
Calls a Google API endpoint repeatedly until all pages are returned. When the
response includes `nextPageToken`, the command automatically requests the next
page by updating the `pageToken` query parameter.

By default, the full response object for each page is returned. Use
`-DataProperty` to output only a specific property from each page (for example,
`users`, `groups`, or `spaces`).

.PARAMETER Uri
The full Google API endpoint URI to call.

The URI can include query parameters; they are preserved and extended with
`pageToken` when paging is required.

.PARAMETER DataProperty
Optional response property name to emit instead of full page objects.

When provided, each item from `$response.<DataProperty>` is written to the
pipeline.

.PARAMETER Factory
The authentication factory instance used to get access tokens for API calls.

If omitted, the current default factory returned by
`Get-GoogleAuthenticationFactory` is used.

.EXAMPLE
PS> Get-GoogleData -Uri 'https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer' -DataProperty 'users'

Returns all users across pages from Google Admin SDK Directory API.

.EXAMPLE
PS> $factory = Get-GoogleAuthenticationFactory -Name 'chatAdminApi'
PS> Get-GoogleData -Uri 'https://chat.googleapis.com/v1/spaces?pageSize=100' -DataProperty 'spaces' -Factory $factory

Returns all Google Chat spaces using a specific authentication factory.

.OUTPUTS
System.Object
#>
function Get-GoogleData
{
	param
	(
		[Parameter(Mandatory)]
		[string]$uri,
		[Parameter()]
		[string]$dataProperty,
		[Parameter()]
		[PSCustomObject]$factory = (Get-GoogleAuthenticationFactory)
	)

	begin
	{
        if($null -eq $factory)
		{
			throw "Token provider is not set. Please call New-GoogleAuthenticationFactory first"
		}
	}

	process
	{
        $uriBuilder = new-object UriBuilder($uri)
        #we ned to parse query from uri to be able to modify it for pagination, and for logging we need the base uri without query params
        $query = [system.web.httpUtility]::ParseQueryString($uriBuilder.query)
        $baseUri  = "$($uriBuilder.scheme)://$($uriBuilder.host)$($uriBuilder.path)"

		$nextPageToken = $null
		do
		{
            $url = "$baseUri`?$($query.ToString())"
			$response = Invoke-GoogleWithRetry -Uri $url -factory $factory
			$nextPageToken = $response.nextPageToken
			if($null -ne $nextPageToken)
			{
                $query['pageToken'] = $nextPageToken
			}
			if([string]::IsNullOrEmpty($dataProperty))
			{
				 $response
			}
			else
			{
				$response.$dataProperty | foreach-object {
                    $_
                }
			}
		}while($null -ne $nextPageToken)
	}
}
