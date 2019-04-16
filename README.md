# burp-authorization-header-updater
A burp plugin that can be used in combination with macros to update request authorization headers within burp tools

* This plugin was built following using TwelveSec security's blog post (https://www.twelvesec.com/2017/05/05/authorization-token-manipulation/) as a starting point
* This combines the two separate plugins written in multiple languages (Python and Java) and compresses them into a single Python extenstion for BurpSuite.
      * Java plugin is available on the @TwelveSec github: https://github.com/twelvesec/BearerAuthToken
      * Python version is available in the aforementioned blog post

## An important note:
* The actual value for the authorization header is dependent on the setup I was testing which was not your typical setup, however, simple tweaking what is checked in the requests/responses should hopefully be somewhat easy.  
* The extension assumes you are able to hit a route with a valid session/cookie to retrieve a new authorization header.  To update the header to check for and modify simply update the variable: AUTH_HEADER_PREFIX to reflect the string value of your header, original was: "Authorization: Bearer "
