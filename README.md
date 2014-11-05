Fruit Picker
============
This is a set of tools used to automate some of the initial testing of a web application. 

Each test is broken out into a seperate module that can be dropped into a script or other tools. The goal is to use only Python's standard library and to make things as modular as possible. Everyone's workflow is different so this tool should be as flexible as possible. Details about each module is listed below.

Note: The parent script fruit\_picker.py is simply to illustrate what pulling the modules together into a larger testing script would look like. The emphasis here is on the modules, not the parent tool.


The following outlines the modules:

_access\_scanner.py_

- This will take a list of URLs in a seperate file (and optional credentials) and check to see what is accessible with and/or without credentials and/or with or without SSL/TLS.
- This is great for taking a sitemap or Burp history and checking to see what resources or pages are accessible wihtout credentials or without SSL/TLS. Also this can be used when checking for horizontal bypass - drop in a different user's credentials and see if they can access another user's stuff.

_cookie\_settings.py_

- This will look at cookie settings for a site and identify inadequate security settings.
- The module looks to see if the secure flag is set, the HttpOnly flag is set, and if the cookie has an expiration (meaning it is written to disk).

_http\_headers.py_

- This will look at the headers returned by the server and identify if there are headers that disclose sensitive information or if certian "security enhancing" headers are missing.
- The module checks for the presence of server, x-powered-by, x-aspnet-version, x-aspnetmvc-version, strict-transport-security, x-frame-options, x-xss-protections, and other x- headers people like to thrown in there.

_http\_methods.py_

- This will try various HTTP methods and identify any that are available and insecure.
- Note: The module will not attempt to perform a DELETE as older IIS servers can recursively delete web roots if misconfigured.

_robots\_txt.py_

- This module will grab the robots.txt for a domain if it is available.

_ssl\_protos\_and\_ciphers.py_

- This module checks what SSL/TLS versions and cipher suites are supported by the server. 
- This does not depend on OpenSSL. 
- Credit to https://thesprawl.org/projects/sslmap/ for the inspiration. 

_timing\_attack.py_

- This checks for user enumeration on the login prompt (or other forms) through timing differences in server responses.
