Fruit Picker
============
This is a script to automate some of the initial testing of a web application. The following outlines the scripts:

access_scanner.py

- This will take a list of URLs and optional credentials and check to see what is accessible with and/or without credentials and/or with or without SSL/TLS.

cookie_settings.py

- This will look at cookie settings for a site and identify inadequate security settings.

http_headers.py

- This will look at the headers returned by the server and identify what is too verbose or missing.

http_methods.py

- This will try various HTTP methods and identify any that are available and insecure

robots_txt.py

- A little script to grab robots.txt on a list of domains

ssl_protos_and_ciphers.py

- This check what SSL/TLS versions and cipher suites are supported by the server. This does not depend on OpenSSL.

timing_attack.py

- This checks for user enumeration on the login prompt (or other forms) through timing differences in server responses.