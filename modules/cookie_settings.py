# Tests the given webserver for some possibly leaky HTTP headers

import sys, argparse
import urllib2, cookielib

class cookie_settings(object):
    def __init__(self, url, port=None, ssl=None, verbosity=True):
        self.url = url
        self.server = url.split('/')[0]
        self.path = '/'+'/'.join(url.split('/')[1:])
        self.port = port or (443 if ssl else 80)
        self.ssl = ssl
        self.verbosity = verbosity

    def getconn(self):
        if self.ssl:
            c = httplib.HTTPSConnection(self.server, self.port, timeout=10)
        else:
            c = httplib.HTTPConnection(self.server, self.port, timeout=10)
        return c

    def request(self):
        if self.ssl:
            url = 'https://'+self.url
        else:
            url = 'http://'+self.url
        r = urllib2.urlopen(url)
        return r

    def test(self):
        r = self.request()
        cookies = r.info().getallmatchingheaders("set-cookie")
        if len(cookies) == 0:
            print "No cookies set..."
        else:
            for cookie in cookies:
                if self.verbosity:
                    print cookie.strip()
                http_only = False
                secure = False
                written_to_disk = False
                crumbs = cookie.split(";")
                print "Analyzing: "+crumbs[0].replace("Set-Cookie: ","")
                for crumb in crumbs:
                    if "httponly" in crumb.lower():
                        http_only = True
                    if "secure" in crumb.lower():
                        secure = True
                    if "expires" in crumb.lower():
                        written_to_disk = True
                if not secure:
                    print "\tSecure flag is NOT set!"
                #else:
                #    print "\tSecure flag IS set"
                if not http_only:
                    print "\tHttpOnly flag is NOT set!"
                #else:
                #    print "\tHttpOnly flag IS set"
                if written_to_disk:
                    print "\tThe cookie IS written to disk!"

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="This is a script that checks cookie settings for a website.")
    parser.add_argument("-p","--port", type=int, help="the webserver port")
    parser.add_argument("-s","--ssl", action="store_true", help="whether or not to use ssl")
    parser.add_argument("-v","--verbose", action="store_true", default=False, help="turn on verbose output")
    parser.add_argument("url", help="the URL to test. Remove http://")
    args = parser.parse_args()

    server = args.url
    port = args.port
    ssl = args.ssl
    verbosity = args.verbose

    t = cookie_settings(server, port, ssl, verbosity)
    print "Analyzing cookie settings..."
    t.test()
