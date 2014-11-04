# Tests the given webserver for some possibly leaky HTTP headers

import sys, argparse
import httplib, urllib

class http_headers(object):
    def __init__(self, url, port=None, ssl=False, verbosity=True):
        self.url = url
        self.server = url.split('/')[0]
        self.path = '/'+'/'.join(url.split('/')[1:])
        self.port = port or (443 if ssl else 80)
        self.ssl = ssl
        self.verbosity = verbosity

    def getconn(self):
        if self.ssl:
            c = httplib.HTTPSConnection(self.server, self.port, timeout=5)
        else:
            c = httplib.HTTPConnection(self.server, self.port, timeout=5)
        return c

    def request(self, method, path, body=None, headers=None):
        c = self.getconn()
        headers = headers or {}
        c.request(method, path, body, headers=headers)
        return c.getresponse()

    def test(self):
        try:
            r = self.request("GET", self.path, headers={"Host":self.server})
            common      = list()
            possible    = list()
            missing     = list()
            hsts_header = False
            xframe_header = False
            xss_header  = False

            for l in r.getheaders():
                if "server" in l[0]:
                    common.append("\t"+l[0]+": "+l[1])
                elif "x-powered-by" in l[0]:
                    common.append("\t"+l[0]+": "+l[1])
                elif "x-aspnet-version" in l[0]:
                    common.append("\t"+l[0]+": "+l[1])
                elif "x-aspnetmvc-version" in l[0]:
                    common.append("\t"+l[0]+": "+l[1])
                elif "strict-transport-security" in l[0]:
                    hsts_header = True
                elif "x-frame-options" in l[0]:
                    xframe_header = True
                elif "x-xss-protection" in l[0]:
                    xss_header = True
                elif "x-" in l[0]:
                    possible.append("\t"+l[0]+": "+l[1])

            if not hsts_header:
                missing.append("\tstrict-transport-security")
            if not xss_header:
                missing.append("\tx-xss-protection")
            if not xframe_header:
                missing.append("\tx-frame-options")
    
        except Exception as e:
            print "test failed:", e

        self.print_results(common,possible,missing)

    def list_possible(self):
        r = self.request("GET", "/", headers={"Abcd":"efghij"})
        for l in r.getheaders():
            if "x-" in l[0]:
                print l[0]+":",l[1]

    def print_results(self,common,possible,missing):
        if len(common) > 0:
            print "Found the following common leaky headers:"
            for e in common:
                print e
        else:
            print "Found no common leaky headers"

        if len(possible) > 0:
            print "Found the following possibly leaky headers:"
            for e in possible:
                print e
        else:
            print "Found no other possibly leaky headers"

        if len(missing) > 0:
            print "The following security headers were missing:"
            for e in missing:
                print e
        else:
            print "Security related headers are present"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="This is a script that checks for HTTP headers that disclose too much information.")
    parser.add_argument("-p","--port", type=int, help="the webserver port")
    parser.add_argument("-s","--ssl", action="store_true", help="whether or not to use ssl")
    parser.add_argument("-v","--verbose", action="store_true", default=False, help="turn on verbose output")
    parser.add_argument("url", help="the URL to scan. Remove http://")
    args = parser.parse_args()

    url = args.url
    port = args.port
    ssl = args.ssl
    verbosity = args.verbose

    t = http_headers(url, port, ssl, verbosity)
    print "Testing for leaky headers..."
    t.test()
