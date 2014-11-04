# grabs the robots.txt for a domain

import sys, argparse
import httplib, urllib

class robots_txt(object):
    def __init__(self, url, port=None, ssl=None, verbosity=True):
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
            r = self.request("GET", "/robots.txt", headers={"Host":self.server})
            if r.status == 200:
                contents = r.read().strip()
                if contents.length > 3 and contents not "404":
                    return contents
                else:
                    return "404"
            else:
                return "404"
        except:
            return "request failed"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="This is a script that grabs robots.txt for a domain.")
    parser.add_argument("-p","--port", type=int, help="the webserver port")
    parser.add_argument("-s","--ssl", action="store_true", help="whether or not to use ssl")
    parser.add_argument("-v","--verbose", action="store_true", default=False, help="turn on verbose output")
    parser.add_argument("url", help="the URL to scan. Remove http://")
    args = parser.parse_args()

    url = args.url
    port = args.port
    ssl = args.ssl
    verbosity = args.verbose

    t = robots_txt(url, port, ssl, verbosity)
    print "grabbing robots.txt for %s" % url
    r = t.test()
    if r:
        if r is not "404" and r is not "request failed":
            print r
    else:
        "failed"
