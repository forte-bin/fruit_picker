# Tests the given urls for unauthenticated and/or insecure access

import sys, argparse
import httplib, urllib

class access_scanner(object):
    def __init__(self, urls_file=None, verbosity=False, port=None, ssl=None):
        self.urls_file = urls_file
        self.verbosity = verbosity
        self.ssl = ssl
        self.port = port or (443 if ssl else 80)

    def get_urls(self, urls_file):
        f = open(urls_file, "r")
        urls = list()
        for url in f:
            urls.append(url)
        return urls

    def get_cookie_jar(self, cookie_jar):
        f = open(cookie_jar, "r")
        return {"Cookie":f.read().replace("\n"," ").replace("\r","").strip()}

    def get_connection(self, server):
        if self.ssl:
            connection = httplib.HTTPSConnection(server, self.port, timeout=10)
        else:
            connection = httplib.HTTPConnection(server, self.port, timeout=10)
        return connection

    def request(self, method, server, path, headers):
        connection = self.get_connection(server)
        headers = headers or {}
        connection.request(method, path, headers=headers)
        response = None
        try:
            response = connection.getresponse()
        except:
            pass
        return response

    def test(self, urls_file, cookie_jar):
        flagged_urls = []
        urls = self.get_urls(urls_file)
        if cookie_jar:
            cookie_jar = self.get_cookie_jar(cookie_jar)

        for url in urls:
            url = url.strip()
            if "//" in url:
                s = url.split("/")
                server = s[2]
            else:
                s = url.split("/")
                server = s[0]
            path = "/" + "/".join(s[3:])
            if len(path) == 0:
                path = "/"
            if self.verbosity: print "Checking - server: " + server + " path: " + path + " port: " + str(self.port) + " ssl: " + ("True" if self.ssl else "False")
            h = {"Host":server}.copy()
            if cookie_jar:
                h.update(cookie_jar)
            try:
                r = self.request("GET", server, path, headers=h)
                if r:
                    body = r.read()
                    if self.verbosity: print "Status: " + str(r.status) + " - " + r.reason
                    if r.status == httplib.OK:
                        flagged_urls.append(url)
                else:
                    if self.verbosity: print "No response returned"
            except:
                if self.verbosity: print "Request failed"

        return flagged_urls


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="This is a script that checks for access to pages with/out SSL and with/out authorization.")
    parser.add_argument("-p","--port", type=int, help="the webserver port")
    parser.add_argument("-s","--ssl", action="store_true", help="whether or not to use ssl")
    parser.add_argument("-v","--verbose", action="store_true", default=False, help="turn on verbose output")
    parser.add_argument("-c","--cookies", help="the file containing the cookies used for authentication")
    parser.add_argument("urls_file", help="the file containing URLs to scan. Remove http://")
    args = parser.parse_args()

    urls_file = args.urls_file
    cookie_jar = args.cookies
    port = args.port
    ssl = args.ssl
    verbosity = args.verbose
    auth = True if args.cookies else False

    t = access_scanner(urls_file, verbosity, port, ssl)

    print "Checking " + ("with " if ssl else "without ") + "SSL and " + ("with " if auth else "without ") + "authorization..."

    flagged_urls = t.test(urls_file, cookie_jar)

    if len(flagged_urls) > 0:
        print "Was able to access the following:"
        for url in flagged_urls:
            print "\t" + url
    else:
        print "Was not able to access any of the supplied locations..."

