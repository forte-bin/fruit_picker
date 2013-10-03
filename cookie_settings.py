#!/usr/bin/env python
# -*- coding: utf-8 -*-
## Tests the given webserver for some possibly leaky HTTP headers

import sys, getopt
import urllib2, cookielib

class Tester(object):
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
        #print r.info()
        cookies = r.info().getallmatchingheaders("set-cookie")
        if len(cookies) == 0:
            print "No Cookies Set..."
        else:
            #print cookies 
            for cookie in cookies:
                if verbosity:
                    print "-----"
                    print cookie
                http_only = False
                secure = False
                crumbs = cookie.split(";")
                print "[*] Analyzing: "+crumbs[0].replace("Set-Cookie: ","")
                for crumb in crumbs:
                    if "httponly" in crumb.lower():
                        http_only = True
                    if "secure" in crumb.lower():
                        secure = True
                if self.ssl and not secure:
                    print "[-]\tSecure flag is NOT set!"
                else:
                    print "[+]\tSecure flag IS set"
                if not http_only:
                    print "[-]\tHttpOnly flag is NOT set!"
                else:
                    print "[+]\tHttpOnly flag IS set"



def usage():
    print "Usage: %s [-p <port>] [-s|--ssl] <webserver>"

if __name__ == "__main__":
    if len(sys.argv) < 1:
        usage()
    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:s", ['port=', 'ssl'])
    except getopt.GetoptError, e:
        print str(e)
        usage()
        sys.exit(2)

    server = None
    port = None
    ssl = False
    verbosity = True

    for o, a in opts:
        if o in ('-p', '--port'):
            port = int(a)
        elif o in ('-s', '--ssl'):
            ssl = True
    if len(args) < 1:
        usage()
        sys.exit(2)

    server = args[0]

    t = Tester(server, port, ssl, verbosity)
    print "[*] Analyzing Cookie Settings..."
    t.test()