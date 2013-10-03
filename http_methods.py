#!/usr/bin/env python
# -*- coding: utf-8 -*-
## Tests the given webserver for some possibly dangerous HTTP methods

import sys, getopt
import httplib, urllib

class Tester(object):
    def __init__(self, url, port=None, ssl=None, verbosity=15):
        self.url = url
        self.server = url.split('/')[0]
        self.path = '/'+'/'.join(url.split('/')[1:])
        self.port = port or (443 if ssl else 80)
        self.ssl = ssl
        self.verbosity = verbosity

    def print_vars(self):
        print "-----"
        print "url",self.url
        print "server",self.server
        print "path",self.path
        print "port",self.port
        print "ssl",self.ssl
        print "-----"

    def getconn(self):
        if self.ssl:
            c = httplib.HTTPSConnection(self.server, self.port, timeout=10)
        else:
            c = httplib.HTTPConnection(self.server, self.port, timeout=10)
        return c

    def request(self, method, path, body=None, headers=None):
        c = self.getconn()
        headers = headers or {}
        c.request(method, path, body, headers=headers)
        return c.getresponse()

    def test(self):
        self.get()
        self.post()
        self.head()
        self.options()
        self.trace()
        self.track()
        self.put()
        #self.delete()
        self.connect()

    def get(self):
        r = self.request("GET", self.path, headers={"Host":self.server})
        body = r.read()

        if self.path in body or r.status == httplib.OK:
            print "GET:\t "+str(r.status)+" ("+r.reason+")"
        else:
            print "GET:\t "+str(r.status)+" ("+r.reason+")"

    def post(self):
        params = urllib.urlencode({'testPOST': 'POSTtest'})
        r = self.request("POST", self.path, params, headers={"Host":self.server})
        body = r.read()

        if self.path in body or r.status == httplib.OK:
            print "POST:\t "+str(r.status)+" ("+r.reason+")"
        else:
            print "POST:\t "+str(r.status)+" ("+r.reason+")"

    def head(self):
        r = self.request("HEAD", self.path, headers={"Host":self.server})
        body = r.read()

        if r.status == httplib.OK and len(body) == 0:
            print "HEAD:\t "+str(r.status)+" ("+r.reason+")"
        else:
            print "HEAD:\t "+str(r.status)+" ("+r.reason+")"

    def options(self):
        r = self.request("OPTIONS", self.path, headers={"Host":self.server})
        body = r.read()

        if r.getheader('allow') and r.status == httplib.OK:
            print "Reported Allowed Methods: " + r.getheader('allow')
            print "OPTIONS: "+str(r.status)+" ("+r.reason+")"
        else:
            print "OPTIONS: "+str(r.status)+" ("+r.reason+")"

    def trace(self):
        # This needs some work, some apps will allow TRACE on certain paths but not the root.
        r = self.request("TRACE", self.path, headers={"Host":self.server})
        body = r.read()

        if self.path in body and r.status == httplib.OK:
            print "TRACE:\t "+str(r.status)+" ("+r.reason+")"
        else:
            print "TRACE:\t "+str(r.status)+" ("+r.reason+")"

    def track(self):
        r = self.request("TRACK", self.path, headers={"Host":self.server})
        body = r.read()

        if self.path in body and r.status == httplib.OK:
            print "TRACK:\t "+str(r.status)+" ("+r.reason+")"
        else:
            print "TRACK:\t "+str(r.status)+" ("+r.reason+")"

    def put(self):
        r = self.request("PUT", self.path, "KEHKEHEKEHKEH")

        if r.status in (httplib.OK, httplib.CREATED, httplib.NO_CONTENT):
            print "PUT:\t "+str(r.status)+" ("+r.reason+")"
        else:
            print "PUT:\t "+str(r.status)+" ("+r.reason+")"

    def delete(self):
        r = self.request("DELETE", self.path)

        if r.status in (httplib.OK, httplib.ACCEPTED, httplib.NO_CONTENT):
            print "DELETE:\t "+str(r.status)+" ("+r.reason+")"
        else:
            print "DELETE:\t "+str(r.status)+" ("+r.reason+")"

    def connect(self):
        r = self.request("CONNECT", "localhost:80")

        if r.status in (httplib.OK, httplib.ACCEPTED, httplib.NO_CONTENT):
            print "CONNECT: "+str(r.status)+" ("+r.reason+")"
        else:
            print "CONNECT: "+str(r.status)+" ("+r.reason+")"

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

    url = None
    port = None
    ssl = False
    for o, a in opts:
        if o in ('-p', '--port'):
            port = int(a)
        elif o in ('-s', '--ssl'):
            ssl = True
    if len(args) < 1:
        usage()
        sys.exit(2)

    url = args[0]

    t = Tester(url, port, ssl,15)
    t.print_vars()
    t.test()
