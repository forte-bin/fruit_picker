#!/usr/bin/env python
# -*- coding: utf-8 -*-
## Tests the given webserver for some possibly leaky HTTP headers

#
# TODO: Add support for checking clickjacking headers
# TODO: Add support for checking Access-Control-Allow-Origin, Access-Control-Allow-Methods, Access-Control-Allow-Headers headers
#

import sys, getopt
import httplib, urllib

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

    def request(self, method, path, body=None, headers=None):
        c = self.getconn()
        headers = headers or {}
        c.request(method, path, body, headers=headers)
        return c.getresponse()

    def test(self):
        r = self.request("GET", self.path, headers={"Host":self.server})
        common = list()
        possible = list()
        for l in r.getheaders():
            if "server" in l[0]:
                common.append("[-]\t"+l[0]+": "+l[1])
            elif "x-powered-by" in l[0]:
                common.append("[-]\t"+l[0]+": "+l[1])
            elif "x-aspnet-version" in l[0]:
                common.append("[-]\t"+l[0]+": "+l[1])
            elif "x-aspnetmvc-version" in l[0]:
                common.append("[-]\t"+l[0]+": "+l[1])
            elif "x-" in l[0]:
                possible.append("[-]\t"+l[0]+": "+l[1])
        return common,possible

    def list_possible(self):
        r = self.request("GET", "/", headers={"Abcd":"efghij"})
        for l in r.getheaders():
            if "x-" in l[0]:
                print l[0]+":",l[1]
                # l[0] not in dict

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
    verbosity = True

    for o, a in opts:
        if o in ('-p', '--port'):
            port = int(a)
        elif o in ('-s', '--ssl'):
            ssl = True
    if len(args) < 1:
        usage()
        sys.exit(2)

    url = args[0]

    t = Tester(url, port, ssl, verbosity)
    print "[*] Testing for leaky headers..."
    common,possible = t.test()

    if len(common) > 0:
        print "[*] Found the following common leaky headers:"
        for e in common:
            print e
    else:
        print "[+] Found no common leaky headers"

    if len(possible) > 0:
        print "[*] Found the following possibly leaky headers:"
        for e in possible:
            print e
    else:
        print "[+] Found no other possibly leaky headers"

