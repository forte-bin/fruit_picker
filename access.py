#!/usr/bin/env python
# -*- coding: utf-8 -*-
## Tests the given urls for unauthenticated and/or insecure access

import sys, getopt
import httplib, urllib

class Tester(object):
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
        #connection.set_debuglevel(1)
        connection.request(method, path, headers=headers)
        response = None
        try:
            response = connection.getresponse()
        except:
            pass
        return response

    def test(self, urls_file, cookie_jar):
        flagged_urls = list()
        urls = self.get_urls(urls_file)
        if cookie_jar:
            cookie_jar = self.get_cookie_jar(cookie_jar)
        
        for url in urls:
            url = url.strip()
            s = url.split("/")
            server = s[2]
            path = "/" + "/".join(s[3:])
            if len(path) == 0:
                path = "/"
            if self.verbosity: print "[+] Checking: server=" + server + " path=" + path + " port=" + str(self.port) + " ssl=" + ("True" if self.ssl else "False")
            # this line needs to be changed for normal opperation
            h = {"Host":server,"X-AntiForgeryToken":"GyXpZeTcl1bNiwspCQ2mvFLXeJ-JjxQo0MHn4SnklsBru__rJhKGpcZ8_6eV87YPkw0yhol9UUcP1Qnj7r3qZkc6jTVR3cEIsXOfIgl2nrMEQf7Vu8Z8n3nPJEy635-JUZBSpQ2:GqcX5Bhx5rd8KyPLvyaEsmq2euVm92U7uztVbRQE8ymH0QHKL7Dtcw2HfFMS1ynqZSeZU6suhasNGbHNA6u5o5NUd2SwUQSnHh3XdnLPpAYPLeM-EVFUzWl-XmkY0jwc1ACAi19IjI2QFJ-zFbuusYPwzr1Suz8uwWX1y_gqAaHwgk4X0"}.copy()
            if cookie_jar:
                h.update(cookie_jar)

            #for i in h:
            #    print i + " " + h[i]
            
            r = self.request("GET", server, path, headers=h)

            if r:
                body = r.read() 
                if self.verbosity: print "[+] Status: " + str(r.status)
                if r.status == httplib.OK:
                    flagged_urls.append(url)
                if self.verbosity: print "[+] -----"
        return flagged_urls

def usage():
    print "Usage: %s [-p <port>] [-s true|false] [-c <file_containing_cookies>] <file_containing_urls>"

if __name__ == "__main__":
    if len(sys.argv) < 1:
        usage()
    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:svc:", ['port', 'ssl', 'verbose', 'cookies'])
    except getopt.GetoptError, e:
        print str(e)
        usage()
        sys.exit(2)

    urls_file = None
    cookie_jar = None
    port = None
    ssl = False
    verbosity = False
    auth = False

    for o, a in opts:
        if o in ('-p', '--port'):
            port = int(a)
        elif o in ('-s', '--ssl'):
            ssl = True
        elif o in ('-c', '--cookies'):
            auth = True
            cookie_jar = a
        elif o in ('-v', '--verbose'):
            verbosity = True
        else:
            assert False, "unhandled option"

    if len(args) < 1:
        usage()
        sys.exit(2)

    urls_file = args[0]

    t = Tester(urls_file, verbosity, port, ssl)
    
    print "[*] Checking " + ("with " if ssl else "without ") + "SSL and " + ("with " if auth else "without ") + "authorization..."
    
    flagged_urls = t.test(urls_file, cookie_jar)

    if len(flagged_urls) > 0:
        print "[*] Was able to access the following:"
        for url in flagged_urls:
            print "[+]\t" + url
    else:
        print "[*] Was not able to access any..."

