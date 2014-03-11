import robots_txt
import http_headers
import http_methods
import access_scanner
import cookie_settings
import ssl_protos_and_ciphers
import sys


urls = open(sys.argv[1],"r")
for u in urls:
	u = u.strip()
	
	print "\n[+] checking headers - %s without ssl on 80" % u
	t = http_headers.http_headers(u, 80, False, True)
	t.test()
	common,possible = t.test()
	t.print_results(common,possible)

	print "\n[+] checking headers - %s with ssl on 443" % u
	t = http_headers.http_headers(u, 433, True, True)
	t.test()
	common,possible = t.test()
	t.print_results(common,possible)

	print "\n[+] checking methods - %s without ssl on 80" % u
	t = http_methods.http_methods(u, 80, False, True)
	t.test()

	print "\n[+] checking methods - %s with ssl on 443" % u
	t = http_methods.http_methods(u, 443, True, True)
	t.test()

	print "checking: %s without SSL" % u
	t = robots_txt.robots_txt(u,80,False,True)
	r = t.test()
	if r:
		print "-----"
		print r
		print "-----"
	else:
		print "[!] failed"

	print "checking: %s with SSL" % u
	t = robots_txt.robots_txt(u,443,True,True)
	r = t.test()
	if r:
		print "-----"
 		print r
		print "-----"
	else:
		print "[!] failed"

	print "==========\n=========="
	