import modules.robots_txt
import modules.http_headers
import modules.http_methods
import modules.access_scanner
import modules.cookie_settings
import modules.ssl_protos_and_ciphers
import sys


urls = open(sys.argv[1],"r")
for u in urls:
	u = u.strip()
	
	print "\nchecking headers - %s without ssl on 80" % u
	t = http_headers.http_headers(u, port=80, ssl=False, verbosity=True)
	t.test()
	common,possible = t.test()
	t.print_results(common,possible)
	
	print "\nchecking headers - %s with ssl on 443" % u
	t = http_headers.http_headers(u, port=443, ssl=True, verbosity=True)
	t.test()
	common,possible = t.test()
	t.print_results(common,possible)
	
	print "\nchecking methods - %s without ssl on 80" % u
	t = http_methods.http_methods(u, 80, False, True)
	t.test()

	print "\nchecking methods - %s with ssl on 443" % u
	t = http_methods.http_methods(u, 443, True, True)
	t.test()

	print "\nchecking robots - %s without ssl on 80" % u
	t = robots_txt.robots_txt(u,80,False,True)
	r = t.test()
	if r:
		print "\nfound a robots.txt"
		f = open("robots/"+u+".txt","w")
		f.write(r)
		f.close()
	else:
		print "\nno robots.txt"

	print "\nchecking robots - %s with ssl on 443" % u
	t = robots_txt.robots_txt(u,443,True,True)
	r = t.test()
	if r:
		print "\nfound a robots.txt"
		f = open("robots/"+u+".txt","w")
		f.write(r)
		f.close()
	else:
		print "no robots.txt"
	
