import socket,binascii,string,sys,csv,pickle
from optparse import OptionParser

def check_cipher(cipher_id, host, port, handshake="TLS"):
	handshake_pkts = {
		"TLS v1.2": '\x80\x2c\x01\x03\x03\x00\x03\x00\x00\x00\x20',
		"TLS v1.1": '\x80\x2c\x01\x03\x02\x00\x03\x00\x00\x00\x20',
		"TLS v1.0": '\x80\x2c\x01\x03\x01\x00\x03\x00\x00\x00\x20',
		"SSL v3.0": '\x80\x2c\x01\x03\x00\x00\x03\x00\x00\x00\x20'
	}

	# NULL handshake challenge string
	challenge = '\x00' * 32

	handshake_pkt = handshake_pkts[handshake]

	cipher = binascii.unhexlify(cipher_id)
	
	s = create_connection(host,port)
	
	s.send(handshake_pkt+cipher+challenge)
	
	try:	
		data = s.recv(1)
	except socket.error, msg:
		s.close()
		return False
		
	state = False

	if data == '\x16':   
		state = True   # Server Hello Code
	elif data == '\x15': 
		state =  False # Server Alert Code
	else:
		print "[!] Something is wrong with the server response"
				
	s.close()
	return state

def check_protocol(host, port, handshake="TLS"):
	#print "checking protocol",handshake

	handshake_pkts = {
		"TLS v1.2": '\x80\x2c\x01\x03\x03\x00\x03\x00\x00\x00\x20',
		"TLS v1.1": '\x80\x2c\x01\x03\x02\x00\x03\x00\x00\x00\x20',
		"TLS v1.0": '\x80\x2c\x01\x03\x01\x00\x03\x00\x00\x00\x20',
		"SSL v3.0": '\x80\x2c\x01\x03\x00\x00\x03\x00\x00\x00\x20',
		"SSL v2.0": '\x80\x2c\x01\x00\x02\x00\x03\x00\x00\x00\x20'
	}

	# NULL handshake challenge string
	challenge = '\x00' * 32

	handshake_pkt = handshake_pkts[handshake]

	cipher = binascii.unhexlify('00002F')
	
	s = create_connection(host,port)
	s.send(handshake_pkt+cipher+challenge)
	
	try:
		data = s.recv(8)
	except socket.error, msg:
		print msg
		s.close()
		return False
		
	state = False

	if len(data) > 0:
		if data[0] == '\x15' or data[0] == '\x16':
			if data[1:3] == handshake_pkt[3:5]:
				state = True
			else: 
				state =  False
		else:
			state = True
	s.close()
	return state

def load_ciphers(file_name):
	cipher_list = open("cipher_suites.pkl","r")
	cipher_suites = pickle.load(cipher_list)
	return cipher_suites

def create_connection(host,port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:   s.connect((host, port))		
	except socket.error, msg:
		print "[!] Could not connect to target host: %s" % msg
		s.close()
		sys.exit()
	return s

def print_cipher(cipher_id,cipher_suites,results):
	if cipher_suites.has_key(cipher_id):
		# Display output
		print "[+]\t%s (0x%s)" % ( cipher_suites[cipher_id]['name'], cipher_id )
		if verbose: 
			print "    Specs: Kx=%s, Au=%s, Enc=%s, Bits=%s, Mac=%s" % ( cipher_suites[cipher_id]['kx'], cipher_suites[cipher_id]['au'], cipher_suites[cipher_id]['enc'], cipher_suites[cipher_id]['bits'], cipher_suites[cipher_id]['mac'] )
			print "    Score: Kx/Au=%s, Enc/MAC=%s, Overall=%s" %  ( cipher_suites[cipher_id]['kxau_strength'], cipher_suites[cipher_id]['enc_strength'], cipher_suites[cipher_id]['overall_strength'])
		
		if not results.has_key(cipher_suites[cipher_id]['overall_strength']):
			results[cipher_suites[cipher_id]['overall_strength']] = list()
		results[cipher_suites[cipher_id]['overall_strength']].append(cipher_id)
	else: 
		print "[+] Undocumented cipher (0x%)" % cipher_id
		if not results.has_key("UNKNOWN"):
			results["UNKNOWN"] = list()
		results["UNKNOWN"].append(cipher_id)

def output_report(results):
	print "\n%s Scan Results %s" % ("="*20, "="*20)
	for classification in results:
		print "The following cipher suites were rated as %s:" % classification
		for cipher_id in results[classification]:
			print "%s" % (cipher_suites[cipher_id]['name'])
		print ""
	
def scan_fuzz_ciphers(host,port,protocols,cipher_suites,results):
	print "[*] Fuzzing %s:%d for all possible cipher suite identifiers." % (host, port)
	for protocol in protocols:
		if verbose: print "[*] Using %s protocol..." % protocol
		for i in range(0,16777215):
			cipher_id = '%06x' % i
			if check_cipher(cipher_id,host,port): print_cipher(cipher_id,cipher_suites,results)

def scan_known_ciphers(host,port,protocols,cipher_suites,results):
	print "[*] Scanning %s:%d for %d known cipher suites for %d supported protocol(s)." % (host,port,len(cipher_suites),len(protocols))
	for protocol in protocols:
		print "[*] Using %s protocol." % protocol
		for cipher_id in cipher_suites.keys():
			if check_cipher(cipher_id,host,port,protocol): print_cipher(cipher_id,cipher_suites,results)

def scan_known_protocols(host,port,handshakes):
	print "[*] Scanning %s:%d for %d support of known protocols." % (host,port,len(handshakes))
	supports = list()
	for handshake in handshakes:
		supported = check_protocol(host,port,handshake)
		if supported:
			print "[+] %s supported." % handshake
			if handshake != "SSL v2.0":
				supports.append(handshake)
	return supports

if __name__ == '__main__':
	parser = OptionParser()
	parser.add_option("--host", dest="host", help="host",  metavar="gmail.com")
	parser.add_option("--port", dest="port", help="port", default=443, type="int", metavar="443")
	parser.add_option("--fuzz", action="store_true", dest="fuzz",  default=False, help="fuzz all possible cipher values (takes time)")
	parser.add_option("--v", action="store_true", dest="verbose",  default=False, help="enable verbose output")
	(options, args) = parser.parse_args()
	
	if not options.host: parser.error(parser.print_help())
	else: HOST = options.host

	if options.verbose: 
		verbose = True
	else:
		verbose = False	

	handshakes = ("SSL v2.0","SSL v3.0","TLS v1.0","TLS v1.1","TLS v1.2")
			
	cipher_suites = load_ciphers("cipher_suites.pkl")
	results = dict()
	protocols = scan_known_protocols(options.host, options.port, handshakes)

	if options.fuzz: 
		scan_fuzz_ciphers(options.host, options.port, protocols, cipher_suites, results)
	else:
		scan_known_ciphers(options.host, options.port, protocols, cipher_suites, results)

	#if results: output_report(results)