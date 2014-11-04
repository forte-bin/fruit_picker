# This tests for the protocols and ciphers used by a webserver 

import socket, binascii, string, sys, csv, pickle, argparse

class ssl_and_protocol_analyzer(object):
	def __init__(self, host, port, verbose):
		self.host = host
		self.port = port
		self.verbose = verbose
		self.handshakes = ("SSL v2.0","SSL v3.0","TLS v1.0","TLS v1.1","TLS v1.2")

	def check_cipher(self, cipher_id, host, port, handshake="TLS"):
		handshake_pkts = {
			"TLS v1.2": '\x80\x2c\x01\x03\x03\x00\x03\x00\x00\x00\x20',
			"TLS v1.1": '\x80\x2c\x01\x03\x02\x00\x03\x00\x00\x00\x20',
			"TLS v1.0": '\x80\x2c\x01\x03\x01\x00\x03\x00\x00\x00\x20',
			"SSL v3.0": '\x80\x2c\x01\x03\x00\x00\x03\x00\x00\x00\x20'
		}

		# NULL handshake challenge string
		challenge 		= '\x00' * 32
		handshake_pkt 	= handshake_pkts[handshake]
		cipher 			= binascii.unhexlify(cipher_id)
		s 				= self.create_connection(host,port)
	
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
			print "Something is wrong with the server response"
					
		s.close()
		return state

	def check_protocol(self, host, port, handshake="TLS"):
		#print "checking protocol",handshake

		handshake_pkts = {
			"TLS v1.2": '\x80\x2c\x01\x03\x03\x00\x03\x00\x00\x00\x20',
			"TLS v1.1": '\x80\x2c\x01\x03\x02\x00\x03\x00\x00\x00\x20',
			"TLS v1.0": '\x80\x2c\x01\x03\x01\x00\x03\x00\x00\x00\x20',
			"SSL v3.0": '\x80\x2c\x01\x03\x00\x00\x03\x00\x00\x00\x20',
			"SSL v2.0": '\x80\x2c\x01\x00\x02\x00\x03\x00\x00\x00\x20'
		}

		# NULL handshake challenge string
		challenge 		= '\x00' * 32
		handshake_pkt 	= handshake_pkts[handshake]
		cipher 			= binascii.unhexlify('00002F')
		s 				= self.create_connection(self.host, self.port)

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

	def load_ciphers(self, file_name):
		cipher_list = open("cipher_suites.pkl","r")
		cipher_suites = pickle.load(cipher_list)
		return cipher_suites

	def create_connection(self, host, port):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:   s.connect((host, port))		
		except socket.error, msg:
			print "Could not connect to target host: %s" % msg
			s.close()
			sys.exit()
		return s

	def print_cipher(self, cipher_id, cipher_suites, results):
		if cipher_suites.has_key(cipher_id):
			space = ""
			if len(cipher_suites[cipher_id]['name']) > 36:
				space = "\t"
			elif len(cipher_suites[cipher_id]['name']) > 28:
				space = "\t\t"
			else:
				space = "\t\t\t"
			print "\t%s (0x%s)%s[%s]" % ( cipher_suites[cipher_id]['name'], cipher_id , space, cipher_suites[cipher_id]['overall_strength'])
			if self.verbose: 
				print "\t\tSpecs: Kx=%s, Au=%s, Enc=%s, Bits=%s, Mac=%s" % ( cipher_suites[cipher_id]['kx'], cipher_suites[cipher_id]['au'], cipher_suites[cipher_id]['enc'], cipher_suites[cipher_id]['bits'], cipher_suites[cipher_id]['mac'] )
				print "\t\tScore: Kx/Au=%s, Enc/MAC=%s, Overall=%s" %  ( cipher_suites[cipher_id]['kxau_strength'], cipher_suites[cipher_id]['enc_strength'], cipher_suites[cipher_id]['overall_strength'])
			if not results.has_key(cipher_suites[cipher_id]['overall_strength']):
				results[cipher_suites[cipher_id]['overall_strength']] = list()
			results[cipher_suites[cipher_id]['overall_strength']].append(cipher_id)
		else: 
			print "Undocumented cipher (0x%)" % cipher_id
			if not results.has_key("UNKNOWN"):
				results["UNKNOWN"] = list()
			results["UNKNOWN"].append(cipher_id)

	def output_report(self, results):
		print "\n%s Scan Results %s" % ("="*20, "="*20)
		for classification in results:
			print "The following cipher suites were rated as %s:" % classification
			for cipher_id in results[classification]:
				print "%s" % (cipher_suites[cipher_id]['name'])
			print ""
		
	def scan_fuzz_ciphers(self, protocols, cipher_suites, results):
		print "Fuzzing %s:%d for all possible cipher suite identifiers." % (self.host,self.port)
		for protocol in protocols:
			if self.verbose: print "Using %s protocol..." % protocol
			for i in range(0,16777215):
				cipher_id = '%06x' % i
				if self.check_cipher(cipher_id,self.host,self.port): 
					self.print_cipher(cipher_id,cipher_suites,results)

	def scan_known_ciphers(self, protocols, cipher_suites, results):
		print "Scanning %s:%d for %d known cipher suites for %d supported protocol(s)." % (self.host,self.port,len(cipher_suites),len(protocols))
		for protocol in protocols:
			print "Using %s protocol." % protocol
			for cipher_id in cipher_suites.keys():
				if self.check_cipher(cipher_id, self.host, self.port, protocol): 
 					self.print_cipher(cipher_id, cipher_suites, results)

	def scan_known_protocols(self):
		print "Scanning %s:%d for support of %d known protocols." % (self.host,self.port,len(self.handshakes))
		supports = list()
		for handshake in self.handshakes:
			supported = self.check_protocol(self.host,self.port,handshake)
			if supported:
				print "%s supported." % handshake
				if handshake != "SSL v2.0":
					supports.append(handshake)
		return supports


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="This is a script that analyzes supported SSL/TLS cipher suites and protocols.")
	parser.add_argument("host", help="the host to analyze")
	parser.add_argument("port", type=int, help="the port to analyze")
	parser.add_argument("-f", "--fuzz", action="store_true", default=False, help="fuzz all possible cipher values")
	parser.add_argument("-v", "--verbose", action="store_true", default=False, help="enable verbose output")
	args = parser.parse_args()
	
	t = ssl_and_protocol_analyzer(host=args.host, port=args.port, verbose=args.verbose)
	protocols       = t.scan_known_protocols()
	cipher_suites 	= t.load_ciphers("cipher_suites.pkl")
	results         = {}

	if args.fuzz: 
		t.scan_fuzz_ciphers(protocols, cipher_suites, results)
	else:
		t.scan_known_ciphers(protocols, cipher_suites, results)

