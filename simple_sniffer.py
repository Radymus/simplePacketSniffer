__author__ = "Radim Spigel"

import socket, binascii, time
from struct import *
import sys



def eth_addr(a):
	b="%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
	return b
try:
	s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
except socket.error, msg:
	print "Nemohl vytvorit socket. Error code: "+str(msg[0])+" msg: "+msg[1]
	sys.exit()

while True:
	packet = s.recvfrom(65565)
	packet = packet[0]
        print
        print "Time: "+str(time.ctime())
 #               print
	eth_length = 14
	eth_header = packet[:eth_length]
	eth = unpack("!6s6sH",eth_header)
	eth_protocol = socket.htons(eth[2])
	print "Cilova Mac: "+eth_addr(packet[0:6])+" Zdrojova Mac: "+eth_addr(packet[6:12])+" Protokol: "+str(eth_protocol)

	if eth_protocol == 8:
		#parsuji ip hlavicku
		ip_header = packet[eth_length:20+eth_length]
		iph = unpack('!BBHHHBBH4x4x',ip_header)
		version_ihl = iph[0]
		version = version_ihl >>4
		ihl = version_ihl & 0xF
		iph_length = ihl*4
		ttl = iph[5]
		protocol = iph[6]
		try:
			s_addr = socket.inet_ntoa(iph[8])
			d_addr = socket.inet_ntoa(iph[9])
		except:
			pass
		print 'Verze: '+str(version)+" delka IP hlavicky "+ str(ihl)+\
		" TTL: "+str(ttl)+" Protokol: "+str(protocol),
		try:
			print " Zdrojova adresa: "+str(s_addr)+\
				" Cilova adresa: "+str(d_addr)
		except:
			pass
		if protocol == 6:
			t = iph_length + eth_length
			tcp_header = packet[t:t+20]
			tcph = unpack("!HHLLBBHHH",tcp_header)
			source_port = tcph[0]
			dest_port = tcph[1]
			sequence = tcph[2]
			acknowledgement = tcph[3]
			doff_reserved = tcph[4]
			tcph_length = doff_reserved >> 4
			print "Protokol TCP"
			print "Zdrojovy port: "+ str(source_port)+ " Cilovy port: "+\
			str(dest_port)+" Sekvence:"+str(sequence)+" Ack:"+\
			str(acknowledgement)+" Delka TCP hlavicky:"+str(tcph_length)

			h_size = eth_length + iph_length + tcph_length *4 
			data_size = len(packet)-h_size
			data = packet[h_size:]	
			print "Data: "+data
		elif protocol == 17:
			u = iph_length+eth_length
			udph_length = 8
			udp_header = packet[u:u+8]
			udph = unpack('!HHHH',udp_header)

			source_port = udph[0]
			dest_port = udph[1]
			length = udph[2]
			checksum = udph[3]
			print "Protokol UDP"
			print "Zdrojovy port: "+str(source_port)+\
			" Cilovy port: "+str(dest_port)+" Delka:"+\
			str(length)+" Checksum: "+str(checksum)

			h_size = eth_length +iph_length+udph_length
			data_size = len(packet) - h_size
			data = packet[h_size:]
			print "Data: "+data

		elif protocol == 1:
			u = iph_length+eth_length
			icmph_length = 4
			icmp_header = packet[u:u+4]
			icmph = unpack('!BBH',icmp_header)
			icmp_type = icmph[0]
			code = icmph[1]
			checksum = icmph[2]
			print "Protokol ICMP"
			print "Typ: "+str(icmp_type)+" Kod: "+str(code)+\
			" Checksum: "+str(checksum)

			h_size = eth_length+iph_length+icmp_length
			data_size = len(packet)-h_size
			
			data = packet[h_size:]
			print "Data: "+data
		else:
			print "Jiny protokol nez TCP/UDP/ICMP"
		print "###################################################"


