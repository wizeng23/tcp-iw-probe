from scapy.all import *
import math
HEADER_SIZE = 40

# dst = 'cs144.keithw.org'
# sport = 1113
# mss = 64

# syn = IP(dst=dst) / TCP(sport=sport, dport=80, flags='S', options=[('MSS', mss)])
# syn_ack = sr1(syn)
# getStr = 'GET /hello HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % dst
# request = IP(dst=dst) / TCP(dport=80, sport=syn_ack[TCP].dport,
#              seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A', options=[('MSS', mss)]) / getStr
# send(request)
# replies = sniff(filter='tcp port ' + str(sport), timeout=5)
# for i in range(len(reply[0])):
	# print(reply[0][i][1])
# print ans.summary()


# (IP, mss, sport) -> Initial window size

# returns -1 if initial window not fully exhausted
# returns tuple of window size, error code
# error codes:
# 0: no error
# 1: no connection
# 2: no data
# 3: rst/fin
# 4: large mss
# 5: packet drop
def get_iw(ip, sport, mss=64, dport=80, app_req=None, app_error_req=None):
	# syn/syn ack handshake - make sure to set mss here
	syn = IP(dst=ip) / TCP(sport=sport, dport=dport, flags='S', options=[('MSS', mss)])
	syn_ack = sr1(syn)

	if len(syn_ack[0]) < 1:
		return 0, 1

	# create and send http request
	if app_req == None:
		app_req = 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % ip
		app_error_req = 'GET /' + 'a' * (10 * mss) + ' HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % ip
	send(IP(dst=ip) / TCP(dport=dport, sport=syn_ack[TCP].dport, 
		seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A', 
		options=[('MSS', mss)]) / app_req)
	replies = sniff(filter='tcp port ' + str(sport), timeout=6)	
	# request = IP(dst=dst) / TCP(dport=80, sport=syn_ack[TCP].dport,
	#              seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A', options=[('MSS', mss)]) / http_req
	# send(request)
	# replies = sniff(filter='tcp port ' + str(sport), timeout=6)

	window_size, error = get_window_size(replies, mss, syn_ack[TCP].seq)
	if error != 0:
		send(IP(dst=ip) / TCP(dport=dport, sport=syn_ack[TCP].dport, 
			seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A', 
			options=[('MSS', mss)]) / app_error_req)
		replies = sniff(filter='tcp port ' + str(sport), timeout=6)	
		window_size, error = get_window_size(replies, mss, syn_ack[TCP].seq)
	return window_size, error


# TODO: check for first packet seqno
def get_window_size(replies, mss, recv_ackno):
	largest_mss = mss
	bytes_received = 0.
	error = 0
	seqno_list = []

	# parse lengths, flags of replies
	# for req, reply in replies:
	for reply in replies:
		# if fin bit set, window has not been saturated, so return -1
		if 'F' in reply[TCP].flags:
			error = 3

		# # assert that the length is at least as long as the header
		assert reply[IP].len >= HEADER_SIZE
		seqno, payload_len = reply[TCP].seq, reply[IP].len - HEADER_SIZE
		seqno_list.append((seqno, payload_len))

		# # if received length is longer than provided mss, update
		# # mss used for counting
		if payload_len > largest_mss:
			largest_mss = payload_len
			error = 4


	# check for missing packets
	sorted_seqno = sorted(seqno_list, key=lambda tup: tup[0])
	next_expected_seqno = recv_ackno + 1
	for seqno, payload_len in sorted_seqno:
		if seqno > next_expected_seqno:
			error = 5
		if seqno == next_expected_seqno:
			bytes_received += payload_len
			next_expected_seqno += payload_len

	if bytes_received == 0:
		error = 2
	window_size = math.ceil(bytes_received / largest_mss)

	return window_size, error
