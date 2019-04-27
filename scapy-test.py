from scapy.all import *

dst = 'cs144.keithw.org'
sport = 1112
mss = 64

syn = IP(dst=dst) / TCP(sport=sport, dport=80, flags='S', options=[('MSS', mss)])
syn_ack = sr1(syn)
getStr = 'GET /hello HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % dst
request = IP(dst=dst) / TCP(dport=80, sport=syn_ack[TCP].dport,
             seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A', options=[('MSS', mss)]) / getStr
reply = sr(request, multi=True, timeout=8)
# for i in range(len(reply[0])):
	# print(reply[0][i][1])
# print ans.summary()


# (IP, mss, sport) -> Initial window size

import math
HEADER_SIZE = 40

GLOBAL_REPLIES = None


# returns -1 if initial window not fully exhausted
# returns tuple of window size, error code
# error codes:
# 0: no error
# 1: no connection
# 2: no data
# 3: rst/fin
# 4: large mss
# 5: packet drop
def get_iw(ip, sport, mss=64):
	# syn/syn ack handshake - make sure to set mss here
	syn = IP(dst=ip) / TCP(sport=sport, dport=80, flags='S', options=[('MSS', mss)])
	syn_ack = sr1(syn)

	if len(syn_ack[0]) < 1:
		raise Exception('No SYN ACK received')
		return 0, 1

	# create and send http request
	http_req = 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % ip
	http_error_req = 'GET /' + 'a' * (10 * mss) + ' HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % ip
	request = IP(dst=dst) / TCP(dport=80, sport=syn_ack[TCP].dport,
	             seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A', options=[('MSS', mss)]) / http_req
	replies, requests = sr(request, multi=True, timeout=5)
	# replies, requests = send_http_req(http_req, syn_ack[TCP].dport, syn_ack[TCP].ack, syn_ack[TCP].seq)
	for i in range(len(replies)):
		print(replies[i][1])

	print(syn_ack[TCP].ack, syn_ack[TCP].seq)

	window_size, error = get_window_size(replies, mss, syn_ack[TCP].seq)
	if window_size == -1:
		replies, _ = send_http_req(http_error_req, syn_ack[TCP].seq)
		window_size, error = get_window_size(replies, mss, syn_ack[TCP].seq)
	return window_size, error

def send_http_req(http_req, sport, recv_ackno, recv_seqno):
	req = IP(dst=dst) / TCP(dport=80, sport=sport,
             seq=recv_ackno, ack=recv_seqno + 1, flags='A', options=[('MSS', mss)]) / http_req
	# timeout of 3 seconds based on tcp standards
	return sr(req, multi=True, timeout=3)


# TODO: check for first packet seqno
def get_window_size(replies, mss, recv_ackno):
	largest_mss = mss
	bytes_received = 0.
	error = 0
	seqno_list = []

	print(replies)

	# parse lengths, flags of replies
	# for req, reply in replies:
	for i in range(len(replies)):
		req, reply = replies[i]
		# print(reply)
		# if fin bit set, window has not been saturated, so return -1
		print(reply[TCP].flags)
		if 'F' in reply[TCP].flags:
			error = 3
			raise Exception('Early FIN Received')

		# # assert that the length is at least as long as the header
		assert reply[IP].len >= HEADER_SIZE
		seqno, payload_len = reply[TCP].seq, reply[IP].len - HEADER_SIZE
		seqno_list.append((seqno, payload_len))

		# # if received length is longer than provided mss, update
		# # mss used for counting
		if payload_len > largest_mss:
			largest_mss = payload_len
			error = 4
			print("payload length: " + str(payload_len))
			print("Largest_mss: " + str(largest_mss))
			raise Exception('Received MSS Too large')


	# check for missing packets
	sorted_seqno = sorted(seqno_list, key=lambda tup: tup[0])
	print(sorted_seqno)
	next_expected_seqno = recv_ackno + 1
	for seqno, payload_len in sorted_seqno:
		print(seqno, payload_len)
		if seqno > next_expected_seqno:
			error = 5
			raise Exception('Dropped packet detected')
		if seqno == next_expected_seqno:
			bytes_received += payload_len
			next_expected_seqno += payload_len

	if bytes_received == 0:
		raise Exception('No data received')
		error = 2
	window_size = math.ceil(bytes_received / largest_mss)

	return window_size, error

# window_size, error = get_iw(dst, sport, mss)
# print(window_size, error)
