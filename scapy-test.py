import util
from scapy.all import *
import random

# file to test invidividual sites
def main():
    ip = 'google.com'
    sport = random.randint(1024, 10000)
    print('Using sport %d' % sport)
    reps = 1
    mss = 64
    util.repeat_iw_query(ip, sport, reps, mss, None, None)

# def tls(ip):
#     with TLSSocket(client=True) as tls_socket:
#         try:
#             tls_socket.connect(ip)
#             print('Connected to server {}'.format(ip))
#         except tls_socket.timeout:
#             print('Failed to open connection to server {}'.format(ip))
#         else:
#             try:
#                 server_hello, server_kex = tls_socket.do_handshake(tls_version, ciphers, extensions)
#                 server_hello.show()
#             except TLSProtocolError as tpe:
#                 print('Got TLS error {}'.format(tpe))
#                 tpe.response.show()
#             else:
#                 resp = tls_socket.do_round_trip(TLSPlaintext(data='GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n'.format(ip)))
#                 print('Got response from server')
#                 resp.show()
#             finally:
#                 print(tls_socket.tls_ctx)

# syn = IP(dst=dst) / TCP(sport=sport, dport=80, flags='S', options=[('MSS', mss)])
# syn_ack = sr1(syn)
# getStr = 'GET /hello HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % dst
# request = IP(dst=dst) / TCP(dport=80, sport=syn_ack[TCP].dport,
#              seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A', options=[('MSS', mss)]) / getStr
# send(request)
# replies = sniff(filter='tcp port ' + str(sport), timeout=5)
# for reply in replies:
#     print(reply[1])

if __name__ == '__main__':
    main()
    # tls('google.com')
