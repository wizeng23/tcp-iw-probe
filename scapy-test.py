from scapy.all import *

dst = 'www.stanford.edu'
sport = 1500 

syn = IP(dst=dst) / TCP(sport=sport, dport=80, flags='S')
syn_ack = sr1(syn)
getStr = 'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % dst
request = IP(dst=dst) / TCP(dport=80, sport=syn_ack[TCP].dport,
             seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A') / getStr
reply = sr(request)
# print ans.summary()
