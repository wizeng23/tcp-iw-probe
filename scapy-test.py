from scapy.all import *

dst = 'cs144.keithw.org'
sport = 1004

syn = IP(dst=dst) / TCP(sport=sport, dport=80, flags='S')
syn_ack = sr1(syn)
getStr = 'GET /hello HTTP/1.1\r\nHost: %s\r\n\r\n' % dst
request = IP(dst=dst) / TCP(dport=80, sport=syn_ack[TCP].dport,
             seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A') / getStr
ans = sr(request, timeout=1, multi=True)
# reply = ans[0][0][1]
# print ans.summary()
