# tcp-iw-probe
Recreating the initial TCP congestion window results of Padhye et. al.'s 2001 paper.

TODOs
Decrease or remove timeout in sr1 call for synack
Check how many ip's fail due to dns errors, do a separate dns run?
TLS? Many fail due to http 302, error 3 or 4
design doc
switch to python2

Some resources because the Scapy Docs aren't too helpful

http://thepacketgeek.com/scapy-p-06-sending-and-receiving-with-scapy/
https://stackoverflow.com/questions/4750793/python-scapy-or-the-like-how-can-i-create-an-http-get-request-at-the-packet-leve
http://www.thice.nl/creating-ack-get-packets-with-scapy/
https://blogs.sans.org/pen-testing/files/2016/04/ScapyCheatSheet_v0.2.pdf