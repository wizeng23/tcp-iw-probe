from scapy.all import *
import math
import time
import csv
HEADER_SIZE = 40

# (IP, mss, sport) -> Initial window size

# returns -1 window size if initial window not fully exhausted
# returns tuple of window size, error code
# error codes:
# 0: no error
# 1: no connection
# 2: no data
# 3: rst/fin
# 4: large mss
# 5: packet drop
def get_iw(ip, sport, app_req, mss=64, dport=80):
    # print('Getting {}'.format(ip))
    # syn/syn ack handshake - make sure to set mss here
    syn = IP(dst=ip) / TCP(sport=sport, dport=dport, flags='S', options=[('MSS', mss)])
    syn_ack = sr1(syn, verbose=False, timeout=3.5)
    # print('Got {} synack'.format(ip))

    if syn_ack == None or len(syn_ack[0]) < 1:
        # print('Synack empty')
        return -1, 1

    # create and send http request
    send(IP(dst=ip) / TCP(dport=dport, sport=syn_ack[TCP].dport, 
        seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A', 
        options=[('MSS', mss)]) / app_req, verbose=False)
    # print('Sending for {}'.format(ip))
    replies = sniff(filter='tcp port ' + str(sport), timeout=3.5)
    # print('Finished sniffing for {}, {} replies'.format(ip, len(replies)))
    rst = IP(dst=ip) / TCP(dport=dport, sport=syn_ack[TCP].dport, 
        seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='AR')
    send(rst, verbose=False)
    return get_window_size(ip, replies, mss, syn_ack[TCP].seq)

# TODO: check for first packet seqno
def get_window_size(ip, replies, mss, recv_ackno):
    largest_mss = mss
    bytes_received = 0
    error = 0
    seqno_list = []

    # parse lengths, flags of replies
    # for req, reply in replies:
    for reply in replies:
        # if fin bit set, window has not been saturated, so return -1
        if 'F' in reply[TCP].flags:
            return -1, 3

        # assert that the length is at least as long as the header
        assert reply[IP].len >= HEADER_SIZE
        seqno, payload_len = reply[TCP].seq, reply[IP].len - HEADER_SIZE
        seqno_list.append((seqno, payload_len))

        # if received length is longer than provided mss, update
        # mss used for counting
        if payload_len > largest_mss:
            largest_mss = payload_len
            return -1, 4

    # check for missing packets
    sorted_seqno = sorted(seqno_list, key=lambda tup: tup[0])
    # seqno_string = ','.join(['({},{})'.format(elem[0], elem[1]) for elem in sorted_seqno])
    # print('{}: {}'.format(ip, seqno_string))
    next_expected_seqno = recv_ackno + 1
    for seqno, payload_len in sorted_seqno:
        if seqno > next_expected_seqno:
            return -1, 5
        if seqno == next_expected_seqno:
            bytes_received += payload_len
            next_expected_seqno += payload_len

    # print('{}: {}, {}'.format(ip, bytes_received, largest_mss))
    if bytes_received == 0:
        return -1, 2
    window_size = math.ceil(bytes_received / largest_mss)

    # print(window_size, error)
    return window_size, error

# returns category and the result number
def get_category(results):
    num_results = 0
    first_result = None
    same_result = True
    for result in results:
        if result > 0:
            num_results += 1
            if first_result is None:
                first_result = result
            elif result != first_result:
                same_result = False
    if num_results >= 3:
        if same_result:
            return 1, first_result
        return 2, first_result
    elif num_results >= 1:
        if same_result:
            return 3, first_result
        return 4, first_result
    else:
        return 5, 0

def repeat_iw_query(ip, sport, reps, mss, visited_ip, visited_lock):
    # if human-readable address, perform DNS query
    # if ip[0].isalpha():
    #     dns_req = IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=ip))
    #     answer = sr1(dns_req, verbose=False)
    #     if answer and answer[DNS] and answer[DNS].an:
    #         ip = answer[DNS].an.rdata

    # lot of human-readable addresses in database resolve to same ip address
    # should only query each ip address once
    if visited_lock:
        visited_lock.acquire()
        if ip in visited_ip:
            visited_lock.release()
            return None
        else:
            visited_ip.add(ip)
            visited_lock.release()
    # print('IP: {}'.format(ip))
    http_req = 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % ip
    http_error_req = 'GET /' + 'a' * (10 * mss) + ' HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % ip
    results = []
    errors = []
    use_error_req = False
    i = 0
    while i < reps:
        if use_error_req:
            iw, error = get_iw(ip, sport, http_error_req)
        else:
            iw, error = get_iw(ip, sport, http_req)
        if error != 0:
            iw = -1
        sport += 1
        if not use_error_req and error == 3:
            # print('Switching to http error string')
            i = 0
            use_error_req = True
            results = []
            errors = []
            continue
        i += 1
        results.append(iw)
        errors.append(error)
    # print('{:25s} {}' .format('Initial Window Results:', str(results)))
    # print('{:25s} {}' .format('Returned Code:', str(errors)))
    return results, errors

# retrieves the first `amount` entries from the ip list
# TODO: offset parameter to get ip's 1001-2000 for example
def get_ip_list(amount=100, filename='data/ip_list.csv'):
    ip_list = []
    with open(filename) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        for row in csv_reader:
            if line_count != 0:
                ip_list.append(row[1])
            line_count += 1
            if len(ip_list) >= amount:
                break
    return ip_list



# # returns category and the result number
# def get_category(results):
#     num_results = 0
#     first_result = None
#     same_result = True
#     results_dict = {}
#     for result in results:
#         if result not in results_dict:
#             results_dict[result] = 1
#         else:
#             results_dict[result] += 1
#     max_value = -1
#     result_value = None
#     num_results = 0
#     for k, v in results_dict.items():
#         if v > max_value:
#             max_value = v
#             result_value = k
#         num_results += v
#     if max_value >= 3:
#         return 1, result_value
#     if num_results >= 3:
#         return 2, result_value
#     if max_value >= 1:
#         return 3, result_value
#     return 5, 0
