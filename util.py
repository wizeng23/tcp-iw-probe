from scapy.all import *
import math
import time
import csv
from multiprocessing import Process, Pipe, Pool

HEADER_SIZE = 40

# (IP, mss, sport) -> Initial window size

def sniff_wrapper(filter, timeout, conn):
	conn.send(sniff(filter=filter, timeout=timeout))
	conn.close()

# returns -1 window size if initial window not fully exhausted
# returns tuple of window size, error code
# error codes:
# 0: no error
# 1: no connection
# 2: no data
# 3: rst/fin
# 4: large mss
# 5: packet drop
def get_iw(ips, sport, app_req, mss=64, dport=80):
    if len(ips) < 1:
        return []
    begin_time = time.time()
    sniff_timeout = 2.5 + len(ips) * 0.01
    # print('Sniff timeout: %f' % sniff_timeout)
    return_values = [None for _ in range(len(ips))]
    syn_acks = [None for _ in range(len(ips))]
    # syn/syn ack handshake - make sure to set mss here
    pool = Pool(processes=len(ips))
    pool_syn = [None for _ in range(len(ips))]
    pool_kwargs = {'verbose':False, 'timeout':sniff_timeout}
    for i, ip in enumerate(ips):
        # print(ip)
        try:
            syn = IP(dst=ip) / TCP(sport=sport + i, dport=dport, flags='S', options=[('MSS', mss)])
            pool_syn[i] = (pool.apply_async(sr1, syn, kwds=pool_kwargs))
        except Exception as e:
            return_values[i] = (-1, 1)
    pool.close()
    pool.join()
    for i in range(len(ips)):
        if return_values[i] != None:
            continue
        syn_acks[i] = pool_syn[i].get()
        if syn_acks[i] == None or len(syn_acks[i][0]) < 1:
            return_values[i] = (-1, 1)
      
    # create and send http request
    parent_conn, child_conn = Pipe()
    sniff_args = {'filter': 'tcp port ' + str(dport), 'timeout': sniff_timeout, 'conn': child_conn}
    p = Process(target=sniff_wrapper, kwargs=sniff_args)
    p.start()
    time.sleep(0.25)
    cur_time = time.time()
    for i, ip in enumerate(ips):
        if return_values[i] != None:
            continue
        send(IP(dst=ip) / TCP(dport=dport, sport=syn_acks[i][TCP].dport, 
            seq=syn_acks[i][TCP].ack, ack=syn_acks[i][TCP].seq + 1, flags='AF', 
            options=[('MSS', mss)]) / app_req[i], verbose=False)
    # print('Took %f seconds to send %d requests' % (time.time() - cur_time, len(ips)))
    replies = parent_conn.recv()
    parent_conn.close()
    p.join()
    for i, ip in enumerate(ips):
        if return_values[i] == None:
            rst = IP(dst=ip) / TCP(dport=dport, sport=syn_acks[i][TCP].dport, 
                seq=syn_acks[i][TCP].ack, ack=syn_acks[i][TCP].seq + 1, flags='AR')
            send(rst, verbose=False)
            return_values[i] = get_window_size(ip, sport + i, replies, mss, syn_acks[i][TCP].seq)
    # print('Overall, took %f seconds for one round of %d IP addresses' % (time.time() - begin_time, len(ips)))
    return return_values

def get_window_size(ip, sport, replies, mss, recv_ackno):
    largest_mss = mss
    bytes_received = 0
    error = 0
    seqno_list = []

    # parse lengths, flags of replies
    # for req, reply in replies:
    # print("Replies length: %d" % len(replies))
    # print('IP: %s' % ip)
    for reply in replies:
        # print(reply.show())
        # if fin bit set, window has not been saturated, so return -1
        if reply[TCP].dport != sport:
        	continue
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

def try_dns(ip):
    if ip[0].isalpha():
        dns_req = IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=ip))
        answer = sr1(dns_req, verbose=False, timeout=1)
        if answer and answer[DNS] and answer[DNS].an:
            return answer[DNS].an.rdata
    return ip

def repeat_iw_query(ips, sport, reps, mss):
    # if human-readable address, perform DNS query
    start_time = time.time()
    urls = ips
    ips = [try_dns(ip) for ip in ips]
    # print('Took {:.2f}s for DNS'.format(time.time() - start_time))

    begin_time = time.time()
    ips = list(ips)
    http_reqs = ['GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % ip for ip in ips]
    http_error_reqs = ['GET /' + 'a' * (10 * mss) + ' HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % ip for ip in ips]
    results = [[] for _ in range(len(ips))]
    errors = [[] for _ in range(len(ips))]
    use_error_req = [False for _ in range(len(ips))]
    error_ips = []
    error_idxs = []
    error_reqs = []
    for _ in range(reps):
        windows_results = get_iw(ips, sport, http_reqs)
        # print(windows_results)
        for i, (iw, error) in enumerate(windows_results):
            if error != 0:
                iw = -1
            results[i].append(iw)
            errors[i].append(error)
            if not use_error_req[i] and error == 3:
                use_error_req[i] = True
                error_ips.append(ips[i])
                error_idxs.append(i)
                error_reqs.append(http_error_reqs[i])
        sport += len(ips)
    for i in error_idxs:
        results[i] = []
        errors[i] = []
    for _ in range(reps):
        windows_results = get_iw(error_ips, sport, error_reqs)
        for i, (iw, error) in enumerate(windows_results):
            if error != 0:
                iw = -1
            results[error_idxs[i]].append(iw)
            errors[error_idxs[i]].append(error) 
        sport += len(error_ips)

    # print('{:25s} {}' .format('IP: ', ips))
    # print('{:25s} {}' .format('Initial Window Results:', str(results)))
    # print('{:25s} {}' .format('Returned Code:', str(errors)))
    # print('Total Time: %f' % (time.time() - begin_time))
    # for i in range(len(ips)):
    #     print(urls[i], ips[i], use_error_req[i], results[i], errors[i])
    return results, errors, use_error_req

# retrieves the first `amount` entries from the ip list
def get_ip_list(amount=100, offset=0, filename='data/ip_list.csv'):
    ip_list = []
    with open(filename) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        for row in csv_reader:
            if line_count >= offset + 1:
                ip_list.append(row[1])
            line_count += 1
            if len(ip_list) >= amount:
                break
    return ip_list
