from scapy.all import *
import math
import time
import csv
from multiprocessing import Process, Pipe, Pool

HEADER_SIZE = 40

# wrapper for scapy sniff used in multiprocessing
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
    sniff_timeout = 5.0 + len(ips) * 0.01
    return_values = [None for _ in range(len(ips))]
    syn_acks = [None for _ in range(len(ips))]
    # syn/syn ack handshake - make sure to set mss here
    pool = Pool(processes=len(ips))
    pool_syn = [None for _ in range(len(ips))]
    pool_kwargs = {'verbose':False, 'timeout':sniff_timeout}
    # send syn asynchronously
    for i, ip in enumerate(ips):
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
      
    # create separate process to sniff packets for all ips at the same time
    parent_conn, child_conn = Pipe()
    sniff_args = {'filter': 'tcp port ' + str(dport), 'timeout': sniff_timeout, 'conn': child_conn}
    p = Process(target=sniff_wrapper, kwargs=sniff_args)
    p.start()
    time.sleep(0.25)
    cur_time = time.time()
    for i, ip in enumerate(ips):
        if return_values[i] != None:
            continue
        try:
            send(IP(dst=ip) / TCP(dport=dport, sport=syn_acks[i][TCP].dport, 
                seq=syn_acks[i][TCP].ack, ack=syn_acks[i][TCP].seq + 1, flags='AF', 
                options=[('MSS', mss)]) / app_req[i], verbose=False)
        except Exception as e:
            return_values[i] = (-1, 1)

    # retrieve returned sniff result from separate process
    replies = parent_conn.recv()
    parent_conn.close()
    p.join()
    for i, ip in enumerate(ips):
        if return_values[i] == None:
            rst = IP(dst=ip) / TCP(dport=dport, sport=syn_acks[i][TCP].dport, 
                seq=syn_acks[i][TCP].ack, ack=syn_acks[i][TCP].seq + 1, flags='AR')
            send(rst, verbose=False)
            return_values[i] = get_window_size(ip, sport + i, replies, mss, syn_acks[i][TCP].seq)
    return return_values

# gets window size for communication matching given sport in set of replies
# returns window size, error tuple as defined in get_iw header
def get_window_size(ip, sport, replies, mss, recv_ackno):
    largest_mss = mss
    bytes_received = 0
    error = 0
    seqno_list = []

    # parse lengths, flags of replies
    for reply in replies:
        # only process packets that have matching dport with sport
        if reply[TCP].dport != sport:
        	continue
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
    next_expected_seqno = recv_ackno + 1
    for seqno, payload_len in sorted_seqno:
        if seqno > next_expected_seqno:
            return -1, 5
        if seqno == next_expected_seqno:
            bytes_received += payload_len
            next_expected_seqno += payload_len

    if bytes_received == 0:
        return -1, 2
    window_size = math.ceil(bytes_received / largest_mss)

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

# makes dns query for ip address if ip is human readable address
def try_dns(ip):
    if ip[0].isalpha():
        dns_req = IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=ip))
        answer = sr1(dns_req, verbose=False, timeout=1)
        if answer and answer[DNS] and answer[DNS].an:
            return answer[DNS].an.rdata
    return ip

# repeat an initial_window query for a given number of reps
def repeat_iw_query(ips, sport, reps, mss):
    # make dns query for human readable addresses
    ips = [try_dns(ip) for ip in ips]

    # copy ips list in order to be able to modify it
    ips = list(ips) 
    http_reqs = ['GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % ip for ip in ips]
    http_error_reqs = ['GET /' + 'a' * (10 * mss) + ' HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % ip for ip in ips]
    results = [[] for _ in range(len(ips))]
    errors = [[] for _ in range(len(ips))]

    # these are for if http 30x error is returned: then http_error_req is sent
    use_error_req = [False for _ in range(len(ips))]
    error_ips = []
    error_idxs = []
    error_reqs = []
    for _ in range(reps):
        windows_results = get_iw(ips, sport, http_reqs)
        for i, (iw, error) in enumerate(windows_results):
            if error != 0:
                iw = -1
            results[i].append(iw)
            errors[i].append(error)
            # if not enough data returned, try adding long uri request
            if not use_error_req[i] and error == 3:
                use_error_req[i] = True
                error_ips.append(ips[i])
                error_idxs.append(i)
                error_reqs.append(http_error_reqs[i])
        # one sport used per ip, so increment by len(ips)
        sport += len(ips)

    # reset error results
    for i in error_idxs:
        results[i] = []
        errors[i] = []
    # resend error requests reqs number of times
    for _ in range(reps):
        windows_results = get_iw(error_ips, sport, error_reqs)
        for i, (iw, error) in enumerate(windows_results):
            if error != 0:
                iw = -1
            results[error_idxs[i]].append(iw)
            errors[error_idxs[i]].append(error) 
        sport += len(error_ips)
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
