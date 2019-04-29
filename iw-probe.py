import math
import pickle
from scapy.all import *
import util as U
import random
import concurrent.futures
from tqdm import tqdm

# exception_filename = 
category_filename = 'experiment/current/categories'
result_filename = 'experiment/current/results.csv'

def main():
    # keith, google, stanford
    # ip_list = ['104.196.238.229', '172.217.6.7', '171.67.215.200']
    ip_list = U.get_ip_list(amount=60, offset=0)
    print('Got IP list')
    mss = 64
    reps = 5
    max_workers = 20
    sport = random.randint(1024, 10000)
    category_lock = Lock()
    categories = {1:[], 2:[], 3:[], 4:[], 5:[]}
    result_file = open(result_filename, 'w')
    result_file.write('IP,Used_error,Results,Errors\n')
    result_file_lock = Lock()

    itr = math.ceil(len(ip_list) / max_workers)
    pbar = tqdm(total=itr)
    for i in range(itr):
        end = min((i + 1) * max_workers, len(ip_list))
        ips = ip_list[(i*max_workers):end]
        outputs = U.repeat_iw_query(ips=ips, sport=sport, reps=reps, mss=mss)
        for j, output in enumerate(zip(*outputs)):
            results, errors, use_error_req = output
            category, result = U.get_category(results)
            categories[category].append((ips[j], result))
            result_str = ','.join([str(res) for res in results])
            error_str = ','.join([str(error) for error in errors])
            result_file.write('{},{},{},{}\n'.format(ips[j], use_error_req, result_str, error_str))
            pbar.update(1)
    # result_file.close()

    # with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
    #     future_to_ip = {}
    #     for ip in ip_list:
    #         future_to_ip[executor.submit(U.repeat_iw_query, ip, sport, reps, mss)] = ip
    #         sport += reps * 2
    #     for future in concurrent.futures.as_completed(future_to_ip):
    #         pbar.update(1)
    #         ip = future_to_ip[future]
    #         try:
    #             data = future.result()
    #         except Exception as exc:
    #             print('%s generated an exception: %s' % (ip, exc))
    #         else:
    #             if data != None:
    #                 results, statuses = data
    #                 category, result = U.get_category(results)
    #                 category_lock.acquire()
    #                 categories[category].append((ip, result))
    #                 category_lock.release()
    #                 result_str = ','.join([str(res) for res in results])
    #                 status_str = ','.join([str(stat) for stat in statuses])
    #                 result_file_lock.acquire()
    #                 result_file.write('{},{},{}\n'.format(ip, result_str, status_str))
    #                 result_file_lock.release()
    # result_file.close()

        # future_to_ip = {executor.submit(repeat_iw_query, ip, ): url for url in URLS}
        # for future in concurrent.futures_
    # for ip in ip_list:

    #     results, statuses = repeat_iw_query(ip, sport, reps)
    #     category, result = get_category(results)
    #     category_lock.acquire()
    #     categories[category].append((ip, result))
    #     category_lock.release()
    #     result_str = ','.join([str(res) for res in results])
    #     status_str = ','.join([str(stat) for stat in statuses])
    #     result_file_lock.acquire()
    #     result_file.write('{},{},{}\n'.format(ip, result_str, status_str))
    #     result_file_lock.release()
    # result_file.close()

    print('Number of IPs: {}'.format(len(ip_list)))
    print('---------------')

    category_total = 0
    for i in range(1, 6):
        category_len = len(categories[i])
        category_total += category_len
        print('Category {}: {}'.format(i, category_len))
    print('Total: {}'.format(category_total))

    results = [result for (ip, result) in categories[1] if result > 0]
    result_total = 0
    print('---------------')
    for i in range(1, 11):
        count = results.count(i)
        result_total += count
        print('ICW {}: {}'.format(i, count))
    print('ICW 11+: {}'.format(len(results) - result_total))
    print('Total: {}'.format(len(results)))

    with open(category_filename, 'wb') as category_file:
        pickle.dump(categories, category_file)
    print('Saved categories pickle to "{}"'.format(category_filename))

if __name__ == '__main__':
    main()
