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
