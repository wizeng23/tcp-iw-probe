import math
import pickle
from scapy.all import *
import util as U
import random
import concurrent.futures
from tqdm import tqdm
import os
import time

from argparse import ArgumentParser

parser = ArgumentParser(description="Initial Window Probe")
parser.add_argument('--ip',
                    help="Request results for IP Addresses or URLS, split with commas")
parser.add_argument('--low',
                    type=int,
                    help="Low end of list of IP Addresses to request (inclusive)")
parser.add_argument('--high',
                    type=int,
                    help="High end of list of IP Addresses to request (exclusive)")
parser.add_argument('--mss',
                    type=int,
                    help="MSS to use in testing",
                    default=64)
parser.add_argument('--sport',
                    type=int,
                    help="first sport to use")
parser.add_argument('--dir', '-d',
                    help="Directory to store outputs")

args = parser.parse_args()

def main():
    if args.dir == None:
        timestr = time.strftime("%Y%m%d-%H%M%S")
        directory = os.path.join('experiment/', timestr)
    else:
        directory = args.dir
    if not os.path.exists(directory):
        os.mkdir(directory)
    if args.sport:
        sport = args.sport
    else:
        sport = random.randint(1024, 10000)
    
    reps = 5
    mss = args.mss
    max_workers = 20        
    category_filename = os.path.join(directory, 'categories')
    result_filename = os.path.join(directory, 'results.csv')
    categories = {1:[], 2:[], 3:[], 4:[], 5:[]}

    if args.ip:
        ips = args.ip.split(',')
        outputs = U.repeat_iw_query(ips=ips, sport=sport, reps=reps, mss=mss)
        for j, output in enumerate(zip(*outputs)):
            results, errors, use_error_req = output
            category, result = U.get_category(results)
            categories[category].append((ips[j], result))
            result_str = ','.join([str(res) for res in results])
            error_str = ','.join([str(error) for error in errors])
            print('IP Address: {},Initial Windows: {}, Error Number: {}\n'.format(ips[j], result_str, error_str))
    else:
        if args.low == None or args.high == None:
            raise Exception('Missing arguments to both IP and Low/High range. At least one must be supplied')
        if args.low >= args.high:
            raise Exception('Passed in low parameter is greater than or equal to high parameter. --low must be lower than --high')
        num_ips = args.high - args.low
        ip_list = U.get_ip_list(amount=num_ips, offset=args.low)

        result_file = open(result_filename, 'w')
        result_file.write('IP,Used_error,Results,Errors\n')

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
