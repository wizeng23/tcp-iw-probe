import pickle
from scapy.all import *
import util as U
import random



# returns category and the result number
def get_category(results):
    num_results = 0
    first_result = None
    same_result = True
    results_dict = {}
    for result in results:
        if result not in results_dict:
            results_dict[result] = 1
        else:
            results_dict[result] += 1
    max_value = -1
    result_value = None
    num_results = 0
    for k, v in results_dict.items():
        if v > max_value:
            max_value = v
            result_value = k
        num_results += v
    if max_value >= 3:
        return 1, result_value
    if num_results >= 3:
        return 2, result_value
    if max_value >= 1:
        return 3, result_value
    return 5, 0

def main():
    # keith, google, stanford
    ip_list = ['104.196.238.229', '172.217.6.7', '171.67.215.200']
    mss = 100
    reps = 5
    sport = random.randint(1024, 10000)
    result_format = 'results-mss{}reps{}.csv'
    category_format = 'categories-mss{}-reps{}'
    categories = {1:[], 2:[], 3:[], 4:[], 5:[]}
    result_filename = result_format.format(mss, reps)
    result_file = open(result_filename, 'w')
    for ip in ip_list:
        http_req = 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % ip
        http_error_req = 'GET /' + 'a' * (10 * mss) + ' HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % ip
        results = []
        statuses = []
        use_error_req = False
        print('IP: {}'.format(ip))
        i = 0
        while i < reps:
            # sport = random.randint(1024, 65500)
            sport += 1
            if use_error_req:
                iw, status = U.get_iw(ip, sport, app_req=http_error_req)
            else:
                iw, status = U.get_iw(ip, sport, app_req=http_req)
            if not use_error_req and status == 3:
                print('Switching to http error string')
                i = 0
                use_error_req = True
                results = []
                statuses = []
                continue
            i += 1
            results.append(iw)
            statuses.append(status)
        print('{:25s} {}' .format('Initial Window Results:', str(results)))
        print('{:25s} {}' .format('Returned Code:', str(statuses)))
        category, result = get_category(results)
        categories[category].append((ip, result))
        result_str = ','.join([str(res) for res in results])
        status_str = ','.join([str(stat) for stat in statuses])
        # print(result_str)
        # print(status_str)
        result_file.write('{},{},{}\n'.format(ip, result_str, status_str))
    result_file.close()

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

    category_filename = category_format.format(mss, reps)
    with open(category_filename, 'wb') as category_file:
        pickle.dump(categories, category_file)
    print('Saved categories pickle to "{}"'.format(category_filename))

if __name__ == '__main__':
    main()
