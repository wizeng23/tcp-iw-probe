import pickle
from scapy.all import *
import util as U

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

def main():
    # keith, google, stanford
    ip_list = ['104.196.238.229', '172.217.6.7', '171.67.215.200']
    mss = 100
    reps = 5
    sport = 1100
    result_format = 'results-mss{}reps{}.csv'
    category_format = 'categories-mss{}-reps{}'
    categories = {1:[], 2:[], 3:[], 4:[], 5:[]}
    result_filename = result_format.format(mss, reps)
    result_file = open(result_filename, 'w')
    for ip in ip_list:
        results = []
        statuses = []
        print('IP: {}'.format(ip))
        for _ in range(reps):
            print('Rep')
            iw, status = U.get_iw(ip, sport)
            sport += 1
            results.append(iw)
            statuses.append(status)
        category, result = get_category(results)
        categories[category].append((ip, result))
        result_str = ','.join([str(res) for res in results])
        status_str = ','.join([str(stat) for stat in statuses])
        print(result_str)
        print(status_str)
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
    for i in range(1, 5):
        count = results.count(i)
        result_total += count
        print('ICW {}: {}'.format(i, count))
    print('ICW 5+: {}'.format(len(results) - result_total))
    print('Total: {}'.format(len(results)))

    category_filename = category_format.format(mss, reps)
    with open(category_filename, 'wb') as category_file:
        pickle.dump(categories, category_file)
    print('Saved categories pickle to "{}"'.format(category_filename))

if __name__ == '__main__':
    main()
