import pickle
from scapy.all import *

ip_list = ['104.196.238.229', '172.217.6.7', '171.67.215.200']
categories = {1:[], 2:[], 3:[], 4:[], 5:[]}
mss = 100
reps = 5
sport = 10
filename = 'categories'

def get_iw(ip, mss, sport):
    return mss*10, 'status'

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
    for ip in ip_list:
        results = []
        for _ in range(reps):
            iw, status = get_iw(ip, mss, sport)
            results.append(iw)
        category, result = get_category(results)
        categories[category].append((ip, result))

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

    with open(filename, 'wb') as file:
        pickle.dump(categories, file)
    print('Saved categories pickle to "{}"'.format(filename))

if __name__ == '__main__':
    main()
