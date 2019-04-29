import csv

def get_ip_list(filename='data/majestic_million.csv'):
    ip_list = []
    file = open('ip_list.csv', 'w')
    file.write('number,ip\n')
    with open(filename) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        for row in csv_reader:
            if line_count != 0:
                # remove last character ('/') because it fucks up the dns
                ip = row[2]#[:-1]
                file.write('{},{}\n'.format(line_count, ip))
            line_count += 1
    file.close()