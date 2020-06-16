import os
import sys
import subprocess
import time


def proc_file(path):
    p = subprocess.Popen('python3 controller/main.py ' + path, shell=True)
    p.wait()


if __name__ == "__main__":
    # Create_report folder
    if not os.path.exists('final_report/'):
        os.makedirs('final_report/')
    if not os.path.exists('report/'):
        os.makedirs('report/')

    with open(sys.argv[1]+'malware.csv') as f:
        data = f.readlines()

    for line in data[:250]:
        line = line[:-1]
        file_name, type_ = line.split(',')
        continue_fl = False
        for _, dirs, _ in os.walk('final_report'):
            for dir in dirs:
                if str(file_name) in dir:
                    print('Found final report!')
                    continue_fl = True
        for _, dirs, _ in os.walk('report'):
            for dir in dirs:
                if str(file_name) in dir:
                    print('Found report')
                    continue_fl = True

        if not continue_fl:
            print(sys.argv[1]+'botnet/'+type_+'/'+file_name)
            proc_file(sys.argv[1]+'botnet/'+type_+'/'+file_name)
        k = subprocess.Popen('sudo pkill qemu-system-', shell=True)
        k.wait()
