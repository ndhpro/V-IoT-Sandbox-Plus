from __future__ import print_function
import subprocess
import signal
import sys
import os
import threading
import time
import shutil
import queue
import json
import pickle
import warnings

import paramiko

from qemu_ctl import *
from server import server
from pcap_analyzer import process_pcap
from utils import *
from scapy.all import *
import pandas as pd
import numpy as np
from gensim.models.doc2vec import Doc2Vec
from graph2vec import graph2vec


vm_ip_dict = {
    'arm': '192.168.122.100',
    'mips': '192.168.122.101',
    'mipsel': '192.168.122.101',
    'i386': '192.168.122.102',
    'amd64': '192.168.122.103',
    'ppc': '192.168.122.104',
}
server_ip = '192.168.122.1:12345'


def pre_analyze(elf):
    print('CPU architecture...', end=' ')
    info = check_file_arch(sys.argv[1])
    with open('info.json', 'w') as f:
        json.dump(info, f)

    arch = info['arch']
    lib = info['linked-libs']

    if arch == 'Unsupported':
        print('Unsupported CPU architecture')
        exit(0)

    print('Starting VM...')
    start_vm(arch)

    vm_ip = vm_ip_dict[arch]

    print('Copying ELF to VM...', end=' ')
    if scp_to_vm(sys.argv[1], 'root', vm_ip, '/root/qemu') == 1:
        shutdown_vm(arch)
        exit(0)

    if lib == 'dynamic':
        print('Checking requested libs...', end=' ')
        cmd = 'cd qemu/ && chmod +x ' + elf + ' && ldd ' + elf
        exit_status, output = paramiko_client(vm_ip, cmd)
        if 'not found' in output:
            print('\nFound missing libs...', end=' ')
            src_lib = os.getcwd() + '/lib_repo/' + arch + '/'
            dst_lib = '/lib/'
            rsync('root', vm_ip, dst_lib, src_lib)
        else:
            print('OK')
    else:
        print('Static, no need to check requested libs')

    print('Analyzing...')
    cmd = 'cd qemu/ && chmod +x ' + elf + ' && python main.py ' + elf + ' 3'
    exit_status, output = paramiko_client(vm_ip, cmd)
    if exit_status == 0:
        print('Receiving report...', end=' ')
        output = output.split('\n')
        report_dir = output[-2][2:]
        scp_to_host('root', vm_ip, '/root/qemu/' +
                    report_dir, './report/', r=True)
    else:
        print('Failed\n' + str(output).strip())
        shutdown_vm(arch)
        exit(0)

    print('Shutting down VM...', end=' ')
    shutdown_vm(arch)
    return arch, lib, report_dir


def analyze_ccserver(elf, arch, lib, report_dir):
    ip_list, fl = process_pcap('./report/' + report_dir + 'tcpdump.pcap')
    if not fl:
        print('Unexpected connection error... Exitting')
        return 0
    print('C&C Server detected... ' + str(len(ip_list)) + ' IP(s)')
    if len(ip_list) == 0:
        print('Finalizing report...', end=' ')
        shutil.move('report/' + report_dir, 'final_report/')
        shutil.move('info.json', 'final_report/' + report_dir)
        print('Done')
        return report_dir

    print('Starting VM...')
    start_vm(arch)

    vm_ip = vm_ip_dict[arch]

    print('Copying ELF to VM...', end=' ')
    if scp_to_vm(sys.argv[1], 'root', vm_ip, '/root/qemu') == 1:
        shutdown_vm(arch)
        exit(0)

    if lib == 'dynamic':
        cmd = 'cd qemu/ && chmod +x ' + elf + ' && ldd ' + elf
        exit_status, output = paramiko_client(vm_ip, cmd)
        if 'not found' in output:
            print('Moving libs...', end=' ')
            src_lib = os.getcwd() + '/lib_repo/' + arch + '/'
            dst_lib = '/lib/'
            rsync('root', vm_ip, dst_lib, src_lib)
        else:
            print('OK')

    with open('ip_list.txt', 'w') as f:
        for ip in ip_list:
            f.write(ip + '\n')
    paramiko_client_ipt(vm_ip)

    que = queue.Queue()
    serverThread = threading.Thread(
        target=lambda q, arg: q.put(server(arg)), args=(que, '', ))
    serverThread.start()

    cmd = 'cd qemu/ && chmod +x ' + elf + ' && python main.py ' + elf + ' 3'
    exit_status, output = paramiko_client(vm_ip, cmd, serverThread, que)

    if exit_status == 0:
        print('Receiving report...', end=' ')
        output = output.split('\n')
        final_report_dir = output[-2][2:]
        scp_to_host('root', vm_ip, '/root/qemu/' +
                    final_report_dir, './final_report/', r=True)
    else:
        if exit_status != 'timeout':
            print('Failed\n' + str(output).strip())
        print('Finalizing report...', end=' ')
        shutil.move('report/' + report_dir, 'final_report/')
        final_report_dir = report_dir
        print('Done')

    try:
        shutil.move('info.json', 'final_report/' + final_report_dir)
        shutil.move('ip_list.txt', 'final_report/' + final_report_dir)
    except Exception as e:
        print(e)

    if not os.path.exists('final_report/' + final_report_dir):
        print('Unexpected connection error...')
        shutil.move('report/' + report_dir, 'final_report/')
        shutil.move('info.json', 'final_report/' + report_dir)
        shutil.move('ip_list.txt', 'final_report/' + report_dir)
        print('Finalized report.')

    print('Shutting down VM...', end=' ')
    shutdown_vm(arch)
    return final_report_dir


def extract_net(final_report_dir):
    dir_path = 'final_report/' + final_report_dir + '/tcpdump.pcap'
    pcap = rdpcap(dir_path)
    wrpcap('temp/temp.pcap', '')
    for i, pkt in enumerate(pcap):
        wrpcap('temp/temp.pcap', pkt, append=True)
        if i == 49:
            break
    p = subprocess.call(
        'cd CICFlowMeter-4.0/bin/ && ./cfm ../../temp/temp.pcap ../../temp/ > /dev/null', shell=True)
    os.remove('temp/temp.pcap')

    attributes = ['Sum ', 'Max ']
    features = ['Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
                'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd IAT Tot', 'Bwd IAT Tot',
                'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
                'Fwd Header Len', 'Bwd Header Len',
                'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt',
                'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt',
                'Init Fwd Win Byts', 'Init Bwd Win Byts',
                'Fwd Act Data Pkts']
    headers = [att + ft for ft in features for att in attributes]
    headers.insert(0, 'Num of flow')

    data = dict()
    data['Num of flow'] = list()
    for feature in features:
        data['Sum ' + feature] = list()
        data['Max ' + feature] = list()

    flow_path = 'temp/temp.pcap_Flow.csv'

    try:
        flow = pd.read_csv(flow_path)
        data['Num of flow'].append(len(flow.index))
        for feature in features:
            data['Sum ' + feature].append(flow[feature].sum())
            data['Max ' + feature].append(max(flow[feature], default=0))
    except Exception as e:
        print(e)
        data['Num of flow'].append(0)
        for feature in features:
            data['Sum ' + feature].append(0)
            data['Max ' + feature].append(0)
    os.remove(flow_path)
    return pd.DataFrame(data)[headers].values


def extract_per(final_report_dir):
    features = [
        "num_total_running", "num_total_sleeping", "num_total_zombie", "num_total_stopped",
        "cpu_%_us", "cpu_%_sy", "cpu_%_ni", "cpu_%_id",
        "cpu_%_wa", "cpu_%_hi", "cpu_%_si", "cpu_%_st",
        "mem_total", "mem_used", "mem_free", "mem_buffers",
        "swap_total", "swap_used", "swap_free", "swap_cache"
    ]

    report_path = 'final_report/' + final_report_dir + '/top.json'
    vt = dict()
    with open(report_path, 'r') as f:
        data = json.load(f)

    for ft in features:
        arr = list()
        for i, step in enumerate(data):
            arr.append(step[ft])
            if i >= 20:
                break
        arr = np.array(arr, dtype=np.float)
        vt[ft + '_mean'] = np.mean(arr)
        vt[ft + '_std'] = np.std(arr)
        vt[ft + '_max'] = np.max(arr)
        vt[ft + '_min'] = np.min(arr)
    header = list()
    for ft in features:
        for att in ['_mean', '_std', '_max', '_min']:
            header.append(ft + att)
    data = list()
    data.append(vt)
    return pd.DataFrame(data)[header].values


def extract_syscall(final_report_dir):
    warnings.filterwarnings("ignore")
    model = Doc2Vec.load('model/doc2vec')
    i = final_report_dir[:final_report_dir.find('_')]
    try:
        data = model.docvecs['g_' + i].reshape(1, -1)
    except Exception as e:
        print(e)
        strace_list = list()
        report_path = 'final_report/' + final_report_dir + '/'
        for _, _, files in os.walk(report_path):
            G = dict()
            G['edges'] = list()
            node = set()
            files.sort()
            for file_name in files:
                if file_name.startswith('strace'):
                    with open(report_path + file_name, 'r') as f:
                        data = json.load(f)
                    for syscall in data:
                        node.add(syscall['name'])
            node = list(node)
            c = 0
            for file_name in files:
                if file_name.startswith('strace'):
                    with open(report_path + file_name, 'r') as f:
                        data = json.load(f)
                    u = -1
                    for syscall in data:
                        v = node.index(syscall['name'])
                        if u >= 0:
                            if c > 300:
                                break
                            G['edges'].append([u, v])
                            c += 1
                        u = v
            graph = 'temp/graph.json'
            with open(graph, 'w') as f:
                json.dump(G, f)
        data = graph2vec()
        os.remove(graph)
    return data


if __name__ == "__main__":
    print('V-IoT-Sandbox Plus')
    print('Analyzing', sys.argv[1])
    elf = '.' + sys.argv[1][sys.argv[1].rfind('/'):]

    print('-' * 80)
    print('Stage 1: Pre-analyze')
    arch, lib, report_dir = pre_analyze(elf)

    print('-' * 80)
    print('Stage 2: Analyzing with C&C Server')
    final_report_dir = analyze_ccserver(elf, arch, lib, report_dir)

    # final_report_dir = 'cf04a95a254a9aada0440281f82d6e9c_1593062314'

    print('-' * 80)
    print('Stage 3: Detection result')
    net = extract_net(final_report_dir)
    fs = pickle.load(open('model/net_fs.sav', 'rb'))
    norm = pickle.load(open('model/net_norm.sav', 'rb'))
    clf_net = pickle.load(open('model/net_DecisionTree.sav', 'rb'))
    net = fs.transform(net)
    net = norm.transform(net)
    res = clf_net.predict_proba(net)[0].item(1)
    print('Network-based Decision:     ', end='')
    if res > 0.5:
        print('\033[91mMALWARE\033[00m (Probability: %.4f)' % (res))
    else:
        print('\033[92mBENIGN\033[00m (Probability: %.4f)' % (res))

    per = extract_per(final_report_dir)
    fs = pickle.load(open('model/per_fs.sav', 'rb'))
    norm = pickle.load(open('model/per_norm.sav', 'rb'))
    clf_per = pickle.load(open('model/per_RandomForest.sav', 'rb'))
    per = fs.transform(per)
    per = norm.transform(per)
    res1 = clf_per.predict_proba(per)[0].item(1)
    print('Performance-based Decision: ', end='')
    if res1 > 0.5:
        print('\033[91mMALWARE\033[00m (Probability: %.4f)' % (res1))
    else:
        print('\033[92mBENIGN\033[00m (Probability: %.4f)' % (res1))

    syscall = extract_syscall(final_report_dir)
    fs = pickle.load(open('model/syscall_fs.sav', 'rb'))
    norm = pickle.load(open('model/syscall_norm.sav', 'rb'))
    clf_sys = pickle.load(open('model/syscall_SVM.sav', 'rb'))
    syscall = fs.transform(syscall)
    syscall = norm.transform(syscall)
    res2 = clf_sys.predict_proba(syscall)[0].item(1)
    print('System Call-based Decision: ', end='')
    if res2 > 0.5:
        print('\033[91mMALWARE\033[00m (Probability: %.4f)' % (res2))
    else:
        print('\033[92mBENIGN\033[00m (Probability: %.4f)' % (res2))

    res = (res + res1 + res2) / 3
    print('-' * 80)
    print('Final Decision:\t\t    ', end='')
    if res >= 0.5:
        print('\033[91mMALWARE\033[00m (Probability: %.4f)' % (res))
    else:
        print('\033[92mBENIGN\033[00m (Probability: %.4f)' % (res))
