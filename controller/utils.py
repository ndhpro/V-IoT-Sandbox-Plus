from __future__ import print_function
import os
import time
import paramiko
from qemu_ctl import scp_to_vm


def check_file_arch(file):
    output = os.popen('file ' + file)
    name = str(file)
    ret = output.read()
    info = dict()

    info['name'] = name[name.rfind('/')+1:]
    if 'ELF' in ret:
        info['type'] = 'ELF'
        if 'ARM' in ret:
            info['arch'] = 'arm'
            print('ARM')
        elif 'MIPS' in ret:
            if 'MSB' in ret:
                info['arch'] = 'mips'
            else:
                info['arch'] = 'mipsel'
            print('MIPS (' + info['arch'] + ')')
        elif 'Intel' in ret:
            info['arch'] = 'i386'
            print('Intel 80386')
        elif 'x86-64' in ret:
            info['arch'] = 'amd64'
            print('x86-64')
        elif 'PowerPC' in ret:
            info['arch'] = 'ppc'
            print('PowerPC')
        else:
            info['arch'] = 'Unsupported'
            print(ret)
    else:
        info['type'] = 'Unsupported'

    if 'LSB' in ret:
        info['endianess'] = 'little'
    else:
        info['endianess'] = 'big'

    if 'static' in ret:
        info['linked-libs'] = 'static'
    else:
        info['linked-libs'] = 'dynamic'

    return info


def paramiko_client(vm_ip, cmd, thread=None, que=None, debug=False):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(vm_ip, username='root', password='root')
    _, stdout, _ = client.exec_command(cmd)

    server_output = 0
    if thread:
        thread.join()
        server_output = que.get()

    if server_output == -1:
        exit_status = 'timeout'
        output = None
    else:
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode('utf-8')
        if debug:
            print(output)
    client.close()
    return exit_status, output


def paramiko_client_ipt(vm_ip):
    print('Moving ip_list...', end=' ')
    if scp_to_vm('ip_list.txt', 'root', vm_ip, '/root/') == 1:
        print('Failed to move list of C&C IPs')
        exit(0)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(vm_ip, username='root', password='root')
    server_ip = '192.168.122.1:12345'
    cmd = 'for IP in $(cat ip_list.txt); do iptables -t nat -A OUTPUT -p tcp -d $IP -j DNAT --to-destination ' + \
        server_ip + '; done'
    _, stdout, _ = client.exec_command(cmd)
    exit_status = stdout.channel.recv_exit_status()
    print('Redirect... OK')
    client.close()
