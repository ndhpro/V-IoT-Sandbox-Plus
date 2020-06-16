from __future__ import print_function
import subprocess
import signal
import sys
import os

import paramiko


def scp_to_vm(local_path, remote_user, remote_host, remote_path, r=False):
    if r:
        p = subprocess.Popen("sshpass -p 'root' scp -q -r %s %s@%s:%s" %
                             (local_path, remote_user, remote_host,
                              remote_path), shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                             )
    else:
        p = subprocess.Popen("sshpass -p 'root' scp -q %s %s@%s:%s" %
                             (local_path, remote_user, remote_host,
                              remote_path), shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                             )
    output = p.communicate()[1].decode('utf-8')
    if output != '':
        print('Failed\n' + output[1].strip())
        return 1
    else:
        print('Done')
        return 0


def scp_to_host(remote_user, remote_host, remote_path, local_path, r=False):
    if r:
        p = subprocess.Popen("sshpass -p 'root' scp -q -r %s@%s:%s %s" %
                             (remote_user, remote_host, remote_path, local_path), shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    else:
        p = subprocess.Popen("sshpass -p 'root' scp -q %s@%s:%s %s" %
                             (remote_user, remote_host, remote_path, local_path), shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    output = p.communicate()[1].decode('utf-8')
    if output != '':
        print('Failed\n' + output[1].strip())
        return 1
    else:
        print('Done')
        return 0


def rsync(remote_user, remote_host, remote_path, local_path):
    p = subprocess.Popen("sshpass -p 'root' rsync -q -avz --ignore-existing %s %s@%s:%s" %
                         (local_path, remote_user, remote_host, remote_path), shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    output = p.communicate()[1].decode('utf-8')
    print('Moved libs')


def start_vm(arch):
    p = subprocess.Popen('cd ./vm/ && sudo ./' + arch + '.sh',
                         shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    while True:
        line = p.stdout.readline().decode('utf-8')
        # print(line.strip())
        if 'Debian GNU/Linux 7 debian-' in line:
            break


def shutdown_vm(arch):
    k = subprocess.Popen('sudo pkill qemu-system-', shell=True)
    k.wait()
    print('Done')
