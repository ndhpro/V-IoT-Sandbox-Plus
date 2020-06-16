import sys
import logging
import os
import subprocess
import time
from sniffer import Sniffer
from strace import Strace
from top import Top
from lsof import Lsof
from lib import Lib
import threading

outputPcap = None
outputStrace = None
outputTop = None
outputLsof = None
outputLdd = None


if __name__ == "__main__":
    logging.debug('This is a debug message')
    startTime = int(time.time())

    path = sys.argv[1] + '_' + str(startTime) + '/'

    os.mkdir(path)
    outputPcap = path + 'tcpdump.pcap'
    outputStrace = path + 'strace'
    outputTop = path + 'top.json'
    outputLsof = path + 'lsof.json'
    outputLdd = path + 'ldd.txt'

    timeout = int(sys.argv[2])
    sniff = Sniffer(outputPcap)
    top = Top(outputTop)
    strace = Strace(sys.argv[1], outputStrace, timeout)
    lsof = Lsof(outputLsof)
    ldd = Lib(sys.argv[1], outputLdd)

    ldd.start()

    topThread = threading.Thread(target=top.start, args=())
    topThread.start()
    lsofThread = threading.Thread(target=lsof.start, args=())
    lsofThread.start()

    sniff.start()

    strace.start()

    sniff.stop()
    strace.stop()
    topThread.do_run = False
    topThread.join()
    lsofThread.do_run = False
    lsofThread.join()

    print('.done')
    print(path)
