import sys
import subprocess
import json
from datetime import datetime
import time
import logging

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
log = logging.getLogger(__name__)


class Lib:
    def __init__(self, target, output):
        self.target = target
        self.proc = None
        self.output = output

    def start(self):
        print('ldd start...')
        self.proc = subprocess.Popen(['ldd', self.target], stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
        self.proc.wait()
        # data = p.communicate()[1].decode('utf8').split('\n')

        err, data = self.proc.communicate()
        print(err)

        with open(self.output, 'w') as f:
            f.write(err.replace('\t', ''))


if __name__ == "__main__":
    lib = Lib(sys.argv[1], 'temp/ldd.txt')
    lib.start()
