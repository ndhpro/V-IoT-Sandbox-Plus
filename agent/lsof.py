import threading
import sys
import subprocess
import json
from datetime import datetime
import time
import logging

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
log = logging.getLogger(__name__)


class Lsof:
    def __init__(self, output):
        self.proc = None
        self.res = []
        self.output = output

    def handleData(self, data):
        obj = {}
        now = time.mktime(datetime.now().timetuple())
        obj['timestamp'] = int(now)

        obj['info'] = []
        for line in data[1:]:
            if len(line) > 76:
                dev = siz = nod = True
                if line[56] == ' ':
                    dev = False
                if line[65] == ' ':
                    siz = False
                if line[76] == ' ':
                    nod = False
                temp = line.split(' ')
                while '' in temp:
                    temp.remove('')
                dat = {}
                dat['COMMAND'] = temp[0].strip()
                dat['PID'] = temp[1].strip()
                dat['USER'] = temp[2].strip()
                dat['FD'] = temp[3].strip()
                dat['TYPE'] = temp[4].strip()
                id = 5
                if dev:
                    dat['DEVICE'] = temp[id].strip()
                    id += 1
                else:
                    dat['DEVICE'] = ''
                if siz:
                    dat['SIZE'] = temp[id].strip()
                    id += 1
                else:
                    dat['SIZE'] = ''
                if nod:
                    dat['NODE'] = temp[id].strip()
                    id += 1
                else:
                    dat['NODE'] = ''
                dat['NAME'] = temp[id].strip()
                obj['info'].append(dat)
        # print(obj)
        return obj

    def start(self):
        print('lsof start...')
        t = threading.currentThread()
        while getattr(t, "do_run", True):
            self.proc = subprocess.Popen(['lsof'], stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
            data = self.proc.communicate()[0].decode('utf8').split('\n')

            obj = self.handleData(data)
            self.res.append(obj)
        # print("Stopping as you wish.")
        # print('self res', self.res)
        with open(self.output, 'w') as f:
            json.dump(self.res, f)

    def stop(self):
        """Stop.
        @return: operation status.
        """
        # The tcpdump process was never started in the first place.
        if not self.proc:
            return

        # The tcpdump process has already quit, generally speaking this
        # indicates an error such as "permission denied".
        if self.proc.poll():
            out, err = self.proc.communicate()
            raise Exception(
                "permission-denied-for-lsof")

        try:
            self.proc.terminate()
        except:
            try:
                if not self.proc.poll():
                    log.debug("Killing lsof")
                    self.proc.kill()
            except OSError as e:
                log.debug("Error killing lsof: %s. Continue", e)
            except Exception as e:
                log.exception("Unable to stop the lsof with pid %d: %s",
                              self.proc.pid, e)

        # Ensure expected output was received from lsof.
        #out, err = self.proc.communicate()
        #log.debug(out, err)


if __name__ == "__main__":
    lsof = Lsof('test.txt')
    with open('lsof', 'r') as f:
        data = f.readlines()
    # print(data)
    lsof.handleData(data)
