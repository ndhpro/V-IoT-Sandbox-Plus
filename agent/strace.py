import sys
import subprocess
import json
from datetime import datetime
import time
import logging
import os

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
log = logging.getLogger(__name__)


class Strace:
    def __init__(self, target, output, timeout):
        self.target = target
        self.proc = None
        self.output = output
        self.timeout = timeout

    def start(self):
        print('strace start...')
        self.proc = subprocess.Popen(['timeout', '-k', '1', str(self.timeout), 'strace', '-to', 'temp', '-ff', self.target], stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
        # data = p.communicate()[1].decode('utf8').split('\n')

        finish = False
        checked = []
        child_pool = []
        index = 0
        while not finish or self.proc.poll() == None:
            finish = True
            file_list = []
            for _, _, files in os.walk('./'):
                for file in files:
                    if str(file).startswith('temp'):
                        file_list.append(file)

            for file in file_list:
                pid = file[file.rfind('.')+1:].strip()
                if os.path.getsize(file) == 0 and pid not in checked:
                    child = subprocess.Popen(['timeout', '-k', '1', str(self.timeout), 'strace', '-to', 'temp_' + str(index), '-ffp', pid], stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE)
                    child_pool.append(child)
                    pid = file[file.find('.')+1:]
                    print('detected untraced proc... ' + pid)
                    checked.append(pid)
                    finish = False

            for child in child_pool:
                if child.poll() == None:
                    finish = False
            index += 1

        print('convert json...')
        file_list = []
        for _, _, files in os.walk('./'):
            for file in files:
                if str(file).startswith('temp') and os.path.getsize(file) > 0:
                    file_list.append(file)

        for file in file_list:
            with open(file, 'r') as f:
                data = f.readlines()

            # err, data = self.proc.communicate()
            # print(err, data)
            # print(data)
            # data = data.decode('utf8').split('\n')
            res = []
            # print(data)
            for line in data:
                if '=' in line:
                    if str(line).startswith('+++') or str(line).startswith('---'):
                        continue
                    obj = {}
                    now = datetime.now().strftime('%Y/%m/%d ') + \
                        str(line[:line.find(' ')])
                    cur = datetime.strptime(now, '%Y/%m/%d %H:%M:%S')

                    obj['timestamp'] = int(time.mktime(cur.timetuple()))
                    line = line[line.find(' ')+1:]
                    obj['name'] = line[:line.find('(')]
                    line = line[line.find('(')+1:]
                    obj['return'] = line[line.rfind('=')+1:-1].strip()
                    line = line[:line.rfind('=')-1]
                    obj['arguments'] = line[:line.rfind(')')].strip()
                    res.append(obj)
            with open(self.output + file[file.rfind('.')+1:] + '.json', 'w') as f:
                json.dump(res, f)

    def stop(self):
        """Stop.
        @return: operation status.
        """
        # The strace process was never started in the first place.
        if not self.proc:
            return

        # The tcpdump process has already quit, generally speaking this
        # indicates an error such as "permission denied".
        if self.proc.poll() != None:
            return
            out, err = self.proc.communicate()
            raise Exception(
                "permission-denied-for-strace"
            )

        try:
            self.proc.terminate()
        except:
            try:
                if self.proc.poll() == None:
                    log.debug("Killing strace")
                    self.proc.kill()
            except OSError as e:
                log.debug("Error killing strace: %s. Continue", e)
            except Exception as e:
                log.exception("Unable to stop the strace with pid %d: %s",
                              self.proc.pid, e)

        # Ensure expected output was received from strace.
        out, err = self.proc.communicate()
        log.debug(out, err)
