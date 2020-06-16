import sys
import logging
import os
import subprocess
import time

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
log = logging.getLogger(__name__)


class Sniffer:
    def __init__(self, file_path):
        self.proc = None
        self.proc_sample = None
        self.file_path = file_path
        self.machine = {}
        self.machine['interface'] = 'eth0'
        self.machine['user'] = 'root'

    def start(self):
        pargs = [
            "tcpdump", "-U", "-q", "-s", "0", "-n",
            "-i", self.machine['interface'],
        ]
        pargs.extend(["-Z", self.machine['user']])
        pargs.extend(["-w", self.file_path])
        # pargs.extend(["host", self.machine.ip])
        # Do not capture Agent traffic.
        # pargs.extend([
        #     "and", "not", "(",
        #     "dst", "host", self.machine.ip, "and",
        #     "dst", "port", "%s" % CUCKOO_GUEST_PORT,
        #     ")", "and", "not", "(",
        #     "src", "host", self.machine.ip, "and",
        #     "src", "port", "%s" % CUCKOO_GUEST_PORT,
        #     ")",
        # ])

        # # Do not capture ResultServer traffic.
        # pargs.extend([
        #     "and", "not", "(",
        #     "dst", "host", self.machine.resultserver_ip, "and",
        #     "dst", "port", "%s" % self.machine.resultserver_port,
        #     ")", "and", "not", "(",
        #     "src", "host", self.machine.resultserver_ip, "and",
        #     "src", "port", "%s" % self.machine.resultserver_port,
        #     ")",
        # ])

        print(' '.join(pargs))
        try:
            self.proc = subprocess.Popen(
                pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
            )
        except (OSError, ValueError):
            print('Error while stating tcpdump')
            return False
        log.info(
            "Started sniffer with PID %d (interface=%s, host=%s)",
            self.proc.pid, self.machine['interface'], '127.0.0.1'
        )
        return True

    def _check_output(self, out, err):

        err = err.decode("utf-8")
        if out:
            raise Exception(
                "Potential error while running tcpdump, did not expect "
                "standard output, got: %r." % out
            )

        err_whitelist_start = (
            "tcpdump: listening on ",
        )

        err_whitelist_ends = (
            "packet captured",
            "packets captured",
            "packet received by filter",
            "packets received by filter",
            "packet dropped by kernel",
            "packets dropped by kernel",
            "packet dropped by interface",
            "packets dropped by interface",
            "dropped privs to root",
        )

        for line in err.split("\n"):
            if not line or line.startswith(err_whitelist_start):
                continue

            if line.endswith(err_whitelist_ends):
                continue

            raise Exception(
                "Potential error while running tcpdump, did not expect "
                "the following standard error output: %r." % line
            )

    def stop(self):
        """Stop sniffing.
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
                "Error running tcpdump to sniff the network traffic during "
                "the analysis; stdout = %r and stderr = %r. Did you enable "
                "the extra capabilities to allow running tcpdump as non-root "
                "user and disable AppArmor properly (the latter only applies "
                "to Ubuntu-based distributions with AppArmor, see also %s)?" %
                (out, err, ("permission-denied-for-tcpdump"))
            )

        try:
            self.proc.terminate()
        except:
            try:
                if not self.proc.poll():
                    log.debug("Killing sniffer")
                    self.proc.kill()
            except OSError as e:
                log.debug("Error killing sniffer: %s. Continue", e)
            except Exception as e:
                log.exception("Unable to stop the sniffer with pid %d: %s",
                              self.proc.pid, e)

        # Ensure expected output was received from tcpdump.
        out, err = self.proc.communicate()
        self._check_output(out, err)
