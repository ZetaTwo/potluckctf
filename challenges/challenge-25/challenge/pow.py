from hashcash import check
import random
import string
import sys
import os
import SocketServer
import hashlib
import os
import subprocess
import socket
import sys
import threading
import codecs
import time


SKIP_SECRET = "letmein_c5BXXA1x3PEh79MM"


def readline(sock):
    data = ''
    while not data.endswith("\n"):
      x = sock.recv(1)
      if len(x) < 1:
        break
      data += x
    return data
def do_pow(bits, sock):
    resource = "".join(random.choice(string.ascii_lowercase) for i in range(8))
    sock.sendall("Please use the following command to solve the Proof of Work: hashcash -mb{} {}\n".format(bits, resource))
    sys.stdout.flush()

    stamp = readline(sock).strip()

    if stamp != SKIP_SECRET:
      if not stamp.startswith("1:"):
        sock.sendall("only hashcash v1 supported")
        return False

      if not check(stamp, resource=resource, bits=bits):
        sock.sendall("invalid")
        return False


    return True

class PowHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(TIMEOUT)
            if do_pow(DIFFICULTY, self.request):
                self.request.settimeout(None) # Turns out this task doesn't like nonblocking fds
                delay = 1.0
                timeout = int(TIMEOUT / delay)
                task = subprocess.Popen(COMMAND, stdin=self.request, stdout=self.request, stderr=self.request)
                while task.poll() is None and timeout > 0:
                    #do other things too if necessary e.g. print, check resources, etc.
                    time.sleep(delay)
                    timeout -= delay
                if timeout <= 0:
                    task.kill()
                    self.request.sendall(b'Timed out...\n')
                task.wait()
        except (socket.timeout):
            self.request.sendall(b'Timed out...\n')


if __name__ == '__main__':

    DIFFICULTY = int(sys.argv[1])
    TIMEOUT = int(sys.argv[2])
    COMMAND = sys.argv[3:]


    SocketServer.ThreadingTCPServer.allow_reuse_address = True
    server = SocketServer.ThreadingTCPServer(('0.0.0.0', 1337), PowHandler)
    server.serve_forever()


