import socket
import threading


def send(c):
    while True:
        cmd = input()
        c.send(cmd.encode())
        print('\033[91msend: \033[00m' + cmd)
        if cmd == '':
            c.close()
            return 0


def recv(c):
    while True:
        data = c.recv(1024)
        print('\033[92mrecv: \033[00m', data)
        if not data:
            print('botnet disconnected...')
            c.close()
            return 0


def server():
    host = ""
    port = 12345
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(5)

    print("Server is listening...")

    while True:
        s.settimeout(10)
        c, addr = s.accept()
        print('Connected to ' + str(addr[0]) + ':' + str(addr[1]))

        sendThread = threading.Thread(target=send, args=(c,))
        recvThread = threading.Thread(target=recv, args=(c,))
        sendThread.start()
        recvThread.start()
        recvThread.join()
        break

    s.close()


if __name__ == '__main__':
    server()
