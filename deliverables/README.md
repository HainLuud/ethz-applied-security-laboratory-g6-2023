# Project of Applied Security Laboratory

Project of Applied Security Laboratory, ETH Zürich, Prof. David Basin, Fall Semester 2023.

## Team

- Damiano Amatruda (<damatruda@student.ethz.ch>)
- Patrick Aldover (<paldover@student.ethz.ch>)
- Alessandro Cabodi (<acabodi@student.ethz.ch>)
- Hain Luud (<haluud@student.ethz.ch>)

## Project Structure

| Folder | Description |
|---|---|
| [backdoor](./backdoor) | Backdoor Script |
| [bak](./bak) | Backup Server |
| [ca](./ca) | Certificate Authority (Core CA) |
| [db](./db) | Database |
| [log](./log) | Log Server |
| [obfuscator](./obfuscator) | Obfuscators |
| [scripts](./scripts) | Build Scripts (for GNU Make targets) |
| [secrets](./secrets) | Global Sensitive Configuration Files |
| [web](./web) | Web Server |

## Credentials
```
<machine>   <username>:<password>
client      vagrant:vagrant
web         vagrant:d1d754db6afb6aba5c4460819a70f616f4aadcf93e2bc8750cb4f057aac7481a
db          vagrant:9da452e63f31d93718b9b327e0245d81cd704574b39a22fa3b0c1a0b79c2fc6c
ca          vagrant:650f489809a133ffb8714c81a7fdfb311bea40a4bf628f015b72290ef516b73f
log         vagrant:47e21d4a0294d12af1e485f6567c05782a00140933d684014e01e6bdfd8c7ae4
bak         vagrant:4448f21ecc9c97757452d4d7bcf4fdc1cb24662b3d474a3ff4d7ba9d5487ac69
```

## System Maintenance
If an admin needs to SSH into the web server they use
`ssh -i secrets/ssh/admin_ssh imovies.ch`

If an admin needs to SSH into any other machine they have to first tunnel from localhost to imovies.ch and from host1 to host2:
`ssh -L 2211:<machine_name>.imovies.ch:22 vagrant@imovies.ch -i secrets/ssh/admin_ssh`
and then in another terminal execute
`ssh -p 2211 vagrant@localhost -i secrets/ssh/admin_ssh`
``


## In case you want to build VMs from source

Build the project and run in virtual machines using:

```bash
vagrant up
```

This command creates the components as virtual machines for VirtualBox using Vagrant and Ansible.

Alternatively, use the following GNU Make target:

```bash
make vagrant
```

Access the Web Server from the client virtual machine at <https://imovies.ch>.

## Run in Local Containers

Run the project in local containers using:

```bash
docker compose up --build --d
```

This command creates the components as containers using Docker, facilitating rapid debugging.

Alternatively, use the following GNU Make target:

```bash
make docker
```

Access the components from your local machine at the following URLs:

| Service | URL |
|---|---|
| Web Server | <https://127.0.0.1:8000> |
| CA | <https://127.0.0.1:8001> |
| Database Server | mysql://127.0.0.1:3306 |
| Log Server | syslog://127.0.0.1:6514 |
| Backup Server | <https://127.0.0.1:8002> |


## Have fun!