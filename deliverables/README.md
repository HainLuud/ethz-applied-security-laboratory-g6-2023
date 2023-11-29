# Project of Applied Security Laboratory

Project of Applied Security Laboratory, ETH Zürich, Prof. David Basin, Fall Semester 2023.

## Team

- Damiano Amatruda (<damatruda@student.ethz.ch>)
- Patrick Aldover (<paldover@student.ethz.ch>)
- Alessandro Cabodi (<acabodi@student.ethz.ch>)
- Hain Luud (<haluud@student.ethz.ch>)

## Deliverable Structure

| Folder | Description |
|---|---|
| [bak](./bak) | Backup Server |
| [ca](./ca) | Certificate Authority (Core CA) |
| [db](./db) | Database |
| [log](./log) | Log Server |
| [secrets](./secrets) | Global Sensitive Configuration Files |
| [web](./web) | Web Server |

## Machine Credentials

| Machine | Username | Password |
|---|---|---|
| client | user | user |
| client | caadmin | 9bc4c5be88de75a18457c498f16a70f7881ab58ca770c449acd8f3a861e71d7e |
| client | sysadmin | c6b8ec87a9e5d073926b04d1de191041edbf88ead01b585aa944540fb506557f |
| web | sysadmin | d1d754db6afb6aba5c4460819a70f616f4aadcf93e2bc8750cb4f057aac7481a |
| db | sysadmin | 9da452e63f31d93718b9b327e0245d81cd704574b39a22fa3b0c1a0b79c2fc6c |
| ca | sysadmin | 650f489809a133ffb8714c81a7fdfb311bea40a4bf628f015b72290ef516b73f |
| log | sysadmin | 47e21d4a0294d12af1e485f6567c05782a00140933d684014e01e6bdfd8c7ae4 |
| bak | sysadmin | 4448f21ecc9c97757452d4d7bcf4fdc1cb24662b3d474a3ff4d7ba9d5487ac69 |

## CA Credentials

| User ID | Password |
|---|---|
| lb | D15Licz6 |
| ps | KramBamBuli |
| ms | MidbSvlJ |
| a3 | Astrid |

## System Maintenance

System administrators can SSH directly into the web server:

```bash
ssh sysadmin@imovies.ch
```

And indirectly into the other machines through the web server, serving as jump host:

```bash
ssh -A -J sysadmin@imovies.ch {machine}.imovies.ch
```

## Certificate Management

CA administrators can log in using the certificate stored in their Desktop as `cert.p12`. They can import it into the web browser using the passphrase: s8XFKgP3CORPK9ZWnyqntMK9v9F4oK02.

## Run in Local Containers

Run the project in local containers using:

```bash
docker compose up --build -d
```

This command creates the components as containers using Docker, facilitating rapid debugging.

Access the components from your local machine at the following URLs:

| Service | URL |
|---|---|
| Web Server | <https://127.0.0.1:8000> |
| CA | <https://127.0.0.1:8001> |
| Database Server | mysql://127.0.0.1:3306 |
| Log Server | syslog://127.0.0.1:6514 |
| Backup Server | <https://127.0.0.1:8002> |

## Build VMs from Source

Run the project in virtual machines using:

```bash
vagrant up
```

This command creates the components as virtual machines for VirtualBox using Vagrant and Ansible.

Access the Web Server from the client virtual machine at <https://imovies.ch>.

## *Have fun!*
