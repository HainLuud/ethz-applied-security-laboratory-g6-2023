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

## Run in Virtual Machines

Run the project in virtual machines using:

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

## Build OVA Packages

Build the OVA packages using:

```bash
make
```

The packages are stored in the `package` folder.

For enhanced reliability, use:

```bash
make clean all
```

This command cleans up the project before building the OVA packages.

## Compilation and Obfuscation

The OVA packages contain Python code compiled using Cython, with a copy of the executables temporarily stored in the `obfuscate` folder.

Build packages containing non-compiled code using:

```bash
make package
```

Run compiled code in virtual machines:

```bash
make obfuscate-vagrant
```

Or in local containers:

```bash
make obfuscate-docker
```

Obfuscate code using Pyarmor instead of compiling using Cython by setting this environment variable before running any GNU Make target:

```bash
export OBFUSCATOR=pyarmor
```
