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

## Illustration
### User
On Firefox, navigate to `https://imovies.ch`. You will see the following: 
![](images/client_1.png)
Simply Click on `Advanced > Accept the Risk and Continue`.
![](images/client_2.png)

Afterwards you will see the login prompt of iMovies.
Since no user currently issued a certificate for their account, you need to login via passwords.
![](images/client_4.png)

Once you successfully logged in, you will land on the `Home` page of the respective account.
You can download the certificate revocation list by clicking on `Download Certificate Revocation List`.
![](images/client_27.png)

Navigate to `Profile`.
![](images/client_6.png)

You can issue a certificate by clicking on `Download`. Note that a passphrase must be given to issue a certificate. Optionally, you can modify the first and last name of the user.
![](images/client_8.png)

At the bottom of the `Profile` page you can see the issued and revoked certificates of the user.
![](images/client_9.png)

To change the password of the user, you must enter the old and the new password and click on `Save`.
![](images/client_10.png)

To perform certificate-based login, first log out to land on the home page of iMovies. On Firefox, click on the `Menu` button (3 stripes). Navigate to `Settings`.
![](images/client_13.png)

Type in the search bar 'cert'. You should immediately see the `Certificates` section.
![](images/client_14.png)
![](images/client_15.png)

Click on `View Certificates`.
![](images/client_16.png)

Click on `Your Certificates`.
![](images/client_17.png)

Click on `Import` and select your downloaded `.p12` certificate for the user.
![](images/client_18.png)

Enter the passphrase for the certificate.
![](images/client_20.png)

You will see the following when you successfully added the certificate to Firefox.
![](images/client_21.png)

When reloading the page, you will see the following message. Just to be sure, uncheck the `Remember this decision` when working with several users.
![](images/client_22.png)

You will see that you can click on `Log in using certificate` to perform a certificate-based login.
![](images/client_23.png)

To revoke a certificate, navigate to `Profile` and check the `Revoke?` box for the respective certificate. Then click on `Revoke selected`.
![](images/client_24.png)

You will see the following if a certificate is revoked.
![](images/client_26.png)

### CA Admin
Before navigating to `https://imovies.ch`, add the admin certificate (located in the Desktop folder) to Firefox as shown before. The CA admin can only log in via this certificate. Afterwards, when visiting   `https://imovies.ch` you will see the following message.
![](images/admin_1.png)

The `Profile` page looks slightly different for the CA admin. The CA admin can only renew its certificate by giving a passphrase for the new certificate. WARNING: The newly generated certificated cannot be downloaded from the browser due to security reasons. Once you renew the certificate, you will be logged out of the admin account. The new certificate can only be exchanged out-of-band with the system admins. 
![](images/admin_2.png)

The `Administration` page shows a dedicated administration panel, where a CA admin can
view the number of issued certificates, the number of revoked certificates,
the current serial number, and the status of the backup server. Furthermore, they can view a list of all the users (represented by their user ID, first name, last name and email address) and issue or revoke their certificates.
![](images/admin_3.png)

Note that when a CA admin attempts to renew the password of a normal user, the CA admin is only required to type in the new password.
![](images/admin_4.png)

## *Have fun!*
