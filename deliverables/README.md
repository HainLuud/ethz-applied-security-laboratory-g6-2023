# Project of Applied Security Laboratory

Project of Applied Security Laboratory, ETH Zürich, Prof. David Basin, Fall Semester 2023.

## Team

- Damiano Amatruda (<damatruda@student.ethz.ch>)
- Patrick Aldover (<paldover@student.ethz.ch>)
- Alessandro Cabodi (<acabodi@student.ethz.ch>)
- Hain Luud (<haluud@student.ethz.ch>)

## System Users

### System Credentials

| Machine | Username | Password |
|---|---|---|
| client | user | user |
| client | caadmin | 2iwk97itccGE5F |
| client | sysadmin | RLa3MJZvo4ZwDF |
| web | sysadmin | qZCgxQBVJ6VhL5 |
| db | sysadmin | AhwQ5wnE48h6ai |
| ca | sysadmin | BFwhLd847hD9Rv |
| log | sysadmin | QrA8zRZAnQdKDu |
| bak | sysadmin | z6PNACqyZh6sfs |

### System Administrators

System administrators can SSH into the web server directly:

```bash
ssh sysadmin@imovies.ch
```

And into the other machines through the web server serving as jump host:

```bash
ssh -A -J sysadmin@imovies.ch {machine}.imovies.ch
```

## CA Users

### CA Credentials

| User ID | Password |
|---|---|
| lb | D15Licz6 |
| ps | KramBamBuli |
| ms | MidbSvlJ |
| a3 | Astrid |

### CA Administrators

CA administrators can log in using the certificate stored in their Desktop as `cert.p12`. They can import it into the web browser using the passphrase.

**Certificate passphrase**: s8XFKgP3CORPK9ZWnyqntMK9v9F4oK02

## Tutorial

### Trust the iMovies Web Certificate

Open Mozilla Firefox and navigate to <https://imovies.ch>. You will see a warning:

![Screenshot](images/client_1.png)

Click **Advanced**.

![Screenshot](images/client_2.png)

You can click **View Certificate** to check it. Note that a copy of the root CA certificate is located at `/usr/local/share/ca-certificates/root.imovies.ch.crt`.

Click **Accept the Risk and Continue**. The login page of the iMovies CA will load.

### Log In Using Credentials

Type the user ID and the password.

![Screenshot](images/client_4.png)

After a successful login, you will land on the **Home**.

### Download the Certificate Revocation List

In the **Home**, click **Download Certificate Revocation List**.

![Screenshot](images/client_27.png)

### Issue a Certificate

Navigate to **Profile**.

![Screenshot](images/client_6.png)

To issue a certificate, you must type a passphrase. Optionally, you can modify the first and last name of the user. Click **Download**.

![Screenshot](images/client_8.png)

At the bottom of the **Profile** page you can see the issued and revoked certificates of the user.

![Screenshot](images/client_9.png)

### Change Password

Change the password of the user by entering the old and the new password and clicking **Save**.

![Screenshot](images/client_10.png)

### Add a Certificate

In Firefox, click the **Menu** button (3 bars) and navigate to **Settings**.

![Screenshot](images/client_13.png)

![Screenshot](images/client_14.png)

Type "cert" in the search bar. You should immediately see the **Certificates** section.

![Screenshot](images/client_15.png)

Click **View Certificates**.

![Screenshot](images/client_16.png)

Open **Your Certificates**.

![Screenshot](images/client_17.png)

Click **Import** and select your downloaded **.p12** certificate.

![Screenshot](images/client_18.png)

Enter the passphrase for the certificate.

![Screenshot](images/client_20.png)

Once added, the certificate will appear in the list.

![Screenshot](images/client_21.png)

### Log In Using Certificate

Log out of the account. When loading the login page, Firefox will prompt you to select the certificate to use. You can uncheck **Remember this decision** in order to use several users more easily.

![Screenshot](images/client_22.png)

After selecting a certificate, you will see that you can click **Log in using certificate**. Click it to perform a certificate-based login via TLS Client Authentication.

![Screenshot](images/client_23.png)

### Revoke a Certificate

Navigate to **Profile** and check the **Revoke?** box for the certificates to revoke. Then click **Revoke selected**.

![Screenshot](images/client_24.png)

The certificate will be confirmed as revoked.

![Screenshot](images/client_26.png)

### CA Administrator - Log In

To log in as a CA administrator, you need to add and use the certificate located in their **Desktop** folder.

![Screenshot](images/admin_1.png)

### CA Administrator - Administration Page

Navigate to **Administration**. This page shows the number of issued certificates, the number of revoked certificates, the current serial number and the status of the backup server. Furthermore, it shows a list of all the users (represented by their user ID, first name, last name and email address) and allows to access their profiles and hence issue and revoke their certificates.

![Screenshot](images/admin_3.png)

### CA Administrator - Change Email Address and Password of a User

CA administrators can change the email address of a user and can renew their password by simply typing the new password.

![Screenshot](images/admin_4.png)

### CA Administrator - Renew Certificate

Navigate to **Profile**. The page looks slightly different for a CA administrator.

![Screenshot](images/admin_2.png)

Renew the CA administrator certificate by typing a passphrase for the new certificate. Note that, for security reasons, when you renew the certificate you are automatically logged out of the account and the new certificate is not downloaded. This can only be exchanged out-of-band with the system administrator.

## Source

### Source Structure

| Folder | Description |
|---|---|
| [bak](./bak) | Backup Server |
| [ca](./ca) | Certificate Authority (Core CA) |
| [db](./db) | Database |
| [log](./log) | Log Server |
| [secrets](./secrets) | Global Sensitive Configuration Files |
| [web](./web) | Web Server |

### Run Source in Local Containers

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

### Build Virtual Machines from Source

Run the project in virtual machines using:

```bash
vagrant up
```

This command creates the components as virtual machines for VirtualBox using Vagrant and Ansible.

Access the Web Server from the client virtual machine at <https://imovies.ch>.

## *Have fun!*
