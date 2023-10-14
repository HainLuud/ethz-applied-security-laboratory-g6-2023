'''
Certificate Authority
Authors: 
- Patrick Aldover (paldover@student.ethz.ch)
- Damiano Amatruda (damatruda@student.ethz.ch)
- Alessandro Cabodi (acabodi@student.ethz.ch)
- Hain Luud (haluud@student.ethz.ch)
'''

import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, BestAvailableEncryption, load_pem_private_key
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import datetime
from os import urandom, path, makedirs, listdir
from logger import Logger
from rfc5424logging import Rfc5424SysLogHandler
from user import User
from OpenSSL.crypto import PKCS12, FILETYPE_PEM, load_certificate, load_privatekey 

# public constants
PEM = Encoding.PEM
PKCS8 = PrivateFormat.PKCS8
SubjectPublicKeyInfo = PublicFormat.SubjectPublicKeyInfo
TraditionalOpenSSL = PrivateFormat.TraditionalOpenSSL

class CA:
    # cryptography
    EXPONENT = 65537
    BITS = 2048

    # hard-coded file paths
    root_certificate_path = '/etc/certs/root.imovies.ch.crt'
    #pub_key_path = '/etc/certs/pub.pem'
    priv_key_path = '/etc/certs/root.imovies.ch.key'
    serial_id_path = '/app/data/ca/serial_id.txt'
    crl_path = '/app/data/ca/crl.pem'

    def __init__(self):
        # TODO: DELETE
        #self.test_logger()
        #------------------------------------
        self.create_directories()
        self.logger = Logger()
        self.revocation_list = []
        self.serial_id = self.get_initial_serial_id()
        self.private_key_password = urandom(64) # TODO: how to store passphrase securely
        #self.create_keypair()
        #self.generate_root_certificate(
        self.read_cert()
        self.create_crl()

    def test_logger(self):
        import logging
        import logging.handlers

        my_logger = logging.getLogger()
        my_logger.setLevel(logging.INFO)

        handler = Rfc5424SysLogHandler(
            address=('log.imovies.ch', 6514),
            facility=1,
            socktype=socket.SOCK_STREAM,
            tls_enable=True,
            tls_verify=True,
            tls_ca_bundle='/etc/certs/root.imovies.ch.crt'
        )
        print("PRINT")

        my_logger.addHandler(handler)

        my_logger.info('this is info')
        my_logger.debug('this is debug')
        my_logger.critical('this is critical')

        
    '''
    Creates directories on startup in case they do not exist.
    '''
    def create_directories(self):
        directories = ['./data', './data/ca', './data/clients', './data/clients/admin']
        for directory in directories:
            if not path.exists(directory): 
                makedirs(directory) 

    '''
    Returns the initial serial id.
    '''
    def get_initial_serial_id(self):
        if not path.exists(self.serial_id_path):
            return 1 #x509.random_serial_number() 
        else:
            serial_id = self.load(self.serial_id_path, 'r')
            return int(serial_id)
    
    '''
    Updates serial id.
    '''
    def update_serial_id(self):
        self.serial_id += 1
        self.store(self.serial_id_path, 'w+', str(self.serial_id))
    
    '''
    Generates a new key pair for the CA.
    '''
    def create_keypair(self):
        self.logger.debug("Generating new key pair ...")
        private_key = rsa.generate_private_key(public_exponent=self.EXPONENT, key_size=self.BITS)

        encrypted_pem_private_key = private_key.private_bytes(encoding=PEM, format=PKCS8,
                                                              encryption_algorithm=BestAvailableEncryption(self.private_key_password))
        pem_public_key = private_key.public_key().public_bytes(encoding=PEM, format=SubjectPublicKeyInfo)
        
        #self.logger.debug(encrypted_pem_private_key.decode())
        #self.logger.debug(pem_public_key.decode())
        self.logger.success("Generated new key pair!")

        # write serialised keys to files
        self.store(self.priv_key_path, 'wb+', encrypted_pem_private_key)
        #self.store(self.pub_key_path, 'wb+', pem_public_key)
    
    '''
    Loads the private key of the CA from the file.
    '''
    def load_encrypted_private_key(self):
        # Read the encrypted private key from the file
        encrypted_pem_private_key = self.load(self.priv_key_path, 'rb')
        
        # Deserialize and decrypt the private key
        private_key = load_pem_private_key(data=encrypted_pem_private_key, password=None, backend=default_backend())
        return private_key

    def read_cert(self):
        self.root_cert_pem = self.load(self.root_certificate_path, 'rb')
        self.root_cert = x509.load_pem_x509_certificate(self.root_cert_pem, default_backend())
        
    '''
    Generates the root certificate.
    '''
    def generate_root_certificate(self):
        
        # Check if the root certificate already exists
        if path.exists(self.root_certificate_path):
            self.logger.debug("Root certificate already exists. Loading it.")

            self.root_cert_pem = self.load(self.root_certificate_path, "rb")
            self.root_cert = x509.load_pem_x509_certificate(self.root_cert_pem, default_backend())
            return


        self.logger.debug("Generating new certificate ...")
        self.root_subject = self.root_issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Zurich"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Zentrum"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"iMovies"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"root.imovies.ch"),
        ])
    
        private_key = self.load_encrypted_private_key()

        basic_constraints = x509.BasicConstraints(ca=True, path_length=1)
        key_usage = x509.KeyUsage(key_cert_sign=True, crl_sign=True, digital_signature=False,
                                  content_commitment=False, key_encipherment=False,
                                  data_encipherment=False, key_agreement=False,
                                  encipher_only=False, decipher_only=False)
        subject_key_id = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())

        self.root_cert = x509.CertificateBuilder().subject_name(self.root_subject) \
                                             .issuer_name(self.root_issuer) \
                                             .public_key(private_key.public_key()) \
                                             .serial_number(self.serial_id) \
                                             .not_valid_before(datetime.datetime.utcnow()) \
                                             .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)) \
                                             .add_extension(basic_constraints, critical=True,) \
                                             .add_extension(key_usage, critical=True) \
                                             .add_extension(subject_key_id, critical=False) \
                                             .sign(private_key, hashes.SHA256())
        self.root_cert_pem = self.root_cert.public_bytes(encoding=PEM)
        #self.logger.debug(self.root_cert_pem.decode())
        self.logger.debug("Generated new certificate!")
        
        self.store(self.root_certificate_path, 'wb+', self.root_cert_pem)
            
        self.update_serial_id()
    
    '''
    Issues a new certificate for a user.
    ----------
    user : User
        The user.
    passphrase : bytes | None
        The passphrase to export the PKCS12 file.
    '''
    def issue_certificate(self, user: User, passphrase: bytes | None, revoke=False):
        # revoke old certificates
        if revoke:
            certs = self.user_certificates(user.uid)
            serial_id_list = []
            for cert in certs:
                if not cert['revoked']:
                    serial_id_list.append(cert['serial_id'])
            self.revoke_certificate(user.uid, serial_id_list, x509.ReasonFlags.affiliation_changed)
        
        self.logger.debug("Generating new client key pair ...")
        # create user key pair 
        client_private_key = rsa.generate_private_key(public_exponent=self.EXPONENT, key_size=self.BITS, )

        pem_client_private_key = client_private_key.private_bytes(encoding=PEM, format=TraditionalOpenSSL,
                                                                  encryption_algorithm=NoEncryption()) # PKCS12 already uses passphrase
        self.logger.success("Generated new client key pair!")
        self.logger.debug("Generating new client certificate ...")
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Zurich"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Zentrum"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"iMovies"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"iMovies"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{user.uid}.imovies.ch"), 
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, user.email),
            x509.NameAttribute(NameOID.SURNAME, user.lastname or ''),
            x509.NameAttribute(NameOID.GIVEN_NAME, user.firstname or ''),
        ])
        
        # generate certificate
        basic_constraints = x509.BasicConstraints(ca=False, path_length=None)
        key_usage = x509.KeyUsage(key_cert_sign=False,
                                  crl_sign=False,
                                  digital_signature=True,
                                  content_commitment=True,  # non repudiation
                                  key_encipherment=True,
                                  data_encipherment=False,
                                  key_agreement=False,
                                  encipher_only=False,
                                  decipher_only=False)

        private_key = self.load_encrypted_private_key()
        subject_key_id = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
        cert = x509.CertificateBuilder().subject_name(subject) \
                                        .issuer_name(self.root_cert.issuer) \
                                        .public_key(client_private_key.public_key()) \
                                        .serial_number(self.serial_id) \
                                        .not_valid_before(datetime.datetime.utcnow()) \
                                        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)) \
                                        .add_extension(basic_constraints, critical=False,) \
                                        .add_extension(key_usage, critical=False) \
                                        .add_extension(subject_key_id, critical=False) \
                                        .sign(private_key, hashes.SHA256())
        
        cert_pem = cert.public_bytes(PEM)
        
        client_directory = f'./data/clients/{user.uid}'
        
        if not path.exists(client_directory): 
            makedirs(client_directory)
        
        self.store(f'{client_directory}/{self.serial_id}_cert.pem', "wb+", cert.public_bytes(encoding=PEM))
        self.update_serial_id()
        
        # TODO: why is downloaded cert corrupted!
        pkcs12 = PKCS12()
        pkcs12.set_certificate(load_certificate(type=FILETYPE_PEM, buffer=cert_pem))
        pkcs12.set_privatekey(load_privatekey(type=FILETYPE_PEM, buffer=pem_client_private_key))
        pkcs12.set_ca_certificates([load_certificate(type=FILETYPE_PEM, buffer=self.root_cert_pem)])
        client_cert = pkcs12.export(passphrase=passphrase)

        self.logger.success("Generated new client certificate ...")
        
        return client_cert
    
    '''
    Returns a list of certificate information of a user.
    ----------
    uid : str
        The user id.
    '''
    def user_certificates(self, uid : str):
        try:
            # load certificate revocation list
            crl_data = self.load(self.crl_path, "rb")
            crl = x509.load_pem_x509_crl(crl_data)

            client_directory = f'./data/clients/{uid}'
            files = listdir(client_directory)
            certs = []
            for file in files:
                cert_pem = self.load(f'{client_directory}/{file}', 'rb')
                cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

                serial_id = cert.serial_number

                # check if certificate is revoked
                revoked_cert = crl.get_revoked_certificate_by_serial_number(serial_id)
                revoked = isinstance(revoked_cert, x509.RevokedCertificate)

                cert_json = {
                    'serial_id': serial_id,
                    'firstname': cert.subject.get_attributes_for_oid(NameOID.GIVEN_NAME)[0].value,
                    'lastname': cert.subject.get_attributes_for_oid(NameOID.SURNAME)[0].value,
                    'email': cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value,
                    'commonname': cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                    'notvalidbefore': cert.not_valid_before,
                    'notvalidafter': cert.not_valid_after,
                    'revoked': revoked
                }
                certs.append(cert_json)

            def extract_datetime(json):
                try:
                    return json['notvalidafter'].timestamp()
                except KeyError:
                    return 0

            certs.sort(key=extract_datetime, reverse=True)
            return certs
        except FileNotFoundError:
            return []
    
    '''
    Returns a certificate of a user based on the serial id.
    ----------
    uid : str
        The user id.
    serial_id : int
        The serial id of the certificate
    '''
    def get_certificate_by_serial_id(self, uid : str, serial_id : int):
        try:
            # load certificate revocation list
            crl_data = self.load(self.crl_path, "rb")
            crl = x509.load_pem_x509_crl(crl_data)

            cert_path = f'./data/clients/{uid}/{serial_id}_cert.pem'
            
            cert_pem = self.load(cert_path, 'rb')
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            
            # check if certificate is revoked
            revoked_cert = crl.get_revoked_certificate_by_serial_number(serial_id)
            revoked = isinstance(revoked_cert, x509.RevokedCertificate)
            cert_json = {
                'serial_id': serial_id,
                'firstname': cert.subject.get_attributes_for_oid(NameOID.GIVEN_NAME)[0].value,
                'lastname': cert.subject.get_attributes_for_oid(NameOID.SURNAME)[0].value,
                'email': cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value,
                'commonname': cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                'notvalidbefore': cert.not_valid_before,
                'notvalidafter': cert.not_valid_after,
                'revoked': revoked
            }
            return cert_json
        except FileNotFoundError:
            raise FileNotFoundError(f'Certificate with the serial id {serial_id} does not exist.')

    '''
    Generates a certificate revocation list.
    '''
    def create_crl(self):

        if path.exists(self.crl_path):
            self.logger.debug("Create  already exists. Loading it.")
            return
        
        t_now = datetime.datetime.utcnow()
        t_update = t_now + datetime.timedelta(hours=24)

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.root_cert.subject)
        builder = builder.last_update(t_now)
        builder = builder.next_update(t_update)

        private_key = self.load_encrypted_private_key()
        crl = builder.sign(private_key=private_key, algorithm=hashes.SHA256())
        
        self.store(self.crl_path, "wb", crl.public_bytes(encoding=PEM))

    def get_crl(self):
        crl_data = self.load(self.crl_path, "rb")
        return crl_data

    '''
    Revokes a certificate.
    ----------
    uid : str
        The user id.
    serial_id_list : list
        The list of certificate serial ids to revoke.
    reason : str
        The reason for revocation.
    '''
    def revoke_certificate(self, uid : str, serial_id_list : list, reason : str):
        # load certificate revocation list
        crl_data = self.load(self.crl_path, "rb")
        crl = x509.load_pem_x509_crl(crl_data)

        # Create a new CRL that includes the revoked certificate
        t_now = datetime.datetime.utcnow()
        t_update = t_now + datetime.timedelta(hours=24)
        crl_builder = x509.CertificateRevocationListBuilder().issuer_name(self.root_cert.subject) \
                                                        .last_update(t_now) \
                                                        .next_update(t_update)
        
        for entry in crl:
            crl_builder = crl_builder.add_revoked_certificate(entry)

        
        for serial_id in serial_id_list:
            try:
                # load user certificate
                user_cert_file = f"./data/clients/{uid}/{serial_id}_cert.pem"
                user_cert_data = self.load(user_cert_file, "rb")
                user_cert = x509.load_pem_x509_certificate(user_cert_data)
                try:
                    reason_flag = x509.ReasonFlags[reason.lower()]
                except Exception:
                    reason_flag = x509.ReasonFlags.unspecified

                revoked = crl.get_revoked_certificate_by_serial_number(serial_id)
                
                if not isinstance(revoked, x509.RevokedCertificate):
                    # Create a revoked certificate entry
                    revoked_cert = x509.RevokedCertificateBuilder().serial_number(user_cert.serial_number) \
                                                                .revocation_date(t_now) \
                                                                .add_extension(x509.CRLReason(reason_flag), critical=False) \
                                                                .build(default_backend())

                    crl_builder = crl_builder.add_revoked_certificate(revoked_cert)
                else:
                    raise FileExistsError(f'Certificate with serial id {serial_id} has already been revoked.')
            except FileNotFoundError:
                raise FileNotFoundError(f'Certificate with serial id {serial_id} does not exist.')
            # errors should not happen if web server is implemented correctly 
        private_key = self.load_encrypted_private_key()
        new_crl = crl_builder.sign(private_key=private_key, algorithm=hashes.SHA256())

        self.store(self.crl_path, "wb", new_crl.public_bytes(encoding=PEM))

    def renew_admin_certificate(self, user: User, passphrase: bytes | None):
        if user.uid != 'admin':
            raise Exception('You don\'t have admin permission')
        self.issue_certificate(user=user, passphrase=passphrase, revoke=True)
        # don't return admin certificate

    '''
    Returns the number of issued certificates, revoked certificates, and the current serial id. 
    '''
    def get_status(self):
        n_issued = self.serial_id - 1 # since we start at 1

        crl_data = self.load(self.crl_path, "rb")
        crl = x509.load_pem_x509_crl(crl_data)

        n_revoked = len(crl)

        return n_issued, n_revoked, self.serial_id
    
    #------------helper methods------------

    def store(self, path, mode, content):
        with open(path, mode) as f:
            f.write(content)
    
    def load(self, path, mode):
        with open(path, mode) as f:
            content = f.read()
            return content