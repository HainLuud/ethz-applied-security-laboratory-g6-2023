'''
Certificate Authority
Authors: Patrick Louis Aldover, Alessandro Cabodi
'''
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, BestAvailableEncryption, load_pem_private_key
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import datetime
from os import urandom, path
from logger import Logger
from user import User
from OpenSSL.crypto import PKCS12, FILETYPE_PEM, load_certificate, load_privatekey 

# public constants
PEM = Encoding.PEM
PKCS8 = PrivateFormat.PKCS8
SubjectPublicKeyInfo = PublicFormat.SubjectPublicKeyInfo
TraditionalOpenSSL = PrivateFormat.TraditionalOpenSSL

class CA:
    EXPONENT = 65537
    BITS = 2048

    root_certificate_path = '../data/ca/cert.pem'
    pub_key_path = '../data/ca/pub.pem'
    priv_key_path = '../data/ca/priv.pem'
    serial_id_path = '../data/ca/serial_id.txt'
    crl_path = '../data/ca/crl.pem'

    def __init__(self):
        self.logger = Logger()
        self.revocation_list = []
        self.serial_id = self.get_serial_id()
        self.private_key_password = urandom(64) # TODO: how to store passphrase securely
        self.create_keypair()
        self.generate_root_certificate()
        self.create_crl()

    def get_serial_id(self):
        if not path.exists(self.serial_id_path):
            return 1#x509.random_serial_number() 
        else:
            serial_id = self.load(self.serial_id_path, 'r')
            return int(serial_id)
    
    def update_serial_id(self):
        self.serial_id += 1
        self.store(self.serial_id_path, 'w+', str(self.serial_id))
        
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
        self.store(self.pub_key_path, 'wb+', pem_public_key)
    
    def load_encrypted_private_key(self):
        # Read the encrypted private key from the file
        encrypted_pem_private_key = self.load(self.priv_key_path, 'rb')
        
        # Deserialize and decrypt the private key
        private_key = load_pem_private_key(encrypted_pem_private_key, password=self.private_key_password,)
        return private_key

    def generate_root_certificate(self):
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
    
    # TODO: new certificate: revoke old certificate
    def issue_certificate(self, user: User, passphrase):
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
            x509.NameAttribute(NameOID.COMMON_NAME, f"{user.uid}.imovies.ch"), 
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, user.email),
            x509.NameAttribute(NameOID.SURNAME, user.lastname),
            x509.NameAttribute(NameOID.GIVEN_NAME, user.firstname),
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
                                        .issuer_name(self.root_subject) \
                                        .public_key(client_private_key.public_key()) \
                                        .serial_number(self.serial_id) \
                                        .not_valid_before(datetime.datetime.utcnow()) \
                                        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)) \
                                        .add_extension(basic_constraints, critical=False,) \
                                        .add_extension(key_usage, critical=False) \
                                        .add_extension(subject_key_id, critical=False) \
                                        .sign(private_key, hashes.SHA256())
        
        cert_pem = cert.public_bytes(PEM)
        
        self.store(f'../data/clients/{self.serial_id}_cert.pem', "wb+", cert.public_bytes(encoding=PEM))
        self.update_serial_id()
        
        pkcs12 = PKCS12()
        pkcs12.set_certificate(load_certificate(type=FILETYPE_PEM, buffer=cert_pem))
        pkcs12.set_privatekey(load_privatekey(type=FILETYPE_PEM, buffer=pem_client_private_key))
        pkcs12.set_ca_certificates([load_certificate(type=FILETYPE_PEM, buffer=self.root_cert_pem)])
        client_cert = pkcs12.export(passphrase=passphrase)
        
        self.logger.success("Generated new client certificate ...")

        return client_cert
    
    def create_crl(self):
        t_now = datetime.datetime.utcnow()
        t_update = t_now + datetime.timedelta(hours=24)

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.root_cert.subject)
        builder = builder.last_update(t_now)
        builder = builder.next_update(t_update)

        private_key = self.load_encrypted_private_key()
        crl = builder.sign(private_key=private_key, algorithm=hashes.SHA256())
        
        self.store(self.crl_path, "wb", crl.public_bytes(encoding=PEM))

    def revoke_certificate(self, serial_id_list, reason):
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
                user_cert_file = f"../data/clients/{serial_id}_cert.pem"
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

        private_key = self.load_encrypted_private_key()
        new_crl = crl_builder.sign(private_key=private_key, algorithm=hashes.SHA256())

        self.store(self.crl_path, "wb", new_crl.public_bytes(encoding=PEM))

    
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