'''
Certificate Authority
Authors: Patrick Louis Aldover, Alessandro Cabodi
'''
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime
from logger import Logger
import os

private_key_password = b"not-so-secret"

class CA:
    revocation_list = []
    root_certificate_path = '../data/cert.pem'
    pub_key_path = '../data/pub.pem'
    priv_key_path = '../data/priv.pem'
    logger = Logger()

    def __init__(self):
        self.create_keypair()
        self.generate_root_certificate()

    def create_keypair(self):
        self.logger.debug("Generating new key pair ...")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        encrypted_pem_private_key = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                              format=serialization.PrivateFormat.PKCS8,
                                                              encryption_algorithm=serialization.BestAvailableEncryption(private_key_password)) # encryption_algorithm=serialization.NoEncryption()
        pem_public_key = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                               format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.logger.debug(encrypted_pem_private_key)
        self.logger.debug(pem_public_key)
        self.logger.success("Generated new key pair!")

        # write serialised keys to files
        with open(self.priv_key_path, "w+") as f:
            f.write(encrypted_pem_private_key.decode())
            
        with open(self.pub_key_path, "w+") as f:
            f.write(pem_public_key.decode())
    
    def load_encrypted_private_key(self):
        # Read the encrypted private key from the file
        with open(self.priv_key_path, "rb") as f:
            encrypted_pem_private_key = f.read()
        
        
        # Deserialize and decrypt the private key
        private_key = serialization.load_pem_private_key(
            encrypted_pem_private_key,
            password=private_key_password,
        )
        return private_key


    def generate_root_certificate(self):
        self.logger.debug("Generating new certificate ...")
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Zürich"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Zentrum"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"iMovies"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"root@imovies.ch"),
        ])
    
        private_key = self.load_encrypted_private_key()

        basic_contraints = x509.BasicConstraints(ca=True, path_length=1)
        key_usage = x509.KeyUsage(key_cert_sign=True, crl_sign=True, digital_signature=False,
                        content_commitment=False, key_encipherment=False,
                        data_encipherment=False, key_agreement=False,
                        encipher_only=False, decipher_only=False)
        subject_key_id = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())

        root_cert = x509.CertificateBuilder().subject_name(subject) \
                                             .issuer_name(issuer) \
                                             .public_key(private_key.public_key()) \
                                             .serial_number(x509.random_serial_number()) \
                                             .not_valid_before(datetime.datetime.utcnow()) \
                                             .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)) \
                                             .add_extension(basic_contraints, critical=True,) \
                                             .add_extension(key_usage, critical=True) \
                                             .add_extension(subject_key_id, critical=False) \
                                             .sign(private_key, hashes.SHA256())
        root_cert_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        self.logger.debug(root_cert_pem)
        self.logger.debug("Generated new certificate!")
        
        with open(self.root_certificate_path, "w+") as f:
            f.write(root_cert_pem)

    def create_CRL(self):
        pass

    def issue_certificate(self):
        pass

    def verify_certificate(self):
        pass

    def revoke_certificate(self):
        pass
