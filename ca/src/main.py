from ca import CA
from user import User
from cryptography import x509
def main():
    ca = CA()
    user = User(32, 'Aldover', 'Patrick Louis', 'paldover@student.ethz.ch')
    passphrase = 'Hello'
    print(ca.get_status())
    
    ca.issue_certificate(user, passphrase)
    print(ca.get_status())

    ca.revoke_certificate([2], x509.ReasonFlags.key_compromise)
    print(ca.get_status())

    ca.revoke_certificate([2], x509.ReasonFlags.key_compromise)
    print(ca.get_status())

main()