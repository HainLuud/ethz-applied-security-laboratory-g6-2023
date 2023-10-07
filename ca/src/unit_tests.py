'''
Certificate Authority - Unit tests
Authors: 
- Patrick Aldover (paldover@student.ethz.ch)
- Damiano Amatruda (damatruda@student.ethz.ch)
- Alessandro Cabodi (acabodi@student.ethz.ch)
- Hain Luud (haluud@student.ethz.ch)
'''
import unittest, json

from ca import CA
from user import User
from ca_api import app, ca

# Note: disable either test or test_api
class TestCA(unittest.TestCase):
    ca = ca
    app.testing = True
    client = app.test_client()
    passphrase = b'Hello'
    
    @unittest.skip("Local")
    def test_basic(self):
        user = User(32, 'Aldover', 'Patrick Louis', 'paldover@student.ethz.ch')
        
        self.assertEqual(self.ca.get_status(), (1, 0, 2))
        
        self.ca.issue_certificate(user, self.passphrase)
        self.assertEqual(self.ca.get_status(), (2, 0, 3))

        self.ca.revoke_certificate(user.uid, [2], "key_compromise")
        self.assertEqual(self.ca.get_status(), (2, 1, 3))

    @unittest.skip("Local")
    def test_advanced(self):
        with self.assertRaises(FileNotFoundError):
            self.ca.revoke_certificate([3, 4], "key_compromise")
        self.assertEqual(self.ca.get_status(), (2, 1, 3))

        user = User(33, 'Cabodi', 'Alessandro', 'acabodi@student.ethz.ch')
        self.ca.issue_certificate(user, self.passphrase)
        self.assertEqual(self.ca.get_status(), (3, 1, 4))

        self.ca.issue_certificate(user, self.passphrase)
        self.assertEqual(self.ca.get_status(), (4, 1, 5))

        self.ca.issue_certificate(user, self.passphrase)
        self.assertEqual(self.ca.get_status(), (5, 1, 6))
        
        self.ca.revoke_certificate(user.uid, [3, 4], "key_compromise")
        self.assertEqual(self.ca.get_status(), (5, 3, 6))

        with self.assertRaises(FileExistsError):
            self.ca.revoke_certificate(32, [2], "key_compromise")
        self.assertEqual(self.ca.get_status(), (5, 3, 6))

    # @unittest.skip("Remote")
    def test_api_basic(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'Welcome to the CA interface')

    # @unittest.skip("Remote")
    def test_api_advanced(self):
        payload = {'uid': 1, 'lastname': 'Max', 'firstname': 'Mustermann', 'email': 'max.mustermann@student.ethz.ch', 'passphrase': '12345'}
        
        response = self.client.post('/issue_certificate', json=payload)
        self.assertEqual(response.status_code, 200)

        response = self.client.post('/issue_certificate', json=payload)
        self.assertEqual(response.status_code, 200)

        response = self.client.post('/issue_certificate', json=payload)
        self.assertEqual(response.status_code, 200)

        response = self.client.get(f'/user_certificates/{payload["uid"]}')
        print(response.data)

        payload = {'uid': payload['uid'], 'serial_id_list': [2], 'reason': 'unspecified'}
        response = self.client.post('/revoke_certificate', json=payload)
        self.assertEqual(response.status_code, 200)

        response = self.client.get('/ca_status')
        self.assertEqual(response.status_code, 200)

        response_string = response.data.decode().split('\n')[0]
        response_json = json.loads(response_string)
        # self.assertEqual(response_json['n_issued'], 2)
        # self.assertEqual(response_json['n_revoked'], 1)
        # self.assertEqual(response_json['next_serial_id'], 3)

if __name__ == '__main__':
    unittest.main()