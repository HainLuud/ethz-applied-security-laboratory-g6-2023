'''
User
Authors: 
- Patrick Aldover (paldover@student.ethz.ch)
- Damiano Amatruda (damatruda@student.ethz.ch)
- Alessandro Cabodi (acabodi@student.ethz.ch)
- Hain Luud (haluud@student.ethz.ch)
'''
class User:
    def __init__(self, uid, lastname, firstname, email):
        self.uid = uid
        self.lastname = lastname
        self.firstname = firstname
        self.email = email