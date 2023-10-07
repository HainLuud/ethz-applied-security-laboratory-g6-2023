'''
Logger (Remove once log server exists)
Authors: 
- Patrick Aldover (paldover@student.ethz.ch)
- Damiano Amatruda (damatruda@student.ethz.ch)
- Alessandro Cabodi (acabodi@student.ethz.ch)
- Hain Luud (haluud@student.ethz.ch)
'''
class Logger:
    def __init__(self):
        pass
    
    def warning(self, message):
        print('\033[93m', message, '\033[0m')
    
    def error(self, message):
        print('\033[91m', message, '\033[0m')
    
    def debug(self, message):
        print('\033[96m', message, '\033[0m')

    def success(self, message):
        print('\033[92m', message, '\033[0m')