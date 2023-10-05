'''
Logger (Remove once log server exists)
Authors: Patrick Louis Aldover
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