import os
import time
import sys

class function(object):
    def __init__(self):
        self.time = 1


    def SYSTEM_CLEAN(self):
        if sys.platform == 'win32':
            os.system('cls')
        else:
            os.system('clear')

    def SLEEP(self):
        time.sleep(self.time)
