import sqlite
import time

import sys


class lunaargvs(object):
    def __init__(self):
        self.flush_session = False
        self.newsqlite = False
        self.flush_session_host = []


    def handle_argvs(self):
        for argvs in sys.argv:
            if self.flush_session == True:
                self.flush_session_host = argvs.split(',')
                self.flush_session = False
            if argvs[0] != '-':
                continue
            if argvs[1:] == '-init':   #sqlite new create
                self.newsqlite = True

            if argvs[1:] == '-flush-session':      # host db create
                self.flush_session = True

        