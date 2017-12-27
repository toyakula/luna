from __future__ import print_function
import os

class lunalog(object):
    def __init__(self, log_file):
        self.logfile = log_file

    def log_error(self,level,text):
        try:
            file = open(self.filename,'w+')
        except IOError as e:
            print("Fatal Error: Can not open file [%s]." %(self.filename))       
            exit(-1)
        if level == "warring":
            file.write("Warring Error: %s.%s" %(text,os.linesep))

        if level == "fatal":
            file.write("Fatal Error: %s.%s" %(text,os.linesep))

        if level == "notice":
            file.write("Notice Error: %s.%s" %(text,os.linesep))

        if level == "exp":
            file.write("Exploit Error: %s.%s" %(text,os.linesep))


    def log_warring(self,text):
        self.log_error("warring",text)

    def log_fatal(self,text):
        self.log_error("fatal",text)

    def log_notice(self,text):
        self.log_error("notice",text)

    def log_exp(self,text):
        self.log_error("exp",text)