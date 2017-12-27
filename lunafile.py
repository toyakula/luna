import output
from conf import lunaconf
import lunalog

import time
import re
import os

luna_conf = lunaconf.lunaconf()
luna_log = lunalog.lunalog(luna_conf.log_file)
luna_output = output.output()

class filecontroller(object):
    def __init__(self, name):
        self.filename = name
        self.filterlist = []
        self.headerlist = []
        self.bodylist = []
        self.host_portlist = []

    def readfile(self,header=0):
        self.bodylist = []
        line_count = 0
        try:
            file = open(self.filename)
        except IOError as e:
            luna_log.log_fatal("Can not open file [%s]." %(self.filename))
            print "Can not open file [%s]." %(self.filename)
            exit(-1)
        count = 0
        boundary = 0

        while True:
                line = file.readline()
                if not line:
                    break
                line = line[:-1]+os.linesep
                if line[:10] == "==========":
                    flag = True
                    hflag = True
                    boundary += 1
                    
                    if boundary == 3:
                        count += 1
                        boundary = 0
                if boundary == 1:
                    if hflag:
                        self.headerlist.append('')
                        hflag = False
                    else:
                        self.headerlist[count]+=line
                if boundary == 2:
                    if flag:
                        self.bodylist.append('')
                        flag = False
                    else:
                        if count in self.filterlist:
                            continue
                        else:
                            self.bodylist[count]+=line

        mark = file.tell()
        file.close()
        ctn = 0
        if len(self.bodylist) ==0:
            ctn= 1

        return ctn,mark,count

                
    def filter(self,host,port):
        if port == '*':
            for i,header in enumerate(self.headerlist):
                m = re.match(r'.*\s*(?:http(?:s?)://)(.*):(\d+)\s*.*',header)
                if not m or not m.group(1) or not m.group(2):
                    luna_log.log_warring("Error burp header in[%s]." %(header))
                else:               
                    if m.group(1) == host:
                        self.host_portlist.append([m.group(1),m.group(2)])  
                    else:
                        self.filterlist.append(i)
        else:
            for i,header in enumerate(self.headerlist):
                m = re.match(r'.*\s*(?:http(?:s?)://)(.*):(\d+)\s*.*',header)
                if not m or not m.group(1) or not m.group(2):
                    luna_log.log_warring("Error burp header in[%s]." %(header))
                else:               
                    if m.group(1) == host and m.group(2)== port:

                        self.host_portlist.append([m.group(1),m.group(2)]) 
                    else: 
                        self.filterlist.append(i)            

    def filterall(self,port):
        if port == '*':
            for i,header in enumerate(self.headerlist):
                m = re.match(r'.*\s*(?:http(?:s?)://)(.*):(\d+)\s*.*',header)
                if not m or not m.group(1) or not m.group(2):
                    luna_log.log_warring("Error burp header in[%s]." %(header))
                else:                
                    self.host_portlist.append([m.group(1),m.group(2)])              
                    self.filterlist = []
        else:
            for i,header in enumerate(self.headerlist):
                m = re.match(r'.*\s*(?:http(?:s?)://)(.*):(\d+)\s*.*',header)
                if not m:
                    luna_log.log_warring("Error burp header in[%s]." %(header))
                else: 
                    if m.group(2) == port or not m.group(1) or not m.group(2):              
                        self.host_portlist.append([m.group(1),m.group(2)])   
                    else:         
                        self.filterlist.append(i)



    def remap(self):
        host_port = []
        for i in self.host_portlist:
            if i in host_port:
                continue
            else:
                host_port.append(i)
        self.host_portlist = host_port
