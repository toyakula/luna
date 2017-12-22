import lunafile
import output
import parasehttp
import lunaexploit
import lunascan
import lunareport
import prescan
import sqlite
import conf.lunaconf
import lunaargvs
import lunalog

import sys
import time

luna_conf = conf.lunaconf.lunaconf()
luna_log = lunalog.lunalog(luna_conf.log_file)
luna_output = output.output()
luna_prescan = prescan.prescan()
luna_exp = lunaexploit.lunaexploit()
luna_sqlite = sqlite.sqlite()
luna_file = lunafile.filecontroller(luna_conf.http_log)
luna_argvs = lunaargvs.lunaargvs()
luna_exploit = lunaexploit.lunaexploit()

def luna():

    luna_argvs.handle_argvs()

    if luna_argvs.newsqlite == True:
        luna_sqlite.create()


    if len(luna_argvs.flush_session_host) != 0 :
            luna_sqlite.flush_session_cgi(luna_argvs.flush_session_host) 

    for host,port in luna_conf.host_port:
        ctn,mark,count = luna_file.readfile(header=1)
        if host == '*':
            luna_file.filterall(port)                

        else:
            luna_file.filter(host,port)

        luna_file.remap()
        

        for host_port in luna_file.host_portlist:
            luna_sqlite.hostid = luna_sqlite.insert_host(host_port[0],host_port[1])
            luna_report = lunareport.lunareport(host_port[0],host_port[1])
            ctn,mark,count = luna_file.readfile()
            
            if ctn:
                continue

            #luna_prescan.prescan(luna_file,luna_report,host_port)

            luna_exploit.adjust()
            luna_exploit.exploit(luna_file,luna_sqlite,luna_report,host_port,luna_output,luna_conf)
    


    

        
if __name__ == '__main__':
    luna()
