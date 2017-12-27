import lunascan
import parasehttp
import conf.lunaconf as lunaconf

import sys
import time
import re 

import httplib

luna_conf = lunaconf.lunaconf()


class prescan(object):
    def __init__(self):
        self.prescan_result = {"waf":0,"waf_type":"null","little_sample":False}
        self.tencent_waf_count = 0
        self.actual_scancount = 0
        self.little_sample = False
        self.pre_scan_count = 0

        self.key_exp = ''
        self.value_exp = ''

        self.raw_scan = False


    def prescan(self,luna_file,luna_report,host_port):
        luna_scan = lunascan.lunascan(host_port[0],host_port[1])
        pre_scan_count = 0
        
        for i,every_body in enumerate(luna_file.bodylist):
            if len(every_body) == 0:
                continue
            luna_parase = parasehttp.parasehttp()
            is_dynamic = luna_parase.parase(luna_file,every_body)
            if is_dynamic == -1:
                continue
            cgi_type = luna_parase.cgi.split('.')[-1]

            if (cgi_type in luna_conf.static_cgi_type):
                continue


            luna_scan.sethttp(luna_parase)
            self.actual_scancount += 1
            luna_scan.pre_scan(self)
                
        

            if self.pre_scan_count >= luna_conf.Max_pre_scan_count:
                break


        self.sum()
        luna_file.dynamic_count = 0
        luna_report.report_prescan(self.prescan_result)

    def scan(self,luna_scan):
        self.waf_test(luna_scan)



    def waf_test(self,luna_scan):
        self.tencent_waf_test(luna_scan)


      

    def tencent_waf_test(self,luna_scan):
        self.value_exp = ' and 1=1'
        iskey = False
        code = luna_scan.scan_for_status(self)
        if code == 501:            
            self.tencent_waf_count += 1




    def sum(self):
        if self.actual_scancount < luna_conf.Max_pre_scan_count:
            self.prescan_result["little_sample"] = True
        if self.tencent_waf_count >= 4:
            self.prescan_result["waf"] = 1
            self.prescan_result["waf_type"] = "Tencent_waf"



