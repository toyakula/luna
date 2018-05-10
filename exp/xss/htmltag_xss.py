import re
import time

import output
import conf.lunaconf
import lunaexp

luna_output = output.output()
luna_conf = conf.lunaconf.lunaconf()

class htmltag_xss(lunaexp.base):

    ruleid = 0x0103
    method = ['GET','POST','COOKIE']
    key_exp = ''
    value_exp = ""
    value_exp_1 = "luna_sta_xss_scan<>luna_end_xss_scan"
    value_exp_2 = "luna_sta_xss_scan&lt;&gt;luna_end_xss_scan"
    rule_type = "refxss-htmltag"

    argv = 0

    match_with = ""

    content_type_whitelist = ["text/javascript","application/x-javascript","application/javascript"]

    options = 0xF1

    def scan_main(self,luna_scan,luna_report,scan_type,urlencode_type):  
        self.value_exp =  self.value_exp_1   
        self.score = 0
        self.match_with = ""

        status,header,body = luna_scan.scan_for_all(self,0,scan_type,urlencode_type)
        if header.has_key('Content-Type'):
            if header['Content-Type'] in self.content_type_whitelist:
                return False,self.match_with

        data = body

        n = body.split("luna_sta_xss_scan")
        if len(n)>=2:
            new_body = n[self.argv+1]
            end = new_body.find("luna_end_xss_scan")
            if end > 0:
                new_body = new_body[:end]  
            else:
                return False,self.match_with
            
            if new_body.find("<") == -1  or new_body.find(">") == -1 :
                self.value_exp =  self.value_exp_2  
                body = luna_scan.scan_for_body(self,0,scan_type,urlencode_type)
                n = body.split("luna_sta_xss_scan")
                if len(n)>=2:
                    new_body = n[self.argv+1]
                    end = new_body.find("luna_end_xss_scan")
                    new_body = new_body[:end] 
                    if new_body.find("<") == -1  or new_body.find(">") == -1 : 
                        return False,self.match_with

                    else:
                        self.match_with += "[Anti Escape]"

        else:
            return False,self.match_with

        self.match_with += "[html_tag]"
        luna_output.vul_xss_output("[","htmltag_xss found","]")
        luna_report.report_http(luna_scan,self)
        return True,self.match_with

