import re
import time

import output
import conf.lunaconf
import lunaexp

luna_output = output.output()
luna_conf = conf.lunaconf.lunaconf()

class injs_xss(lunaexp.base):

    ruleid = 0x0102
    method = ['GET','POST','COOKIE']
    key_exp = ''
    value_exp = ""
    value_exp_1 = "luna_ref_xss_scan0abcdefghijklmnopqrstuvwxyz"
    value_exp_2 = "luna_sta_xss_scan'\"{}[]();/luna_end_xss_scan"
    rule_type = "refxss-injs"

    argv = 0

    score = 0
    match_with = ""

    content_type_whitelist = ["text/javascript","application/x-javascript","application/javascript"]


    c_array = ["'",'"','{','}','[',']','(',')',';','/']

    w_array = [30,30,3,6,2,4,5,10,4,6]                                             #'"{}[]();/

    x_array = [0,0,0,0,0,0,0,0,0,0]

    options = 0xF1

    def scan_main(self,luna_scan,luna_report,scan_type,urlencode_type):  
        self.value_exp =  self.value_exp_1   
        self.score = 0
        self.match_with = ""

        status,header,body = luna_scan.scan_for_all(self,0,scan_type,urlencode_type)
        if header.has_key('Content-Type'):
            if header['Content-Type'] in self.content_type_whitelist:
                return False
        data = body

        n = body.split("luna_ref_xss_scan")
        if len(n)>=2:
            if n[self.argv+1][0] == "0" or n[self.argv+1][0] == "a":

                count = 18
                for i,chars in enumerate(n[self.argv+1]):
                    if i+96 == ord(chars) or i+97 == ord(chars):
                        count+=1


                self.value_exp = self.value_exp_2
                body = luna_scan.scan_for_body(self,0,scan_type,urlencode_type)
                n = body.split("luna_sta_xss_scan")
                new_body = n[self.argv+1]
                if count>43:


                    end = new_body.find("luna_end_xss_scan")
                    new_body = new_body[:end]
                    self.score += 15                                                        # 43 => 15

                elif count>27:
                    
                    end = new_body.find("l")
                    new_body = new_body[:end]
                    self.score += 5                                                         # 27 => 5

                else :
                    pass





            for i,c in enumerate(self.c_array):
                if new_body.find(c)+1:
                    self.x_array[i] = 1
                    self.score += self.x_array[i] * self.w_array[i]

            if self.score>100:
                self.score = 100

            if self.score > 60:
                self.match_with = "score="+str(self.score)+">60"
                luna_output.vul_xss_output("[","injs_xss found,score:"+str(self.score),"]")
                luna_report.report_http(luna_scan,self)
            
                return True
            else:
                return False
       

