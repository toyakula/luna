import re
import time

import output
import conf.lunaconf
import lunaexp

luna_output = output.output()
luna_conf = conf.lunaconf.lunaconf()

class jsenable_xss(lunaexp.base):

    ruleid = 0x0105
    method = ['GET','POST','COOKIE']
    key_exp = ''
    value_exp = ""
    value_exp_1 = "luna_ref_xss_scan0abcdefghijklmnopqrstuvwxyz"
    value_exp_2_sta = "luna_sta_xss_scan"
    value_exp_2_end = "luna_end_xss_scan"
    rule_type = "refxss-jsenable"

    argv = 0

    match_with = ""

    content_type_whitelist = ["text/javascript","application/x-javascript","application/javascript"]

    c_array = ['<script>','src','src=','href' , 'srcdoc' , 'formaction' ,'onload=' , 'onerror', 'onerror=' , 'onmousemove=', 'onclick', 'ondblclick=', 'onmouseover', 'onfocus','ondblclick+=','onerror+="']

    w_array = [100       , 10  ,30    , 10    , 10       , 10           , 15       ,  15      ,  25        ,  25           ,   10     ,  25          ,  10          ,  10      , 40           , 50         ]
    
    x_array = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

    options = 0xF1

    def scan_main(self,luna_scan,luna_report,scan_type,urlencode_type):  
        self.value_exp =  self.value_exp_1   
        self.score = 0
        self.match_with = ""

        status,header,body = luna_scan.scan_for_all(self,0,scan_type,urlencode_type)
        if 'Content-Type' in header:
            if header['Content-Type'] in self.content_type_whitelist:
                return False,self.match_with

        n = body.split("luna_ref_xss_scan")
        if n[self.argv+1]:
            if n[self.argv+1][0] == "0" or n[self.argv+1][0] == "a":

                count = 18
                for i,chars in enumerate(n[self.argv+1]):
                    if i+96 == ord(chars) or i+97 == ord(chars):
                        count+=1


                for i,c in enumerate(self.c_array):
                    self.value_exp = self.value_exp_2_sta+c+self.value_exp_2_end
                    body = luna_scan.scan_for_body(self,0,scan_type,urlencode_type)
                    n = body.split("luna_sta_xss_scan")
                    if len(n)>self.argv+1:
                        new_body = n[self.argv+1]
                    else:
                        return False
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

                    if new_body.find(c)+1:
                        self.x_array[i] = 1
                        self.score += self.x_array[i] * self.w_array[i]


            

                if self.score>100:
                    self.score = 100

                if self.score > 60:
                    self.match_with = "score="+str(self.score)+">60"
                    luna_output.vul_xss_output("[","jsenable_xss found,score:"+str(self.score),"]")
                    luna_report.report_http(luna_scan,self)
                
                    return True
                else:
                    return False
       