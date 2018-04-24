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


    content_type_whitelist = []

    rule_type = "sqli-main"
    match_with = ""

    options = 0xF1

   
    def scan_main(self,luna_scan,luna_report,scan_type,urlencode_type):                                                        #user_define
        #exp = "err_sqli"
        #module = __import__("exp.sql."+exp,{},{},list(exp))
        #exp_obj = getattr(module, exp)()
        #errsqli_vul = exp_obj.scan(luna_scan,luna_report)
        #if errsqli_vul:
            #return True

        exp = "timebased_sqli"
        module = __import__("exp.sql."+exp,{},{},list(exp))
        exp_obj = getattr(module, exp)()
        errsqli_vul = exp_obj.scan(luna_scan,luna_report)
        if errsqli_vul:
            return True

        return False


