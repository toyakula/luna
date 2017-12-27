import re
import time

import output
import conf.lunaconf
import lunaexp

luna_output = output.output()
luna_conf = conf.lunaconf.lunaconf()

class utf7_xss(lunaexp.base):

    ruleid = 0x0101
    method = ['GET','POST','COOKIE']
    key_exp = ''
    value_exp = '+/v8'
    rule_type = "refxss-utf7"
    match_with = '+/v8'

    content_type_whitelist = ["text/javascript","application/x-javascript","application/javascript"]

    options = 0xF1

    def scan_main(self,luna_scan,luna_report,scan_type,urlencode_type):                                                        #user_define
        status,header,body = luna_scan.scan_for_all(self,0,scan_type,urlencode_type)
        if 'Content-Type' in header:
            if header['Content-Type'] in self.content_type_whitelist or ( header['Content-Type'].find("charset") != -1 and header['Content-Type'].find("utf-7") == -1):
                return False
        data = body

        m = re.match(r'^\+\/v8',data)

        if m:
            luna_output.vul_xss_output("[","utf7_xss found","]")
            luna_report.report_http(luna_scan,self)
            time.sleep(3)
            return True
        else:
            return False
       

