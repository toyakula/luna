import lunaexp
import output
import conf.lunaconf
import time

class helloworld_exp(lunaexp.base):

    ruleid = 0x0001
    options = 0xA1
    rule_type = "helloworld-test"
    match_with = "'helloworld' was found in the response"
   
    def scan_main(self,luna_scan,luna_report,scan_type,urlencode_type):                                                        #user_define
        
        body=luna_scan.scan_for_body(self,0,scan_type,urlencode_type)
        if body[:10] == 'helloworld':
            print self.method
            time.sleep(5)   
            luna_report.report_http(luna_scan,self)
            return True

