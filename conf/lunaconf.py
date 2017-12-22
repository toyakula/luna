#   __           __      __    ___     __          __
#   ||           ||      ||    ||\\    ||         /__\
#   ||           ||      ||    || \\   ||        //  \\
#   ||           ||      ||    ||  \\  ||       //____\\
#   ||           ||      ||    ||   \\ ||      //------\\
#   ||_______    \\______//    ||    \\||     //        \\
#   |--------\    \------/     |-     \-|    /-          -\


#host=[['www.luna.com','80'],] , scan when host is 'www.luna.com' and port is 80.
#host=[['luna.com','80'],['www.luna.com','80'],['luna.luna.com','8080'] , scan when host:port in an array.
#host_port=[['*','80'],] , all host:80 in the lunahttplog will be scan
#host_port['www.luna.com','*'],] , all port of the host www.luna.com in the lunahttplog will be scan
host_port=[['127.0.0.1','80'],]

#exp_take='ref_xss' , scan with only one exp(ref_xss)
#exp_take=['ref_xss','array_error',...] , scan with any exp you pick in the list
#exp_take= * , scan with all exp under the exp dir
#exp_take= luna , auto scan by luna method,recommended
#exp_take= luna

#http_log='lunahttplog.txt' , http requires will be token from the 'lunahttplog.txt'
#http_log= * , just do a simple scan to the host(host must not be * in this case)
http_log = 'lunahttplog.txt'

#log_file='./log/luna.log' , The file is used to store scanlog.
log_file = './log/luna.log'

#static_cgi_type = ['css','js','swf','jpg','xml']
static_cgi_type = ['css','js','swf','jpg','xml']

#Max_pre_scan_count = 5 , the count of pre-scan http request .
Max_pre_scan_count = 5

content_type_whitelist = ["application/x-jpg","image/jpeg","image/gif","application/x-shockwave-flash", "audio/x-ms-wma", \
                            "application/msword","application/x-javascript","application/x-msdownload","text/css" \
                            "application/octet-stream","application/x-zip-compressed","application/zip"]


scan_cookie = 0   # 0 will not scan, 1 will scan

class lunaconf(object):
    def __init__(self):
        self.host_port = host_port
        self.http_log = http_log
        self.log_file = log_file
        self.static_cgi_type = static_cgi_type
        self.Max_pre_scan_count = Max_pre_scan_count
        self.content_type_whitelist = content_type_whitelist
        self.scan_cookie = scan_cookie

        self.check()
    def check(self):
        pass
