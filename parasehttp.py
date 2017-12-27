from __future__ import print_function
import output
import function

import re
import time

luna_output = output.output()
func = function.function()

class parasehttp(object):
    def __init__(self):

        self.text = ''
        self.http_method = ''

        self.get_key_list = []
        self.get_value_list = []
        self.get_text = ''

        self.post_key_list = []
        self.post_value_list = []
        self.post_text = ''

        self.cookie_key_list = []
        self.cookie_value_list = []
        self.cookie_text = ''

        self.cgi = ''
        self.content_length=''
        self.method_type = 0

    def parase_get(self):
        dom = self.get_text.split('#',1)
        before_dom = dom[0]

        if before_dom != '':
            parameter_value = before_dom.split('&')
            for per_key_val in parameter_value:
                key_val = per_key_val.split('=')
                self.get_key_list.append(key_val[0])
                if len(key_val) == 1:
                    key_val.append('')
                self.get_value_list.append(key_val[1])
                if len(self.get_key_list) != len(self.get_value_list):
                    print("GET key value error!")
                    return -1 


    def parase_post(self):
        parameter_value = self.post_text.split('&')
        for per_key_val in parameter_value:
            key_val = per_key_val.split('=')
            self.post_key_list.append(key_val[0])
            if len(key_val) == 1:
                key_val.append('')
            self.post_value_list.append(key_val[1])
            if len(self.post_key_list) != len(self.post_value_list):
                print("POST key value error!")
                return -1  
            
    def parase_cookie(self):
        self.cookie_key_list= []
        self.cookie_value_list = []
        parameter_value = self.cookie_text.split(';')
        for per_key_val in parameter_value:
            per_key_val = per_key_val.strip()
            key_val = per_key_val.split('=')
            self.cookie_key_list.append(key_val[0])
            if len(key_val) == 1:
                    key_val.append('')
            self.cookie_value_list.append(key_val[1])
            if len(self.cookie_key_list) != len(self.cookie_value_list):
                    print("Cookie key value error!")
                    return -1 






    def parase(self,luna_file,text):

        text = text[:-2]                              #remove \r\n

        cookie = re.match(r'(?i)[\s\S]*Cookie\s*:\s*(.*)',text)

        if cookie:
            self.cookie_text = cookie.group(1)
            self.parase_cookie()

        self.text = text

        if text[:4] == 'GET ':
            self.method_type = 1
            self.http_method = 'GET'
            dynamic = re.match(r'GET\s*(.*)\?(\S*?)\s*HTTP',text)
            if dynamic:
                self.cgi = dynamic.group(1)
                if dynamic.group(2) != '':
                    self.get_text = dynamic.group(2)
                    self.parase_get()

            else:
                print("not dynamic")
                func.SYSTEM_CLEAN()
                return -1

        elif text[:4] == 'POST':
            self.method_type = 2
            self.http_method = 'POST'
            dynamic = re.match(r'POST\s*(.*)\??(\S*)\s*HTTP([\s\S]*?)\r\n\r\n([^\r]*)(?:\r\n\r\n)?',text)
            if dynamic:
                self.cgi = dynamic.group(1)

                if dynamic.group(2) != '':
                    self.get_text = dynamic.group(2)
                    self.parase_get()
                content_length_m = re.match(r'[\s\S]*Content-Length:\s*(\d+)\s*',dynamic.group(3))
                if content_length_m:                    
                    self.content_length = content_length_m.group(1)
                type_m = re.match(r'[\s\S]*Content-Type:\s*(.*)\s*\r\n',dynamic.group(3))
                if type_m:

                    if type_m.group(1)[:33] == "application/x-www-form-urlencoded":
                        if dynamic.group(4)!='':
                            self.post_text = dynamic.group(4)
                            self.parase_post()
                            
                    elif type_m.group(1)[:20] == 'multipart/form-data;':
                        print("multipart")
                        return -1

                    else:
                        print("post error")
                        return -1
            else:
                print("not dynamic")
                func.SYSTEM_CLEAN()
                return -1
        else:
            print(text)
            return -1    

        luna_output.general_output(self)




