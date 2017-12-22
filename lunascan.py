import output

import socket
import sys
import time
import re 
import StringIO, gzip
import urllib

import httplib

MAX_LENGTH = 65535

timeout = 10
socket.setdefaulttimeout(timeout)

luna_output = output.output()



class lunascan(object):
    def __init__(self,host,port):
        self.host = host
        self.port = port
        self.text = ''
        self.cgi = ''
        self.http_method = ''
        self.request =''
        self.response = ''

        self.scan_response_type = 0

        self.get_key_list = ''
        self.get_value_list = ''
        self.get_text = ''

        self.post_key_list = ''
        self.post_value_list = ''
        self.post_text = ''

        self.cookie_key_list = ''
        self.cookie_value_list = ''
        self.cookie_text = ''

        self.method_type = 0
        self.content_length = ''

        self.pointer = 0
        self.type_pointer = 0

        
        self.connection = ''
        self.response = ''
        

    def sethttp(self,luna_parase):
        self.text = luna_parase.text
        self.cgi = luna_parase.cgi
        self.http_method = luna_parase.http_method

        self.get_text = luna_parase.get_text
        self.get_key_list = luna_parase.get_key_list
        self.get_value_list = luna_parase.get_value_list

        self.post_text = luna_parase.post_text
        self.post_key_list = luna_parase.post_key_list
        self.post_value_list = luna_parase.post_value_list

        self.cookie_text = luna_parase.cookie_text
        self.cookie_key_list = luna_parase.cookie_key_list
        self.cookie_value_list = luna_parase.cookie_value_list

        self.content_length = luna_parase.content_length

    def setpointer(self,pointer,type_pointer):
        self.pointer = pointer
        self.type_pointer = type_pointer

    def scan(self,luna_exp,raw_scan,scan_type,urlencode_type):

        
        connect_str = self.host+':'+str(self.port)
        self.connection = httplib.HTTPConnection(connect_str)

        if raw_scan:                                      #raw request
            if luna_exp.key_empty  or luna_exp.value_empty :
                if luna_exp.key_empty:
                    pass
                else:
                    pass
            else:
                request = self.text
            
        else:

            if not scan_type:

                if self.type_pointer == 1:                              #GET

                    parstr_get = ''
                    http = self.text.split(self.get_text,1)
                    for i,ver_get_key in enumerate(self.get_key_list):
                        if i != self.pointer:
                            parstr_get += ver_get_key + '=' + self.get_value_list[i]
                            if i != len(self.get_key_list) - 1 :
                                parstr_get += '&'
                        else :
                            parstr_get += ver_get_key + urllib.quote(luna_exp.key_exp) + '=' +  urllib.quote(luna_exp.value_exp)
                            if i != len(self.get_key_list) - 1 :
                                parstr_get += '&'
                    request = http[0] + parstr_get + http[1]
                if self.type_pointer == 2:                               #POST
                    if urlencode_type:
                        key_exp = urllib.quote(luna_exp.key_exp)
                        value_exp = urllib.quote(luna_exp.value_exp)
                    else:
                        key_exp = luna_exp.key_exp
                        value_exp = luna_exp.value_exp
                    parstr_post = ''
                    http = self.text.split(self.post_text,1)

                    length = int(self.content_length)
                    length += len(key_exp) + len(value_exp)

                    content_length_sub = "Content-Length: "+str(length)
                    http[0] = re.sub(r'Content-Length:\s*(\d+)',content_length_sub,http[0])
                
                    for i,ver_post_key in enumerate(self.post_key_list):
                        if i != self.pointer:
                            parstr_post += ver_post_key + '=' + self.post_value_list[i]
                            if i != len(self.post_key_list) - 1 :
                                parstr_post += '&'
                        else :
                            parstr_post += ver_post_key + key_exp + '=' +  value_exp
                            if i != len(self.post_key_list) - 1 :
                                parstr_post += '&'
                    request = http[0] + parstr_post + http[1]

                if self.type_pointer == 3:                               #COOKIE
                    if urlencode_type:
                        key_exp = urllib.quote(luna_exp.key_exp)
                        value_exp = urllib.quote(luna_exp.value_exp)
                    else:
                        key_exp = luna_exp.key_exp
                        value_exp = luna_exp.value_exp
                    parstr_cookie = ''
                    http = self.text.split(self.cookie_text,1)
                
                    for i,ver_cookie_key in enumerate(self.cookie_key_list):
                        if i != self.pointer:
                            parstr_cookie += ver_cookie_key + '=' + self.cookie_value_list[i]
                            if i != len(self.cookie_key_list) - 1 :
                                parstr_cookie += '&'
                        else :
                            parstr_cookie += ver_cookie_key + key_exp + '=' +  value_exp
                            if i != len(self.cookie_key_list) - 1 :
                                parstr_cookie += '&'
                    request = http[0] + parstr_cookie + http[1]

            else :
                if self.type_pointer == 1:                              #GET
                    parstr_get = ''
                    http = self.text.split(self.get_text,1)
                    for i,ver_get_key in enumerate(self.get_key_list):
                        if i != self.pointer:
                            parstr_get += ver_get_key + '=' + self.get_value_list[i]
                            if i != len(self.get_key_list) - 1 :
                                parstr_get += '&'
                        else :
                            parstr_get += ver_get_key + urllib.quote(luna_exp.key_exp) + '=' + self.get_value_list[i] + urllib.quote(luna_exp.value_exp)
                            if i != len(self.get_key_list) - 1 :
                                parstr_get += '&'
                    request = http[0] + parstr_get + http[1]

                if self.type_pointer == 2:                               #POST
                    parstr_post = ''
                    http = self.text.split(self.post_text,1)
                    if urlencode_type:
                        key_exp = urllib.quote(luna_exp.key_exp)
                        value_exp = urllib.quote(luna_exp.value_exp)
                    else:
                        key_exp = luna_exp.key_exp
                        value_exp = luna_exp.value_exp
                    length = int(self.content_length)
                    length += len(key_exp) + len(value_exp)

                    content_length_sub = "Content-Length: "+str(length)
                    http[0] = re.sub(r'Content-Length:\s*(\d+)',content_length_sub,http[0])
                
                    for i,ver_post_key in enumerate(self.post_key_list):
                        if i != self.pointer:
                            parstr_post += ver_post_key + '=' + self.post_value_list[i]
                            if i != len(self.post_key_list) - 1 :
                                parstr_post += '&'
                        else :
                            parstr_post += ver_post_key + key_exp + '=' + self.post_value_list[i] + value_exp
                            if i != len(self.post_key_list) - 1 :
                                parstr_post += '&'
                    request = http[0] + parstr_post + http[1]

                if self.type_pointer == 3:                               #COOKIE
                    if urlencode_type:
                        key_exp = urllib.quote(luna_exp.key_exp)
                        value_exp = urllib.quote(luna_exp.value_exp)
                    else:
                        key_exp = luna_exp.key_exp
                        value_exp = luna_exp.value_exp
                    if urlencode_type:
                        key_exp = urllib.quote(luna_exp.key_exp)
                        value_exp = urllib.quote(luna_exp.value_exp)
                    parstr_cookie = ''
                    http = self.text.split(self.cookie_text,1)
                
                    for i,ver_cookie_key in enumerate(self.cookie_key_list):
                        if i != self.pointer:
                            parstr_cookie += ver_cookie_key + '=' + self.cookie_value_list[i]
                            if i != len(self.cookie_key_list) - 1 :
                                parstr_cookie += '&'
                        else :
                            parstr_cookie += ver_cookie_key + key_exp + '=' + self.cookie_value_list[i] + value_exp
                            if i != len(self.cookie_key_list) - 1 :
                                parstr_cookie += '&'
                    request = http[0] + parstr_cookie + http[1]


        replyline=''
        self.request = request
        self.connection.send(request)
        #print request
        #time.sleep(1)


        try:
            self.response = self.connection.getresponse()
            replyline = self.response.read(MAX_LENGTH)
            try:
                compressedstream = StringIO.StringIO(replyline)  
                gziper = gzip.GzipFile(fileobj=compressedstream)    
                new_replyline = gziper.read() 

            except Exception  as e:
                #print e
                new_replyline = replyline
            
            reply_status = self.response.status
            reply_headers = self.response.msg
            self.response = self.response.response + '\r\n' + replyline

        except  Exception as e:
            print e
            new_replyline = ''
            reply_status = 0
            reply_msg = ''
            reply_headers = ''
            self.response = ''
        
        self.connection.close()
        if self.scan_response_type == 0b100:
            return new_replyline
        elif self.scan_response_type == 0b1:
            return reply_status
        elif self.scan_response_type == 0b10:
            return reply_headers
        elif self.scan_response_type == 0b111:
            return reply_status,reply_headers,new_replyline
 
    def scan_for_status(self,luna_exp,raw_scan,scan_type,urlencode_type):
        self.scan_response_type = 0b1
        status = self.scan(luna_exp,raw_scan,scan_type,urlencode_type)
        return status

    def scan_for_header(self,luna_exp,raw_scan,scan_type,urlencode_type):
        self.scan_response_type = 0b10
        header = self.scan(luna_exp,raw_scan,scan_type,urlencode_type)
        return header

    def scan_for_body(self,luna_exp,raw_scan,scan_type,urlencode_type):
        self.scan_response_type = 0b100
        body = self.scan(luna_exp,raw_scan,scan_type,urlencode_type)
        return body

    def scan_for_all(self,luna_exp,raw_scan,scan_type,urlencode_type):
        self.scan_response_type = 0b111
        status,header,body = self.scan(luna_exp,raw_scan,scan_type,urlencode_type)
        return status,header,body



    def v_scan(self,luna_report,luna_parase,luna_exp,luna_conf):
        for method in luna_exp.method:
            if method == 'GET' and len(self.get_text) != 0:
                for i,every_get_key in enumerate(self.get_key_list):
                    self.setpointer(i,1)
                    luna_exp.scan(self,luna_report)
                    
            if method == 'POST' and len(self.post_text) != 0:
                for i,every_post_key in enumerate(self.post_key_list):
                    self.setpointer(i,2)
                    luna_exp.scan(self,luna_report)
                    

            if method == 'COOKIE' and len(self.cookie_text) != 0 and luna_conf.scan_cookie:
                for i,every_cookie_key in enumerate(self.cookie_key_list):
                    self.setpointer(i,3)
                    luna_exp.scan(self,luna_report)
                        

    def pre_scan(self,luna_prescan):

        if len(self.get_text) != 0 and len(self.get_key_list)>0:
            self.setpointer(0,1)
            luna_prescan.scan(self,luna_report)
            luna_prescan.pre_scan_count += 1
            return

        if len(self.post_text) != 0 and len(self.post_key_list)>0:
            self.setpointer(0,2)
            luna_prescan.scan(self,luna_report)
            luna_prescan.pre_scan_count += 1
            return

    def scan_key(self):
        if self.type_pointer == 1:
            return self.get_key_list[self.pointer]

        if self.type_pointer == 2:
            return self.post_key_list[self.pointer]

        if self.type_pointer == 3:
            return self.cookie_key_list[self.pointer]
                        
            


    
