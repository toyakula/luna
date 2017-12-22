import re
import time

import output
import conf.lunaconf

luna_output = output.output()

class base(object):

    ruleid = 0x0000
    method = ['GET','POST','COOKIE']                                                    #scan parameter in GET/POST/COOKIE
    key_exp = ''                                                                        #a[here]=1            
    value_exp = ''                                                                      #a=1[here]
    content_type_whitelist = []                                                         #content_type  whitelist                                                   
    options = 0x00                                                                      #master switch

    def __init__(self):

        self.luna_output = output.output()                                                       #cmd out control
        self.luna_conf = conf.lunaconf.lunaconf()                                                #load conf
        self.set_option()                                                                        #call set_option() when you use master switch


    def set_option(self):

        self.unurl_encode = (self.options&0b11111111)>>7
        self.url_encode   = (self.options&0b01111111)>>6
        self.replace_scan = (self.options&0b00111111)>>5
        self.add_scan     = (self.options&0b00011111)>>4
        self.raw_scan     = (self.options&0b00001111)>>3
        self.key_empty    = (self.options&0b00000111)>>2
        self.value_empty  = (self.options&0b00000011)>>1
        self.do_scan      = (self.options&0b00000001)>>0

        #self.unurl_encode = True
        #self.url_encode = False
        #self.replace_scan = True
        #self.add_scan = True

        #self.raw_scan = False      #Case True Then scan without exp Else scan with exp.

        #self.key_empty = False      #Case True Then scan without key[pointer]=value[pointer].
        #self.value_empty = False    #Case True Then scan like key[pointer]=&... .

        #self.do_scan = True       #Case True Then scan every key|val Else False skip scan.


    def before_scan(self,luna_scan,luna_report):        #Scan once before ver key and value
        header = luna_scan.scan_for_header(self,1,1,0)
        if header.has_key('Content-Type'):
            if header['Content-Type'] in self.luna_conf.content_type_whitelist:
                return False                #must return True stand for doscan or False stand for not doscan.  
        return True        

    def scan(self,luna_scan,luna_report):
        luna_vul = False
        add_scan = self.add_scan
        replace_scan = self.replace_scan

        while (add_scan or replace_scan) and not luna_vul:
            if add_scan:
                add_scan = False
                url_encode = self.url_encode
                unurl_encode = self.unurl_encode
                while unurl_encode or url_encode:
                    if unurl_encode:
                        unurl_encode = False
                        luna_vul = self.scan_main(luna_scan,luna_report,1,0)
                        if luna_vul:
                            return luna_vul
                    if url_encode:
                        url_encode = False
                        luna_vul = self.scan_main(luna_scan,luna_report,1,1)
                        if luna_vul:
                            return luna_vul
            if replace_scan:
                replace_scan = False
                url_encode = self.url_encode
                unurl_encode = self.unurl_encode
                while unurl_encode or url_encode:
                    if unurl_encode:
                        unurl_encode = False
                        luna_vul = self.scan_main(luna_scan,luna_report,0,0)
                        if luna_vul:
                            return luna_vul
                    if url_encode:
                        url_encode = False
                        luna_vul = self.scan_main(luna_scan,luna_report,0,1)
                        if luna_vul:
                            return luna_vul
        return luna_vul

    def scan_main(self,luna_scan,luna_report,scan_type,urlencode_type):
        pass                                                                 #interface

