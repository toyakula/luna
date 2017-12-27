from __future__ import print_function
import function

import os
import time
import colorama
import sys

func = function.function()

class output(object):
    def __init__(self):
        colorama.init(autoreset=True) 

    def startup(self):
        func.SYSTEM_CLEAN()
        for i in range(10):
            print("------------------------------------------------------------")
        func.SLEEP()

    def standard_output(self,host,port,total,now):
        func.SYSTEM_CLEAN()
        sys.stdout.write(colorama.Back.LIGHTWHITE_EX + colorama.Fore.BLACK+ 'Host:'+host+ '  Port:' + port +'    Total:'+ str(total)+ '    Now:' + str(now))
        for i in range(50-(len(host)+len(port)+len(str(total))+len(str(now)))):
            sys.stdout.write(colorama.Back.LIGHTWHITE_EX + colorama.Fore.BLACK+" ")

    def white_output(self,text):
        sys.stdout.write(colorama.Fore.LIGHTWHITE_EX + colorama.Back.BLACK+text)

    def yellow_output(self,text):
        sys.stdout.write(colorama.Fore.LIGHTYELLOW_EX + colorama.Back.BLACK+text)

    def green_output(self,text):
        sys.stdout.write(colorama.Fore.LIGHTGREEN_EX + colorama.Back.BLACK+text)

    def red_output(self,text):
        sys.stdout.write(colorama.Fore.LIGHTRED_EX + colorama.Back.BLACK+text)

    def blue_output(self,text):
        sys.stdout.write(colorama.Fore.LIGHTBLUE_EX + colorama.Back.BLACK+text)

    def cyan_output(self,text):
        sys.stdout.write(colorama.Fore.LIGHTCYAN_EX  + colorama.Back.BLACK+text)

    def general_output(self,luna_parase):
        text = luna_parase.text
        if luna_parase.get_text != '':
            get_split_text = text.split(luna_parase.get_text,1)
            self.white_output(get_split_text[0])
            for i,per_key in enumerate(luna_parase.get_key_list):
                self.yellow_output(per_key)
                self.white_output('=')
                self.green_output(luna_parase.get_value_list[i])
                if i != len(luna_parase.get_key_list) - 1:
                    self.white_output('&')
            text = get_split_text[1]

        if luna_parase.cookie_text != '':
            cookie_split_text = text.split(luna_parase.cookie_text,1)
            self.white_output(cookie_split_text[0])
            for i,per_key in enumerate(luna_parase.cookie_key_list):
                self.blue_output(per_key)
                self.white_output('=')
                self.cyan_output(luna_parase.cookie_value_list[i])
                if i != len(luna_parase.cookie_key_list) - 1:
                    self.white_output(';')
            if len(cookie_split_text) == 1 :
                return
            else:
                text = cookie_split_text[1]


        if luna_parase.post_text != '':
            post_split_text = text.split(luna_parase.post_text,1)
            self.white_output(post_split_text[0])
            for i,per_key in enumerate(luna_parase.post_key_list):
                self.yellow_output(per_key)
                self.white_output('=')
                self.green_output(luna_parase.post_value_list[i])
                if i != len(luna_parase.post_key_list) - 1:
                    self.white_output('&')
            if len(post_split_text) == 1:
                return
            else:
                text = post_split_text[1]

        self.white_output(text)




    def vul_xss_output(self,raw1,exp,raw2):

        self.white_output(raw1)
        self.red_output(exp)
        self.white_output(raw2)






