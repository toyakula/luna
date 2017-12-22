import re
import time

import lunaexp

class ref_xss(lunaexp.base):

    ruleid = 0x0100
    method = ['GET','POST','COOKIE']
    key_exp = ''
    value_exp = 'luna_ref_xss_scan'
    rule_type = "refxss-main"
    match_with = ""

    on_level = 1     # 1  simple    2    custom  3   total


    content_type_whitelist = ["text/javascript","application/x-javascript","application/javascript"]

    danger_tag = ["script","a","img","object","embed","video","form","iframe","button","math","link"]

    options = 0xB1

    def scan_main(self,luna_scan,luna_report,scan_type,urlencode_type):

        data = luna_scan.scan_for_body(self,0,scan_type,urlencode_type)
        
        n = data.split(self.value_exp)

        
        if len(n) >= 2:
            if n[0] == '':
                exp = "utf7_xss"
                module = __import__("exp.xss."+exp,{},{},list(exp))
                exp_obj = getattr(module, exp)()
                utf7_vul = exp_obj.scan(luna_scan,luna_report)
                if utf7_vul:
                    return True

            for i,raw in enumerate(n):
                if i == len(n)-1:
                    break
                self.luna_output.vul_xss_output(n[i][-50:],self.value_exp,n[i+1][:50])
                time.sleep(1)
                if self.injs(n[i].lower()):
                    exp = "injs_xss"
                    module = __import__("exp.xss."+exp,{},{},list(exp))
                    exp_obj = getattr(module, exp)()
                    exp_obj.argv = i
                    injs_vul = exp_obj.scan(luna_scan,luna_report)
                    if injs_vul:
                        return True
                inhtmltag,tagtext = self.inhtmltag(n[i].lower(),n[i+1].lower())
                if inhtmltag:
                    if self.inquotes(tagtext):
                        exp = "inquotes_xss"
                        module = __import__("exp.xss."+exp,{},{},list(exp))
                        exp_obj = getattr(module, exp)()
                        exp_obj.argv = i
                        inquotes_vul,match_with = exp_obj.scan(luna_scan,luna_report)
                        if inquotes_vul:

                            tag = self.in_dangertag(tagtext)
                            
                            if tag:
                                self.match_with = match_with+"[tag:"+tag+"]"
                                luna_report.report_http(luna_scan,self)
                                return True
                        else:
                            if self.jsenable_xss(luna_scan,luna_report,i):
                                return True
                    else:
                        htmltag_vul,match_with = self.htmltag_xss(luna_scan,luna_report,i)
                        if htmltag_vul:
                            if self.jsenable_xss(luna_scan,luna_report,i):
                                return True

                else:
                    htmltag_vul,match_with = self.htmltag_xss(luna_scan,luna_report,i)
                    if htmltag_vul:
                        if self.jsenable_xss(luna_scan,luna_report,i):
                            return True
                    



            #vul_type = 'ref_xss'
            #luna_report.report_http(luna_scan.text,luna_scan.scan_key(),vul_type,self.value_exp)
            return True
        else:
            return False


    def htmltag_xss(self,luna_scan,luna_report,i):
        exp = "htmltag_xss"
        module = __import__("exp.xss."+exp,{},{},list(exp))
        exp_obj = getattr(module, exp)()
        exp_obj.argv = i
        htmltag_vul,match_with = exp_obj.scan(luna_scan,luna_report)
        if htmltag_vul:
            return True,match_with
        else:
            return False,match_with


    def jsenable_xss(self,luna_scan,luna_report,i):
        exp = "jsenable_xss"
        module = __import__("exp.xss."+exp,{},{},list(exp))
        exp_obj = getattr(module, exp)()
        exp_obj.argv = i
        jsenable_vul= exp_obj.scan(luna_scan,luna_report)
        if jsenable_vul:
            return True
        else:
            return False

    def injs(self,html_text):
        script_type = 0x0

        on_array = ["src" , "href" , "srcdoc" , "formaction" ,
                    'onload' , 'onerror' , 'onmousemove', 'onclick', 'onsubmit', 'onmouseover', 'onfocus',
                    'onloadeddata', 'onwaiting', 'onredo', 'onprogress', 'ondragenter', 'onreset', 'onended', 
                    'onmousedown', 'onforminput', 'onhaschange', 'ondurationchange', 'onpause', 'onplay', 
                    'onmousewheel', 'onchange', 'onafterprint', 'oninvalid', 'onloadstart', 'onabort', 
                    'oninput', 'onmouseout', 'ondragover', 'onsuspend', 'ontimeupdate', 'onratechange', 
                    'ondragleave', 'onresize', 'onselect', 'onundo', 'onemptied', 'ondrag', 'oncanplay',
                    'onstorage', 'onformchange', 'onblur', 'ondragstart', 'onoffline', 'ondrop', 'onkeypress', 
                    'ononline', 'onkeydown', 'onpageshow', 'onvolumechange', 'onpopstate', 'oncontextmenu', 
                    'onscroll','onunload', 'onloadedmetadata', 'ondragend', 'onseeking', 'onbeforeprint', 
                    'oncanplaythrough', 'onbeforeunload', 'onpagehide', 'onmouseup', 'onkeyup', 'onmessage',
                    'onplaying', 'ondblclick', 'onseeked', 'onreadystatechange', 'onstalled']

        scr_start = html_text.rfind("<script")
        if scr_start + 1:
            scr_end = html_text.rfind("</script")
            if scr_end + 1:
                v_text = html_text[scr_end:]
                scr_start = v_text.rfind("<script")
                if scr_start + 1:
                    script_type = 0b0001
                    return script_type
            else:
                script_type = 0b0001
                return script_type

        for i,on_text in enumerate(on_array):
            if self.on_level == 1:
                if i>10:
                    break
            on_start = html_text.rfind(on_text)
            if on_start + 1:
                v_text = html_text[on_start:]
                v_text = v_text.replace(" ","")
                v_text = v_text.replace("\t","")
                new_on_start = v_text.rfind(on_text+"=\"")
                if new_on_start + 1:
                    new_on_start += len(on_text) + 2
                    v_text = v_text[new_on_start:]
                    new_on_end = v_text.find("\"")
                    if new_on_end == -1:
                        script_type = 0b0010
                        return script_type

        css_start = html_text.rfind("expression(")
        if css_start + 1:
            html_text = html_text[css_start:]
            left = html_text.count("(")
            right = html_text.count(")")
            if left > right:
                script_type = 0b0100
                return script_type

        return script_type




    def inhtmltag(self,html_text_bef,html_text_aft):
        bef_tag_start = html_text_bef.rfind("<")
        if bef_tag_start + 1:
            html_text_bef = html_text_bef[bef_tag_start + 1:]
            bef_tag_end = html_text_bef.rfind(">")
            if bef_tag_end + 1:
                v_text = html_text_bef[bef_tag_end:]
                bef_tag_start = v_text.rfind("<")
                if bef_tag_start + 1:
                    text = html_text_bef[bef_tag_start+1:]
                    aft_tag_start = html_text_aft.find(">")
                    if aft_tag_start + 1:
                        html_text_aft = html_text_aft[:aft_tag_start]
                        aft_tag_end = html_text_aft.find("<")
                        if aft_tag_end + 1:
                            v_text = html_text_aft[:aft_tag_end]
                            aft_tag_start = v_text.find(">")
                            if aft_tag_start + 1:
                                return True,text
                        else:
                            return True,text
            else:
                text = html_text_bef
                aft_tag_start = html_text_aft.find(">")
                if aft_tag_start + 1:
                    html_text_aft = html_text_aft[:aft_tag_start]
                    aft_tag_end = html_text_aft.find("<")
                    if aft_tag_end + 1:
                        v_text = html_text_aft[:aft_tag_end]
                        aft_tag_start = v_text.find(">")
                        if aft_tag_start + 1:
                            return True,text
                    else:
                        return True,text

        
        return False,-1


    def inquotes(self,tagtext):
        if tagtext.count('"')%2 :
            return True
        else:
            return False

    def in_dangertag(self,tagtext):
        print tagtext
        time.sleep(5)
        tag_end = tagtext.find(" ")
        if tag_end+1:
            tag = tagtext[:tag_end]
            if tag in self.danger_tag:
                return tag
            else:
                return False