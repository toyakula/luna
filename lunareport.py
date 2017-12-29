import datetime
import time

class lunareport(object):

    title_list = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    title_no = 0

    rep_file = ''
    vul_type = 0 

    vul_title= ['General','Reflected XSS','SQL Injection']
    vul_text = ['','','','','','','','','','','','','','','']


    file_name = ''

    content = ''


    def __init__(self,host,port):
        now = datetime.datetime.now()
        date = now.strftime('%Y-%m-%d')
        self.file_name = "./report/" + host + "["+ port +"]" +"_" + date + "_report.html"
        self.rep_file = open(self.file_name,'w')
        self.content = """
<!DOCTYPE html>
<html lang="zh-cn">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Luna Report</title>

    <!-- Bootstrap -->
    <link href="css/bootstrap.min.css" rel="stylesheet">

    <!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
    <!-- WARNING: Respond.js doesn't work if you view the page via file:// -->
    <!--[if lt IE 9]>
      <script src="http://cdn.bootcss.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="http://cdn.bootcss.com/respond.js/1.4.2/respond.min.js"></script>
    <![endif]-->



    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="js/jquery-3.1.1.min.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="js/bootstrap.min.js"></script>
  </head>
  <body>
    <nav class="navbar navbar-inverse navbar-fixed-top" role="navigation">
      <div class="container">
        <div class="navbar-header">
          <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
            <span class="sr-only">Toggle navigation</span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
          </button>
          <a class="navbar-brand" href="#">Luna</a>
        </div>
        <div id="navbar" class="collapse navbar-collapse">
          <ul class="nav navbar-nav">
            <li class="active"><a href="#">Home</a></li>
            <li><a href="#about">About</a></li>
            <li><a href="#contact">Contact</a></li>
          </ul>
        </div><!--/.nav-collapse -->
      </div>
    </nav>
<style>
body {background-color:#101010;}
#wrapper {position:absolute;top:100px;left:50%;width:200px;height:200px;margin-left:-100px;
    -webkit-animation-name: moonline;-webkit-animation-duration: 10s;-webkit-animation-timing-function: linear;-webkit-animation-iteration-count: infinite;
    -moz-animation-name: moonline;-moz-animation-duration: 10s;-moz-animation-timing-function: linear;-moz-animation-iteration-count: infinite;
}
@-webkit-keyframes moonline {
    0% {top:100px;left:30%;opacity:0;}
    30% {top:100px;left:30%;opacity:1;}
    50% {top:100px;left:30%;opacity:1;}
    80% {top:100px;left:30%;opacity:1;}
    100% {top:100px;left:30%;opacity:0;}
}
@-moz-keyframes moonline {
    0% {top:100px;left:30%;opacity:0;}
    30% {top:100px;left:30%;opacity:1;}
    50% {top:100px;left:30%;opacity:1;}
    80% {top:100px;left:30%;opacity:1;}
    100% {top:100px;left:30%;opacity:0;}
}
#circle {
    position: absolute;
    top: 0;
    left: 0;
    width: 200px;
    height: 200px;
    background-color: #EFEFEF;
    -webkit-box-shadow:0 0 40px #FFFFFF;
    -moz-box-shadow:0 0 40px #FFFFFF;
    box-shadow:0 0 40px #FFFFFF;
    border-radius: 100px;
    -webkit-animation-name: moonright;-webkit-animation-duration: 10s;-webkit-animation-timing-function: linear;-webkit-animation-iteration-count: infinite;
    -moz-animation-name: moonright;-moz-animation-duration: 10s;-moz-animation-timing-function: linear;-moz-animation-iteration-count: infinite;
}
@-webkit-keyframes moonright {
    0% {-webkit-box-shadow:0 0 10px #FFFFFF;}
    30% {-webkit-box-shadow:0 0 10px #FFFFFF;}
    40% {-webkit-box-shadow:0 0 20px #FFFFFF;}
    50% {-webkit-box-shadow:0 0 40px #FFFFFF;}
    60% {-webkit-box-shadow:0 0 20px #FFFFFF;}
    80% {-webkit-box-shadow:0 0 10px #FFFFFF;}
    100% {-webkit-box-shadow:0 0 10px #FFFFFF;}
}
@-moz-keyframes moonright {
    0% {-moz-box-shadow:0 0 10px #FFFFFF;}
    30% {-moz-box-shadow:0 0 10px #FFFFFF;}
    40% {-moz-box-shadow:0 0 20px #FFFFFF;}
    50% {-moz-box-shadow:0 0 40px #FFFFFF;}
    60% {-moz-box-shadow:0 0 20px #FFFFFF;}
    80% {-moz-box-shadow:0 0 10px #FFFFFF;}
    100% {-moz-box-shadow:0 0 10px #FFFFFF;}
}
#circle1 {
    display:block;
    content:"";
    position: absolute;
    top: -1px;
    left: -1px;
    width: 202px;
    height: 202px;
    background-color: #101010;
    border-radius: 100px;
    -webkit-animation-name: moon;-webkit-animation-duration: 10s;-webkit-animation-timing-function: linear;-webkit-animation-iteration-count: infinite;
    -moz-animation-name: moon;-moz-animation-duration: 10s;-moz-animation-timing-function: linear;-moz-animation-iteration-count: infinite;
}
@-webkit-keyframes moon {
    0% { left:"""+self.draw_moon()+"""px }
    30% { left:"""+self.draw_moon()+"""px }
    49% { left:"""+self.draw_moon()+"""px }
    51% { left:"""+self.draw_moon()+"""px }
    51% { left:"""+self.draw_moon()+"""px }
    53% { left:"""+self.draw_moon()+"""px }
    80% { left:"""+self.draw_moon()+"""px }
    100% { left:"""+self.draw_moon()+"""px }
    }
@-moz-keyframes moon {
    0% { left:0px }
    30% { left:0px }
    49% { left:0px;}
    51% { left:0px;}
    53% { left:0px;}
    80% { left:0px;}
    100% { left:0px;}
}
</style>
<script>
$(document).ready(function(){
  $(".btn1").click(function(){
    $("p").toggle(true);
  });
});

function f(){
   $("#aaa").html("GET /search/?key=1 HTTP/1.1<br>Host: gad.qq.com<br>Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8<br>Upgrade-Insecure-Requests: 1<br>User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36<br>Referer: http://gad.qq.com/search/?key=1<br>Accept-Encoding: gzip, deflate, sdch<br>Accept-Language: zh-CN,zh;q=0.8<br>Cookie: eas_sid=M1B4R6R201K9a9I6348479O2y9; gaduid=5729a11212f22; funshow_skey=1462779692; mobileUV=1_154993e8360_1a5db; <br>tvfe_boss_uuid=30d0e7e3c2f78fed; AMCV_248F210755B762187F000101%40AdobeOrg=793872103%7CMCIDTS%7C16987%7CMCMID%7C06642548846215397568190837881177038732%7CMCAID%7CNONE%7CMCAAMLH-1468225788%7C11%7CMCAAMB-1468225788%7Chmk_Lq6TPIBMW925SPhw3Q; sd_userid=80031475223515412; sd_cookie_crttime=1475223515412; luin=o0346253755; lskey=0001000013c0072a7d6af2c19fbaf8f42bd4ae64cbb55f5b91a62b0bda3d4ad1d122c2f5dd0069004b3bb059; LOL_a20151217news_bind_346253755=19; RK=TRvnCzjyPG; pgv_pvi=1130935296; rv_mini_unmute=1; pac_uid=1_1328730763; uid=26361808; ptisp=ctc; ptcz=5c5c3470477e3d287855ef68326d7e2f48a78687a54498637a5b3a502c62873c; pt2gguin=o0346253755; uin=o0346253755; skey=@EiGUkgV0j; IED_LOG_INFO2=userUin%3D346253755%26nickName%3Ddo9gy%2525E2%252596%2525A1%26userLoginTime%3D1479178949; user-tags-flag=1; pgv_info=ssid=s146561918; ts_last=gad.qq.com/search/; pgv_pvid=7116668991; o_cookie=346253755; ts_uid=178598014; csrf=%40EiGUkgV0j%7C22017382696; PHPSESSID=rk29cfuua4sb60m8asqbvmdes3");
}
function g(){

    $("#aaa").html("GET /search/?key=1 HTTP/1.1<br>Host: gad.qq.com...");
    }
</script>
<div id="wrapper">
  <div id="circle"></div>
  <div id="circle1"></div>
</div>
    <div class="container theme-showcase" role="main" style="padding-top:100px;padding-left:600px">
        <font color="#77FF33" ><h1><strong>LUNA Web Security Scanner</strong></h1></font>
        <font color="#CCCCCC" ><p class="lead">Dog loves God as well as Bunny loves Luna.<br> Thank you for your support.</p></font>


            """+now.strftime('<font color="#00CCFF" ><h1><strong>'+host+'</strong></h1></font><font color="#CCCCCC" ><p class="lead">start at %Y-%m-%d %H:%M:%S</p></font></div></div><!-- /.container -->')
        self.rep_file.write(self.content)
        self.rep_file.flush()


    def __del__(self):

        self.rep_file.close()

    def draw_title(self,part_type):
       
        part_title="""
        <div  style="padding-top:100px;padding-left:300px;">
            <div style=" width:30px; height:30px; background-color:#7BCD33; border-radius:25px;">
         <span style="color:#FFFFFF; display:block;width:1300px;padding-left:8px;"><h3>
         """+str(self.title_no)+"&nbsp;&nbsp;&nbsp;&nbsp;"+self.vul_title[part_type]+"""</h3></span>
            </div>
             <span style="color:#FFFFFF;">
                <table style="border-collapse:separate; border-spacing:20px; ">
                    <tr><td width="10%" ><strong><font size="4">Url</font></strong></td><td width="10%"><strong><font size="4">Method</font></strong></td><td width="10%"><strong><font size="4">Parameter</font></strong></td><td width="20%"><strong><font size="4">Request</font></strong></td><td width="20%"><strong><font size="4">Response</font></strong></td><td width="10%"><strong><font size="4">Rule-id</font></strong></td><td width="10%"><strong><font size="4">Rule-type</font></strong></td><td width="10%"><strong><font size="4">Match-with</font></strong></td></tr>
                    """


        self.vul_text[part_type] += part_title


    def report_http(self,luna_scan,luna_exp):

        text = luna_scan.request.replace('>', '&gt;').replace('<','&lt;').replace("\r\n","<br>")
        response = luna_scan.response.replace('>', '&gt;').replace('<','&lt;').replace("\r\n","<br>")


        part_type = luna_exp.ruleid>>8
        if (self.title_list[part_type]) == 0 :
            self.title_list[part_type] = 1
            self.title_no += 1
            self.draw_title(part_type)

        self.vul_text[part_type] += '<tr><td><font size="3">'+luna_scan.host+luna_scan.cgi.replace('>', '&gt;').replace('<','&lt;')+'</font></td><td><font size="3">'+luna_scan.http_method+'</font></td><td><font size="3">'+luna_scan.scan_key().replace('>', '&gt;').replace('<','&lt;')+'</font></td><td ondblclick="$(this).hide();$(this).next().show(2000);"><font size="3">'+luna_scan.request[:70]+'...</td><td style="display:none;white-space: nowrap;" ondblclick="$(this).hide();$(this).prev().show(2000);"><font size="3">'+text+'</font></td><td ondblclick="$(this).hide();$(this).next().show(2000);"><font size="3">'+luna_scan.response[:70]+'...</td><td style="display:none;white-space: nowrap;" ondblclick="$(this).hide();$(this).prev().show(2000);"><font size="3">'+response+'</font></td><td><font size="3">'+str(luna_exp.ruleid)+'</font></td><td><font size="3">'+luna_exp.rule_type+'</font></td><td><font size="3">'+luna_exp.match_with.replace('>', '&gt;').replace('<','&lt;')+'</font></td></tr>'
        end_table = '</table> </span></div>'

        self.rep_file=open(self.file_name,'w')
        self.rep_file.write(self.content)

        for i in range(0xF):
            if self.title_list[i] == 0 :
                continue
            self.rep_file.write(self.vul_text[part_type]+end_table)

        self.rep_file.write("</body></html>")
        self.rep_file.flush()



    def report_prescan(self,prescan):
        if prescan["little_sample"]:
            self.rep_file.write("little_sample<br>")
            self.rep_file.flush()
            return
        have_waf = prescan["waf"]
        waf_type = prescan["waf_type"]
        self.rep_file.write("waf: %d,waf_type: %s<br>" %(have_waf,waf_type))
        self.rep_file.flush()

    def draw_moon(self):
        Q = (datetime.date.today().year-1977)/4
        R = (datetime.date.today().year-1977)%4
        Firstday = datetime.date(datetime.date.today().year,1,1).toordinal()
        Today = datetime.date.today().toordinal()
        D =  Today - Firstday + 1 
        T = (14*Q + 10.6*(R+1) + D)
        n = T/29.5
        n = int(n)
        m_day = int(T - 29.5*n)
        if m_day > 30:
            m_day = 30
        if m_day < 1:
            m_day = 15
        if m_day > 15:
            moon = - ((31 - m_day ) /15.0)  *210
        else:
            moon = (m_day /15.0)  *210
        return str(int(moon))