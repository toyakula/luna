import sqlite3
import json
import time

class sqlite(object):
    def __init__(self):
        self.conn = sqlite3.connect("./luna.db")
        self.sqlite_con=self.conn.cursor()
        self.hostid = 0

    def __del__(self):
        self.sqlite_con.close()

    def create(self):
        self.sqlite_con.execute("drop table if exists host")
        self.sqlite_con.execute("drop table if exists cgi")

        self.sqlite_con.execute("create table host(hostid integer primary key autoincrement,hostname TEXT,port integer)")
        self.sqlite_con.execute("create table cgi(cgiid integer primary key autoincrement,hostid integer,cgi TEXT,method integer,get_keylist TEXT,get_valuelist TEXT,post_keylist TEXT,post_valuelist TEXT)")

    def insert_host(self,host,port):

        hostidresult = self.sqlite_con.execute("SELECT hostid FROM host WHERE hostname = ? AND port = ?",(host,port))
        result = hostidresult.fetchone()
        if result :
            return result[0]
        else:
            self.sqlite_con.execute("INSERT INTO host VALUES (NULL,?,?)",(host,port))
            self.conn.commit()
            hostidresult = self.sqlite_con.execute("SELECT hostid FROM host WHERE hostname = ? AND port = ?",(host,port))
            result = hostidresult.fetchone()
            return result[0]

    def insert_cgi(self,hostid,cgi,method,get_keylist,get_valuelist,post_keylist,post_valuelist):
        get_keyjson = json.dumps(get_keylist)
        get_valuejson = json.dumps(get_valuelist)
        post_keyjson = json.dumps(post_keylist)
        post_valuejson = json.dumps(post_valuelist)  

        self.sqlite_con.execute("INSERT INTO cgi VALUES (NULL,?,?,?,?,?,?,?)",(hostid,cgi,method,get_keyjson,get_valuejson,post_keyjson,post_valuejson))   
        self.conn.commit()

    def select_cgi(self,hostid,cgi):
        self.sqlite_con.execute("SELECT keylist,valuelist FROM cgi WHERE hostid = ? AND cgi = ?",(hostid,cgi))

    def cgi_exist(self,hostid,cgi):
        cgiresult = self.sqlite_con.execute("SELECT * FROM cgi WHERE hostid = ? AND cgi = ?",(hostid,cgi))
        result = cgiresult.fetchone()
        if result:
            return True
        else:
            return False


    def cgi_key_exist(self,hostid,luna_parse):
        cgiresult = self.sqlite_con.execute("SELECT get_keylist,post_keylist FROM cgi WHERE hostid = ? AND cgi = ?",(hostid,luna_parse.cgi))
        for row in cgiresult:
            get_keylist = json.loads(row[0])
            post_keylist = json.loads(row[1])
            if set(get_keylist) == set(luna_parse.get_key_list)  and  set(post_keylist) == set(luna_parse.post_key_list) :
                return True
                
        return False

    def flush_session_cgi(self,hosts):

        for host in hosts:
            time.sleep(3)
            cgiresult = self.sqlite_con.execute("SELECT hostid FROM host WHERE hostname = ? ",(host,))
            result = cgiresult.fetchone()
            print result
            self.sqlite_con.execute("DELETE  FROM cgi WHERE hostid = ? ",result)
            self.conn.commit()