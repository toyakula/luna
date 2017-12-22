import re
import time

import output
import conf.lunaconf
import lunaexp

luna_output = output.output()
luna_conf = conf.lunaconf.lunaconf()

class err_sqli(lunaexp.base):

    ruleid = 0x0201
    method = ['GET','POST','COOKIE']
    key_exp = ''
    value_exp = ""
    exp_list = ["'",'"',"xbf'xbf\"","xF0x27x27xF0x22x22","\\","JyI=","(select convert(int,CHAR(65)))","%27`\"%5C200%0d%0a1","1'\"","1x00xc0xa7xc0xa2",
                "5e010x'%bf'1\"%bf\"1%23","@@abcde",
                "1) and luna_sqli in (1","1%' and luna_sqli in (1) and '%'='","1' and luna_sqli in (1) and 'a'='a","1)) and luna_sqli in ((1",'1" and luna_sqli in (1) and "a"="a',"1') and luna_sqli in ('1",'1") and luna_sqli in ("1',
                "1) || luna_sqli in (1)--","1%' || luna_sqli in (1)--","1' || luna_sqli in (1)--","1)) || luna_sqli in (1)--", "1\" || luna_sqli in (1)--","1') || luna_sqli in (1)--","1\") || luna_sqli in (1)--",
                "1)+or+luna_sqli+in+(1)#","1%'+or+luna_sqli+in+(1)#","1'+or+luna_sqli+in+(1)#","1))+or+luna_sqli+in+(1)#","1\"+or+luna_sqli+in+(1)#","1')+or+luna_sqli+in+(1)#","1\")+or+luna_sqli+in+(1)#"]     #total 33

    rule_type = "err_sqli"

    argv = 0

    score = 0
    match_with = ""

    content_type_whitelist = []


    options = 0xF1

    def scan_main(self,luna_scan,luna_report,scan_type,urlencode_type):  
        for exp in self.exp_list:
            self.value_exp = exp
            body = luna_scan.scan_for_body(self,0,scan_type,urlencode_type)
            data = body
            m = re.search(r"(is\snull\sor\snot\san\sobject)|(Warning.*?mysql_)|(<b>Warning<\/b>:\s\spg_exec)|(\[Macromedia\]\[SQLServer\sJDBC\sDriver\]\[SQLServer\])|(Syntax\serror\s(.*)in\squery\sexpression\s)|(Data type mismatch in criteria expression)|(Could not update; currently locked by user '.*?' on machine '.*?')|\
                (Incorrect\ssyntax\snear\s'[^']*?')|(Microsoft\sJET\sDatabase\sEngine\s\([^\)]*?\)<br>Syntax\serror(.*)\sin\squery\sexpression\s)|(ORA-\d{4,5}:)|(Query\sfailed\:\sERROR\:)|(Syntax error: Missing operand after)|(System\.Data\.OleDb\.OleDbException\:)|(The string constant beginning with .*? does not have an ending string delimiter\.)|\
                (Unclosed\squotation\smark\safter\sthe\scharacter\sstring\s'[^']*?')|(Unknown column\s'[^']+'\sin\s'\w+\sclause')|(You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '[^']*')|(pg_query\(\)[:]*\squery\sfailed:\serror:\s)|(SQL error:.*no such column)|\
                (Conversion\sfailed\swhen\sconverting\sthe\svarchar\svalue\s'A'\sto\sdata\stype\sint)|(Call to a member function row_array() on a non-object in)|(Can't\sfind\srecord\sin)|(Column count doesn't match value count at row)|(ERROR: parser: parse error at or near)|(Error Executing Database Query)|(Error: 221 Invalid formula)|(Incorrect column name)|\
                (Incorrect\scolumn\sspecifier\sfor\scolumn)|(Incorrect\ssyntax\snear)|(Invalid\sSQL:)|(Invalid\scolumn\sname)|(Microsoft OLE DB Provider for ODBC Drivers)|(Microsoft OLE DB Provider for SQL Server)|(Must declare the scalar variable)|(ODBC Microsoft Access Driver)|(ODBC SQL Server Driver)|(PostgreSQL query failed)|(SQL command not properly ended)|\
                (SQLSTATE=42603)|(SQLite3::SQLException:)|(SQLite3::query(): Unable to prepare statement:)|(SqlException)|(Supplied argument is not a valid PostgreSQL result)|(Syntax error in string in query expression)|(Syntax error near\s.*?\sin the full-text search condition\s)|(Syntax error or access violation:)|(System\.Data\.SqlClient\.SqlException:)|\
                (Unclosed quotation mark before the character string)|(Unclosed quotation mark)|(Unexpected end of command in statement \[)|(Unknown system variable)|(Unknown table)|(You have an error in your SQL syntax)|(\): encountered SQLException \[)|(\[Microsoft\]\[ODBC Microsoft Access 97 Driver\])|(\[ODBC Informix driver\]\[Informix\])|\
                (\[SQL Server Driver\]\[SQL Server\]Line.*: Incorrect syntax near)|(column .* does not exist)|(internal error \[IBM\]\[CLI Driver\]\[DB2\/6000\])|(java\.sql\.SQLSyntaxErrorException)|(near\s[^:]+?:\ssyntax\serror)|(org.hibernate.QueryException)|(org.hibernate.exception.SQLGrammarException:)|\
                (pg_fetch_row() expects parameter 1 to be resource, boolean given in)",data)
            if m:
                
                self.match_with=m.group(0) 
                luna_output.vul_xss_output("[","err_sql found","]")
                luna_report.report_http(luna_scan,self)
                return True
            else:

                m = re.search(r"(supplied argument is not a valid MySQL result)|(syntax error at end of input)|(unexpected end of SQL command)|(unrecognized token:)|(unterminated quoted identifier at or near)|(unterminated quoted string at or near)|(Error:.*luna_sqli.*is\snot\sdefined)|\
                    (PostgreSQL.*ERROR)|(Warning.*\Wpg_)|(valid PostgreSQL result)|(Npgsql\.)|(ERROR:\s\ssyntax error at or near)|(org\.postgresql\.util\.PSQLException)|(Driver.* SQL[\-\_\ ]*Server)|(OLE DB.* SQL Server)|(\bSQL Server.*Driver)|(Warning.*mssql_)|(\bSQL Server.*[0-9a-fA-F]{8})|((?s)Exception.*\WSystem\.Data\.SqlClient\.)|\
                    ((?s)Exception.*\WRoadhouse\.Cms\.)|(Microsoft Access (\d+ )?Driver)|(JET Database Engine)|(Access Database Engine)|(Oracle error)|(Oracle.*Driver)|(Warning.*\Woci_)|(Warning.*\Wora_)|(CLI Driver.*DB2)|(DB2 SQL error)|(\bdb2_\w+\()|(Exception.*Informix)|(Dynamic SQL Error)|(Warning.*ibase_)|(SQLite/JDBCDriver)|\
                    (SQLite.Exception)|(System.Data.SQLite.SQLiteException)|(Warning.*sqlite_)|(Warning.*SQLite3::)|(\[SQLITE_ERROR\])|(SQL error.*POS([0-9]+))|(Warning.*maxdb)|((?i)Warning.*sybase)|(Sybase message)|(Sybase.*Server message.*)|(Warning.*ingres_)|(Ingres SQLSTATE)|(Ingres\W.*Driver)|(Exception (condition )?\d+. Transaction rollback.)|\
                    (org\.hsqldb\.jdbc)",data)

                if m:
                    self.match_with=m.group(0) 
                    luna_output.vul_xss_output("[","err_sql found","]")
                    luna_report.report_http(luna_scan,self)  
                    return True

                    

        return False
       

