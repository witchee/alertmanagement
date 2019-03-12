#!/usr/bin/env python
# -*-coding:utf-8-*-
import socket
import sys
import urllib2
import ConfigParser
import datetime
import httplib
import urllib
import cx_Oracle
import os
import time
import threading

# 解析grafana数据
def analysis_grafana():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', 7000))
        # s.bind(('127.0.0.1', 8000))
        # s.bind(('192.168.20.1', 6666))
        s.listen(10)
    except socket.error as msg:
        print(msg)
        sys.exit(1)
    print("Wait for Connection..................")
    reload(sys)
    sys.setdefaultencoding('utf8')
    while True:
        sock, addr = s.accept()
        buf = sock.recv(4096)
        buf = str(buf.decode('utf-8'))
        sourcename = buf.split("\r\n")[2].split(" ")[1]
        sourceid = search_source_id(sourcename)
        alter = buf[buf.find("{"):]
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(str(now)+alter)
        global null
        null = ''
        dic = eval(alter)
        query = dic["evalMatches"]
        alertname = dic["ruleName"]
        alertname = str(alertname).replace("'", "")
        messagearray = {}
        for num in range(len(query)):
            alertdetail = query[num]["metric"]
            alertdetail = str(alertdetail).replace("'", "")
            value = str(round(query[num]["value"], 2))
            alertlogdetail = alertdetail + " " + value
            save_alertlog(alertname, alertlogdetail, sourceid)
            if "笔数" in alertname:
                # 率和笔数需同时出现才发送报警
                newalertdetail = alertdetail.replace("率", "").replace("笔数", "")
                if alter.count(newalertdetail) > 1:
                    messagearray = check_alert(sourceid, alertname, alertdetail, value, messagearray)
            else:
                messagearray = check_alert(sourceid, alertname, alertdetail, value, messagearray)
            keys = list(messagearray.keys())
            for key in keys:
                # 字数大于500发送短信
                if len(messagearray[key]) > 500:
                    send_alert_message(key, messagearray[key])
                    del messagearray[key]
        for key in messagearray:
            send_alert_message(key, messagearray[key])


# 判断报警
def check_alert(sourceid, alertname, alertdetail, value, messagearray):
    if in_monitor_time(sourceid) and not in_maintenance_time(sourceid) and not in_ignore(sourceid, alertdetail) or special_rule(sourceid, alertdetail):
        new_alert_id = is_new_alert(alertname, alertdetail, sourceid)
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        message = alertdetail + " " + value
        # 如果是新报警
        if new_alert_id == -1:
            # 发送报警
            tels = get_users(sourceid, alertdetail)
            for i in range(len(tels)):
                if str(tels[i]) in messagearray.keys():
                    count = messagearray[str(tels[i])].count("详细") + 1
                    messagearray[str(tels[i])] += "\n详细" + str(count) + ":" + message
                else:
                    messagearray[str(tels[i])] = "监控报警\n" + "时间:" + now + "\n" + "报警名:" + alertname + "\n详细1:" + message
            save_alert(alertname, alertdetail, sourceid, value)
        else:
            update_last_alert(new_alert_id)
            if alert_again(new_alert_id, sourceid):
                # 发送重发报警
                tels = get_users(sourceid, alertdetail)
                for i in range(len(tels)):
                    if str(tels[i]) in messagearray.keys():
                        count = messagearray[str(tels[i])].count("详细") + 1
                        messagearray[str(tels[i])] += "\n详细" + str(count) + ":" + message
                    else:
                        messagearray[str(tels[i])] = "监控报警\n" + "时间:" + now + "\n" + "报警名:" + alertname + "\n详细1:" + message
                update_alert(new_alert_id)
    return messagearray


# 获取需要发送短信的用户，返回手机号列表
def get_users(sourceid, detail):
    conn = connect_oracle()
    c = conn.cursor()
    x = c.execute("select source_group_id from tb_source where source_id=" + str(sourceid))
    rs = x.fetchone()
    source_group_id = str(rs[0])
    x = c.execute("select distinct a.user_id from tb_usergroup_user a,tb_user_source b where b.user_id = a.user_group_id and b.source_id = '"+source_group_id+"' ")
    rs = x.fetchall()
    c.close()
    conn.close()
    users = []
    for i in range(len(rs)):
        tel = get_user_telephone(rs[i][0])
        users.append(tel)
    specialusers = in_special(detail)
    for i in range(len(specialusers)):
        tel = get_user_telephone(specialusers[i])
        users.append(tel)
    return users


# 对特殊规则进行过滤，报警返回true，不报警返回false
def special_rule(sourceid, detail):
    conn = connect_oracle()
    c = conn.cursor()
    x = c.execute("select SPECIAL_NAME,MONITOR_STARTTIME,MONITOR_ENDTIME,ALERT_STATUS from tb_specialrule where source_id=" + str(sourceid))
    rs = x.fetchall()
    c.close()
    conn.close()
    for rss in range(len(rs)):
        specialname = rs[rss][0]
        if specialname in detail:
            alert_status = rs[rss][3]
            if alert_status == 0:
                return False
            else:
                starttime = rs[rss][1]
                endtime = rs[rss][2]
                now = datetime.datetime.now().strftime('%H:%M')
                if now >= starttime and now <= endtime:
                    return True
    return False


# 根据user_id获取用户手机号
def get_user_telephone(user_id):
    conn = connect_oracle()
    c = conn.cursor()
    x = c.execute("select telephone from tb_userinfo where user_id='" + str(user_id) + "'")
    rs = x.fetchone()
    tel = rs[0]
    c.close()
    conn.close()
    return tel


# 发送短信
def send_alert_message(tel, message):
    url = 'http://163.10.10.185:10080/handapp_upmp/wl/SmsServlet?phoneNo=%s&sms=%s&code=utf-8'
    newurl = url % (tel, message)
    urllib.urlopen(newurl.encode('utf-8'))
    print(newurl)


# 是否要重发
def alert_again(alertid, sourceid):
    conn = connect_oracle()
    c = conn.cursor()
    x = c.execute("select silent_time from tb_source where source_id=" + str(sourceid))
    rs = x.fetchone()
    silenttime = datetime.datetime.strptime(str(rs[0]), '%H:%M')
    x = c.execute("select alert_time from tb_alert where alert_id=" + str(alertid))
    rs = x.fetchone()
    last_alert_time = datetime.datetime.strptime(str(rs[0]), '%Y-%m-%d %H:%M:%S')
    c.close()
    conn.close()
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    nowtime = datetime.datetime.strptime(now, '%Y-%m-%d %H:%M:%S')
    timedifference = nowtime - last_alert_time
    if "day" in str(timedifference):
        return True
    else:
        timedifference = datetime.datetime.strptime(str(timedifference), '%H:%M:%S')
        if timedifference >= silenttime:
            return True
        else:
            return False


# 存入报警日志表
def save_alertlog(alertname, alertdetail, sourceid):
    conn = connect_oracle()
    c = conn.cursor()
    alertname = check_input(alertname, 500)
    alertdetail = check_input(alertdetail, 500)
    c.execute("insert into tb_alertlog(alertlog_id,source_id,alert_time,alert_name,alert_detail) values(SEQ_ON_ALERTLOG.nextval,'"+str(sourceid)+"',sysdate,'"+alertname+"', '"+alertdetail+"')")
    conn.commit()
    c.close()
    conn.close()


# 存入报警表
def save_alert(alertname, alertdetail, sourceid, value):
    conn = connect_oracle()
    c = conn.cursor()
    alertname = check_input(alertname, 500)
    alertdetail = check_input(alertdetail, 500)
    value = check_input(value, 500)
    c.execute("insert into tb_alert(alert_id,source_id,alert_time,alert_name,alert_detail,LAST_ALERT_TIME,ALERT_STATUS,ALERT_VALUE) values(SEQ_ON_ALERT.nextval,'" + str(sourceid) + "',sysdate,'" + alertname + "','" + alertdetail + "',sysdate,1,'"+str(value)+"')")
    conn.commit()
    c.close()
    conn.close()


# 更新报警表发送短信时间
def update_alert(alertid):
    conn = connect_oracle()
    c = conn.cursor()
    c.execute("update tb_alert set ALERT_TIME=sysdate where alert_id='"+str(alertid)+"'")
    conn.commit()
    c.close()
    conn.close()


# 更新报警表最后报警时间
def update_last_alert(alertid):
    conn = connect_oracle()
    c = conn.cursor()
    c.execute("update tb_alert set LAST_ALERT_TIME=sysdate where alert_id='"+str(alertid)+"'")
    conn.commit()
    c.close()
    conn.close()


# 判断是否在监控时间
def in_monitor_time(sourceid):
    conn = connect_oracle()
    c = conn.cursor()
    x = c.execute("select monitor_starttime,monitor_endtime from tb_source where source_id="+str(sourceid))
    rs = x.fetchone()
    if rs[0] == None:
        x = c.execute("select monitor_starttime,monitor_endtime from tb_source where source_id=0")
        rs = x.fetchone()
    starttime = rs[0]
    endtime = rs[1]
    c.close()
    conn.close()
    now = datetime.datetime.now().strftime('%H:%M')
    if now >= starttime and now <= endtime:
        return True
    else:
        return False


# 过滤输入长度
def check_input(input, length):
    if len(input) > length:
        input = input[0:length]
    return input


# 判断是否在维护时间
def in_maintenance_time(sourceid):
    conn = connect_oracle()
    c = conn.cursor()
    x = c.execute("select maintenance_starttime,maintenance_endtime from tb_maintenance where source_id=" + str(sourceid) + " and maintenance_status=1")
    rss = x.fetchall()
    c.close()
    conn.close()
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    flag = 1
    for rs in range(len(rss)):
        starttime = rss[rs][0]
        endtime = rss[rs][1]
        if now >= starttime and now < endtime:
            flag = 0
            break
    if flag == 1:
        return False
    else:
        return True


# 判断是否是忽略字段
def in_ignore(sourceid, detail):
    conn = connect_oracle()
    c = conn.cursor()
    flag = 1
    x = c.execute("select ignore_name from tb_ignore where source_id = " + str(sourceid) + " or source_id = 0")
    rss = x.fetchall()
    c.close()
    conn.close()
    for rs in range(len(rss)):
        ignore_name = rss[rs][0]
        if ignore_name in detail:
            flag = 0
            break
    if flag == 1:
        return False
    else:
        return True


# 判断是否是特殊字段，返回user_id列表
def in_special(detail):
    conn = connect_oracle()
    c = conn.cursor()
    x = c.execute("select user_id,special_name from tb_special")
    rss = x.fetchall()
    c.close()
    conn.close()
    useridlist = []
    for rs in range(len(rss)):
        special_name = rss[rs][1]
        if special_name in detail:
            useridlist.append(rss[rs][0])
    return useridlist


# 连接数据库
def connect_oracle():
    # conn = cx_Oracle.connect('qrcodedev', 'qrcodedev', '163.10.10.135/oratest')
    conn = cx_Oracle.connect('qrcodeprod', 'e1&cNHaz', '163.10.10.136/qrcdb', threaded=True)
    return conn


# 判断是否是新报警，是返回-1，不是返回alert_id
def is_new_alert(alertname, alertdetail, sourceid):
    conn = connect_oracle()
    c = conn.cursor()
    x = c.execute("select alert_id from tb_alert where ALERT_STATUS=1 and source_id='"+str(sourceid)+"' and alert_name='"+alertname+"' and alert_detail='"+alertdetail+"'")
    rss = x.fetchone()
    c.close()
    conn.close()
    if rss == None:
        return -1
    else:
        return rss[0]


# 根据source_name找到source_id
def search_source_id(sourcename):
    conn = connect_oracle()
    c = conn.cursor()
    x = c.execute("select source_id from tb_source where source_name='"+sourcename+"'")
    rss = x.fetchone()
    c.close()
    conn.close()
    return rss[0]


# 获取恢复时间
def get_recovery_time(sourceid, detail):
    conn = connect_oracle()
    c = conn.cursor()
    x = c.execute("select recovery_time from tb_source where SOURCE_ID=" + str(sourceid))
    rs = x.fetchone()
    recovery_time = datetime.datetime.strptime(rs[0], "%H:%M")
    x = c.execute("select SPECIAL_NAME,RECOVERY_TIME from tb_specialrule where source_id=" + str(sourceid))
    rs = x.fetchall()
    c.close()
    conn.close()
    for rss in range(len(rs)):
        specialname = rs[rss][0]
        if specialname in detail:
            recovery_time = datetime.datetime.strptime(rs[rss][1], "%H:%M")
            break
    return recovery_time


# 发送恢复短信
def send_recovery():
    reload(sys)
    sys.setdefaultencoding('utf8')
    while True:
        conn = connect_oracle()
        c = conn.cursor()
        x = c.execute("select ALERT_ID,LAST_ALERT_TIME,SOURCE_ID,ALERT_DETAIL from tb_alert where ALERT_STATUS=1")
        rss = x.fetchall()
        c.close()
        conn.close()
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        nowtime = datetime.datetime.strptime(now, '%Y-%m-%d %H:%M:%S')
        messagearray = {}
        # 循环报警表中未恢复的报警
        for rs in range(len(rss)):
            last_alert_time = datetime.datetime.strptime(str(rss[rs][1]), '%Y-%m-%d %H:%M:%S')
            timedifference = nowtime - last_alert_time
            if "-1 day" in str(timedifference):
                timedifference = datetime.datetime.strptime("00:00:00", '%H:%M:%S')
            else:
                timedifference = datetime.datetime.strptime(str(timedifference), '%H:%M:%S')
            noalerttime = get_recovery_time(rss[rs][2], rss[rs][3])
            if timedifference >= noalerttime:
                update_alert_status(rss[rs][0])
                message = get_alert_message(rss[rs][0])
                message = message.replace("警告", "恢复")
                tels = get_users(rss[rs][2], rss[rs][3])
                for i in range(len(tels)):
                    if str(tels[i]) in messagearray.keys():
                        count = messagearray[str(tels[i])].count("报警名") + 1
                        messagearray[str(tels[i])] += "\n" + "报警名" + str(count) + ":" + message
                    else:
                        messagearray[str(tels[i])] = "恢复提醒\n" + "时间:" + now + "\n" + "报警名1:" + message
        for key in messagearray:
            send_alert_message(key, messagearray[key])
        time.sleep(10)


# 获取报警信息
def get_alert_message(alert_id):
    conn = connect_oracle()
    c = conn.cursor()
    x = c.execute("select RECOVERY_TIME,ALERT_NAME,ALERT_DETAIL,ALERT_VALUE from tb_alert where alert_id=" + str(alert_id))
    rs = x.fetchone()
    message = str(rs[1]) + "\n" + "详细:" + str(rs[2])
    c.close()
    conn.close()
    return message


# 修改报警状态
def update_alert_status(alert_id):
    conn = connect_oracle()
    c = conn.cursor()
    c.execute("update tb_alert set ALERT_STATUS=0,RECOVERY_TIME=sysdate where alert_id=" + str(alert_id))
    conn.commit()
    c.close()
    conn.close()


# 循环维护表判断是否结束
def change_maintenance():
    while True:
        conn = connect_oracle()
        c = conn.cursor()
        x = c.execute("select maintenance_id,maintenance_endtime from tb_maintenance")
        rss = x.fetchall()
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
        for rs in range(len(rss)):
            id = rss[rs][0]
            endtime = rss[rs][1]
            if now >= endtime:
                c.execute("update TB_MAINTENANCE set MAINTENANCE_STATUS=0 where MAINTENANCE_ID=" + str(id))
                conn.commit()
        c.close()
        conn.close()
        time.sleep(30)


threads = []
t1 = threading.Thread(target=analysis_grafana)
threads.append(t1)
t2 = threading.Thread(target=send_recovery)
threads.append(t2)
t3 = threading.Thread(target=change_maintenance)
threads.append(t3)


if __name__ == '__main__':
    for t in threads:
        t.setDaemon(True)
        t.start()
    t.join()


