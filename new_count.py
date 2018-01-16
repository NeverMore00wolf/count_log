#!/usr/bin/env python
#coding=utf-8
'''
@author:dingzenghua,nevermore
@date:2017-09-27
'''
import time,re,os,IPy
from datetime import datetime
from IPy import IP
time_start=time.time()
def c_attack(file):
    f = open(file, 'r')
    f.seek(0, 0)
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line
def get_inside_ip():
    inside_ip = []
    for line in open("/root/inside_ip.txt"):
        line=line.strip('\n')
        inside_ip.append(line)
    get_ip = inside_ip[0].split(',')
#    for i in range(len(get_ip))
#       ipaddress = get_ip[i]
#       turn_ip = []
#       turn_ip = IP(ipaddress).strNormal(3).split('-')
#       start_ip = turn_ip[0]
#       end_ip = turn_ip[1]
    return get_ip

def getTimeDiff(timeStra,timeStrb):
    if timeStra>=timeStrb:
       return 0
    ta = time.strptime(timeStra, "%Y-%m-%d %H:%M:%S")
    tb = time.strptime(timeStrb, "%Y-%m-%d %H:%M:%S")
    uTime_start = time.mktime(time.strptime(timeStra, "%Y-%m-%d %H:%M:%S"))
    uTime_end = time.mktime(time.strptime(timeStrb, "%Y-%m-%d %H:%M:%S"))
    y,m,d,H,M,S = ta[0:6]
    dataTimea=datetime(y,m,d,H,M,S)
    y,m,d,H,M,S = tb[0:6]
    dataTimeb=datetime(y,m,d,H,M,S)
    secondsDiff=(dataTimeb-dataTimea).total_seconds()        
#两者相加得转换成分钟的时间差
    minutesDiff=round(secondsDiff/60,1)
#重组时间格式
    ta_turn = time.strftime("%m/%d/%Y-%H:%M:%S",ta)
    tb_turn = time.strftime("%m/%d/%Y-%H:%M:%S",tb)
    return int(uTime_start),int(uTime_end),secondsDiff,minutesDiff,ta_turn,tb_turn

def handle_line(lines):
    timeStra = raw_input("please input start time(ex:2018-05-22 10:23:00):")
    timeStrb = raw_input("please input start time(ex:2018-05-22 10:23:00):")
#    times=()
    unixTime_s,unixTime_e,times1,times2,start_time_turn,end_time_turn = getTimeDiff(timeStra,timeStrb)
    inside_ip = []
    inside_ip = get_inside_ip()
    print inside_ip
    attack_type = []
    attacked_type = []
    c_source_ip = {}
    c_source_ip_list = []
    c_destnation_ip = {}
    c_destnation_ip_list = []
    attack_suspict = {}
    attack_taget = {}
    attacked_suspict = {}
    attacked_taget = {}
    line_count = 0
    line_count_ed = 0
    t = 0
    count = []
    counted = []
    year = 0
    month = 0
    day = 0
    hour = 0
    minute = 0
    second = 0
    old_time = ""
    begin_time = ""
    TCP_count_attack = 0
    UDP_count_attack = 0
    ICMP_count_attack = 0
    TCP_count_attacked = 0
    UDP_count_attacked = 0
    ICMP_count_attacked = 0
    for line in lines:
        t = t + 1 
#	r_time_start=line.find(start_time_turn)
#	r_time_end=line.find(end_time_turn)
        print inside_ip
	print unixTime_s
        print unixTime_e
	print "查询时间间隔为" + str(times1) + "分， " + str(times2) + "秒"
        print start_time_turn
	print end_time_turn
        print t
        if not line.strip():
          continue
	start_time = str(line.split(" ")[0])
        year = start_time.split("-")[0].split("/")[2]
        month = start_time.split("-")[0].split("/")[0]
        day = start_time.split("-")[0].split("/")[1]
        hour = start_time.split("-")[1].split(":")[0]
        minute = start_time.split("-")[1].split(":")[1]
        second = start_time.split("-")[1].split(":")[2].split(".")[0]
        milsecond = start_time.split("-")[1].split(":")[2].split(".")[1]
        o_time = year + '-' + month + '-' + day + " " + hour + ':' + minute + ':' + second
        u_line_time = int(time.mktime(time.strptime(o_time, '%Y-%m-%d %H:%M:%S')))
	print int(u_line_time)
	if unixTime_s > u_line_time:
	   continue
	elif unixTime_e < u_line_time:
           break  
	else:
	   if line_count == 0:
               print o_time
               begin_time = datetime.strptime(o_time, '%Y-%m-%d %H:%M:%S')
               print "the start time is at : "
               print year + "年" + month + "月" + day + "日 " + hour + ":" + minute + ":" + second + "." + milsecond
	       print '=' * 50
            #old_time = time.mktime(time.strptime(o_time,"%Y-%m-%d %H:%M:%S"))
           regex = r'Classification:\s[\w\-\s]{1,}[\]]'
	   protocal = '\{(TCP|UDP|ICMP)\}'
#********************************************************************************************
	   source_ip = '(\}\s)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
           destnation_ip = '(\-\>\s)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
           pattern1 = re.compile(regex)
	   pattern2 = re.compile(protocal)
	   pattern3 = re.compile(source_ip)
           pattern4 = re.compile(destnation_ip)
           if not len(pattern3.findall(line)):
              continue
	   o_source_ip = pattern3.findall(line)[0][1]
           if not len(pattern4.findall(line)):
              continue
           o_destnation_ip = pattern4.findall(line)[0][1]
           lalal = pattern2.findall(line)[0]
	   print o_destnation_ip
           print o_source_ip
#**********************************************************************
           ip_num = 0
           for ip_tag in range(len(inside_ip)):
              if IP(o_source_ip).overlaps(inside_ip[ip_tag]):
	         break
              else:
                 ip_num = ip_num +1
                 continue
           if ip_num != len(inside_ip):
              print "攻击方"
              if len(str(attack_suspict.has_key(o_source_ip)))==5:
                 attack_suspict[o_source_ip] = 1
              elif len(str(attack_suspict.has_key(o_source_ip)))==4:
                 attack_suspict[o_source_ip] += 1
              if len(str(attack_taget.has_key(o_destnation_ip)))==5:
                 attack_taget[o_destnation_ip] = 1
              elif len(str(attack_taget.has_key(o_destnation_ip)))==4:
                 attack_taget[o_destnation_ip] += 1
              if pattern1.findall(line):
               classification = pattern1.findall(line)[0]
               type = classification[16:len(classification)-1]
               line_count += 1
               num_index = 0
               if type not in attack_type:
                   attack_type.append(type)
                   count.append(1)
               elif type in attack_type:
                   num_index = attack_type.index(type)
                   count[num_index] += 1
              if lalal == 'UDP':
                 UDP_count_attacked += 1
              if lalal == 'TCP':
                 TCP_count_attacked += 1
              if lalal == 'ICMP':
                 ICMP_count_attacked +=1
           elif ip_num == len(inside_ip):
              print "被攻击方"
              if len(str(attacked_suspict.has_key(o_source_ip)))==5:
                 attacked_suspict[o_source_ip] = 1
              elif len(str(attacked_suspict.has_key(o_source_ip)))==4:
                 attacked_suspict[o_source_ip] += 1
              if len(str(attacked_taget.has_key(o_destnation_ip)))==5:
                 attacked_taget[o_destnation_ip] = 1
              elif len(str(attacked_taget.has_key(o_destnation_ip)))==4:
                 attacked_taget[o_destnation_ip] += 1
              if pattern1.findall(line):
               classification = pattern1.findall(line)[0]
               type = classification[16:len(classification)-1]
               line_count_ed += 1
               num_index_ed = 0
               if type not in attacked_type:
                   attacked_type.append(type)
                   counted.append(1)
               elif type in attacked_type:
                   num_index = attacked_type.index(type)
                   counted[num_index] += 1
              if lalal == 'UDP':
                 UDP_count_attack += 1
              if lalal == 'TCP':
                 TCP_count_attack += 1
              if lalal == 'ICMP':
                 ICMP_count_attack +=1
           if pattern1.findall(line):
#               classification = pattern1.findall(line)[0]
#               type = classification[16:len(classification)-1]
#               line_count += 1
#               num_index = 0
#               if type not in attack_type:
#                   attack_type.append(type)
#                   count.append(1)
#               elif type in attack_type:
#                   num_index = attack_type.index(type)
#                   count[num_index] += 1
#**********************************************************************
#	    print c_source_ip.has_key(o_source_ip)
#            value1 = c_source_ip.has_key(o_source_ip)
#	    print len(str(value1))
	       if len(str(c_source_ip.has_key(o_source_ip)))==5:
		   c_source_ip[o_source_ip] = 1
	       elif len(str(c_source_ip.has_key(o_source_ip)))==4:
		   c_source_ip[o_source_ip] += 1
               if len(str(c_destnation_ip.has_key(o_destnation_ip)))==5:
                   c_destnation_ip[o_destnation_ip] = 1
               elif len(str(c_destnation_ip.has_key(o_destnation_ip)))==4:
                   c_destnation_ip[o_destnation_ip] += 1
#            print '\n*********************IP**********************\n'
#            print 'source_ip_count\n'
#	    print sorted(c_source_ip.items(), lambda x, y: cmp(x[1], y[1]), reverse=True)
#            print 'destnation_ip_ count\n'
#	    print sorted(c_destnation_ip.items(), lambda x, y: cmp(x[1], y[1]), reverse=True)
#	    print '\n*********************************************\n'
	       c_source_ip_list = sorted(c_source_ip.items(), lambda x, y: cmp(x[1], y[1]), reverse=True)
	       c_destnation_ip_list = sorted(c_destnation_ip.items(), lambda x, y: cmp(x[1], y[1]), reverse=True)
               attack_suspict_list = sorted(attack_suspict.items(), lambda x, y: cmp(x[1], y[1]), reverse=True)
	       attack_taget_list = sorted(attack_taget.items(), lambda x, y: cmp(x[1], y[1]), reverse=True)
               attacked_suspict_list = sorted(attacked_suspict.items(), lambda x, y: cmp(x[1], y[1]), reverse=True)
               attacked_taget_list = sorted(attacked_taget.items(), lambda x, y: cmp(x[1], y[1]), reverse=True)
#输出排名前十的源ip地址，以及统计计数
#	    print len(c_source_ip_list)
               c = 1
               new_time = year + '-' + month + '-' + day + " " + hour + ':' + minute + ':' + second
               print "当前时间是： " + year + "年" + month + "月" + day + "日 " + hour + ":" + minute + ":" + second + "." + milsecond
               s_date = (datetime.strptime(new_time, '%Y-%m-%d %H:%M:%S') - begin_time)
               hours = s_date.seconds / 3600.0 + s_date.days * 24
               if hours <= 1:
                   hours = 1
               else:
                   hours = round(hours)
#	    print len(c_source_ip_list)
	       print '\n*********************基于源目IP进行统计**********************\n'
	       for c in range(1,11):
	          if len(c_source_ip_list)>=10 and len(c_destnation_ip_list)>=10:
                     print '源IP第' + str(c) + '名' + str(c_source_ip_list[c-1]) + '            ' + '目的IP第' + str(c) + '名' + str(c_destnation_ip_list[c-1]) + '\n'
                  else:
    		     break

               print '\n********************基于页面展示统计：攻击者**********************\n'
               for c_web in range(1,11):
                  if len(attack_suspict_list)>=10 and len(attack_taget_list)>=10:
                     print '嫌疑犯第' + str(c_web) + '名' + str(attack_suspict_list[c_web-1]) + '            ' + '目的第' + str(c_web) + '名' + str(attack_taget_list[c_web-1]) + '\n'
                  else:
                     break
               print "UDP" + str(UDP_count_attack)
               print "TCP" + str(TCP_count_attack)
               print "ICMP" + str(ICMP_count_attack)
               print "攻击者次数：" + str(line_count)
               print r"截止到上述时间，时间间隔为：" + str(hour) +"小时，共计检测到攻击类别为： " + str(len(attack_type)) + ' 类'
            #'This is a \033[1;35m test \033[0m!'
               for i in range(len(count)):
                   if count[i] >= 10:
                      if i == num_index:
                         print '\033[1;31;40m \t总计：\033[0m' + str(count[i]) + "\033[1;31;40m \t 频率是：\033[0m" + str(round(count[i] / hours,2)) + "\033[1;31;40m 次/小时 -------> \033[0m" + attack_type[i] + '\033[0m'
                      else:
                          print "\t总计：" + str(count[i]) + "\t 频率是：" + str(round(count[i] / hours,2)) + "次/小时 ------> " + attack_type[i]
                   else:
                       if i == num_index:
                          print '\033[1;31;40m \t总计：\033[0m' + str(count[i]) + "\033[1;31;40m \t 频率是：\033[0m" + str(round(count[i] / hours,2)) + "\033[1;31;40m 次/小时------> \033[0m" + attack_type[i] + '\033[0m'
                       else:
                           print "\t总计：" + str(count[i]) + "\t\t 频率是：" + str(round(count[i] / hours,2)) + '次/小时 ------> ' + attack_type[i]
               print "*" * 100



               print '\n********************基于页面展示统计：被攻击者**********************\n'
               for t_web in range(1,11):
                  if len(attacked_suspict_list)>=10 and len(attacked_taget_list)>=10:
                     print '嫌疑犯第' + str(t_web) + '名' + str(attacked_suspict_list[t_web-1]) + '            ' + '目的第' + str(t_web) + '名' + str(attacked_taget_list[t_web-1]) + '\n'
                  else:
                     break
               print "UDP" +str(UDP_count_attacked)
               print "TCP" + str(TCP_count_attacked)
               print "ICMP" + str(ICMP_count_attacked)
               print "被攻击次数：" + str(line_count_ed)
               print r"截止到上述时间，时间间隔为：" + str(hour) +"小时，共计检测到攻击类别为： " + str(len(attacked_type)) + ' 类'
            #'This is a \033[1;35m test \033[0m!'
               for i in range(len(counted)):
                   if counted[i] >= 10:
                      if i == num_index_ed:
                         print '\033[1;31;40m \t总计：\033[0m' + str(counted[i]) + "\033[1;31;40m \t 频率是：\033[0m" + str(round(counted[i] / hours,2)) + "\033[1;31;40m 次/小时 ------> \033[0m" + attacked_type[i] + '\033[0m'
                      else:
                          print "\t总计：" + str(counted[i]) + "\t 频率是：" + str(round(counted[i] / hours,2)) + "次/小时 ------> " + attacked_type[i]
                   else:
                       if i == num_index_ed:
                          print '\033[1;31;40m \t总计：\033[0m' + str(counted[i]) + "\033[1;31;40m \t 频率是：\033[0m" + str(round(counted[i] / hours,2)) + "\033[1;31;40m 次/小时 ------> \033[0m" + attacked_type[i] + '\033[0m'
                       else:
                           print "\t总计：" + str(counted[i]) + "\t\t 频率是：" + str(round(counted[i] / hours,2)) + '次/小时 ------> ' + attacked_type[i]
               print "*" * 100
               print '\n*********************************************\n'

#	    print '*************66*****'
#	    for v,k in c_source_ip.items():
#	        print('{v}:{k}'.format(v = v, k = k))
#	    print '*************66*****'
#	    if o_source_ip not in c_source_ip:
#		c_source_ip.append(o_source_ip)
#	    elif o_siyrce_ip in c_source_ip:
#		count_s_ip_tag = c_source_ip.index(o_source_ip)
#                count_source_ip[count_s_ip_tag] +=1
#**********************************************************************
            # n_time = time.time()
            # now_time = str(datetime.fromtimestamp(n_time))
            # new_year = now_time.split(" ")[0].split("-")[0]
            # new_month = now_time.split(" ")[0].split('-')[1]
            # new_day = now_time.split(" ")[0].split("-")[2]
            # new_hour = now_time.split(" ")[1].split(":")[0]
            # new_minute = now_time.split(" ")[1].split(":")[1]
            # new_second = now_time.split(" ")[1].split(":")[2].split(".")[0]
#*********************************************************************************           
	       time_end=time.time()
               print '\n*****************\n'
               print "程序运行时间：" + str(time_end-time_start) + "秒"
	       print "程序开始时间：" + str(begin_time)
               print '\n*****************\n'
#************************************************************************************
#	       new_time = year + '-' + month + '-' + day + " " + hour + ':' + minute + ':' + second
#               print "当前时间是： " + year + "年" + month + "月" + day + "日 " + hour + ":" + minute + ":" + second + "." + milsecond
#               s_date = (datetime.strptime(new_time, '%Y-%m-%d %H:%M:%S') - begin_time)
#               hours = s_date.seconds / 3600.0 + s_date.days * 24
#               if hours <= 1:
#                   hours = 1
#               else:
#                   hours = round(hours)
               print r"截止到上述时间，时间间隔为：" + str(hour) +"小时，共计检测到攻击类别为： " + str(len(attack_type)) + ' 类'
	    #'This is a \033[1;35m test \033[0m!'
               for i in range(len(count)):
		   if count[i] >= 10:
                      if i == num_index:
                         print '\033[1;31;40m \t总计：\033[0m' + str(count[i]) + "\033[1;31;40m \t 频率是：\033[0m" + str(round(count[i] / hours,2)) + "\033[1;31;40m 次/小时 ------> \033[0m" + attack_type[i] + '\033[0m'
                      else:
                          print "\t总计：" + str(count[i]) + "\t 频率是：" + str(round(count[i] / hours,2)) + "次/小时 ------> " + attack_type[i]
                   else:
                       if i == num_index:
                          print '\033[1;31;40m \t总计：\033[0m' + str(count[i]) + "\033[1;31;40m \t 频率是：\033[0m" + str(round(count[i] / hours,2)) + "\033[1;31;40m 次/小时 ------> \033[0m" + attack_type[i] + '\033[0m'
                       else:
                           print "\t总计：" + str(count[i]) + "\t\t 频率是：" + str(round(count[i] / hours,2)) + '次/小时 ------> ' + attack_type[i]
               print "*" * 100

if __name__ == '__main__':
#    if os.path.exists('/home/log/isec/fast.log'):
    if os.path.exists('/home/log/isec/fast.log'):
#/home/log/isec/fast.log
#        handle_line(c_attack('/home/log/isec/fast.log'))
       handle_line(c_attack('/home/log/isec/fast.log'))
	
    else:
        print "the file fast.log is not existed...please check it !!!"
        print "*" * 30
