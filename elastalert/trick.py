#coding
import re
alert_text='''应用系统编号：BS-449
规则名：AVPZX1_5min_15_freq
查询条件：[[{'bool': {'must': [{'range': {'thread_id': {'gte': 30}}}]}}]]
命中记录数：246681
合并事件数：246681
当前值：55072
主机：MDCBDBC6
ip：197.0.128.102
最近发生时间：2020-07-03T14:35:45.089000+08:00
时间窗口：0:00:01
ES_id：1GxjE3MB-rFxBoPSlvDx'''


text_list = [re.sub(r'：', ':', line.strip()).strip()for line in re.split(r'\n',alert_text)]
print(text_list)


