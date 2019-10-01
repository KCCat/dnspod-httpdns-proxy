# dnspod-httpdns-proxy
使用 dnspod httpdns 来防止劫持的一个小轮子，仅支持 A IN 标准查询  
支持提交本地IP来应对穿透造成的解析问题  
使用 `asyncio` 模块重写需要 `asyncdns.py` 即可,读取 `china_ip_list.txt` 来查寻 ip 归属国  
## 使用  
__请配合其他强壮的DNS软件共同使用__  
## 需求  
Python3.7+  
## 配置  

参考文件内注释  
