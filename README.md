# dnspod-httpdns-proxy
使用 dnspod httpdns 来防止劫持的一个小轮子，仅支持 A IN 标准查询  
支持提交本地IP来应对穿透造成的解析问题  
提供应答过滤功能，httpdns应答的 __第一个__ IP不在所填的IP段内的话就无应答  
## 使用  
__请配合其他强壮的DNS软件共同使用__  
## 需求  
Python3.5+  
## 配置  
修改文件```udpdnsserver(addr='0.0.0.0')```来更改本地端口，可选项```addr='127.0.0.1', port=53```  
修改```httpdns(ednsip='211.138.113.115')```来更改提交的IP和应答默认TTL，可选项```ednsip='211.138.113.115', ttl=300```  
