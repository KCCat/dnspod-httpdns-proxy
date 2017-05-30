#!/usr/bin/env python3
# encoding: utf-8

#dnspod httpdns proxy
#Only supported TYPE A Class IN Standard query

import urllib.request, socket

class httpdns(object):

    def __init__(self, ednsip, ttl=300):
        self.domain=''
        self.ednsip=ednsip
        self.ANCOUNT=0
        self.TTL=(ttl).to_bytes(4, byteorder='big')
        self.answer=b''

    def labelsTOdomain(self, domain):
    # b'\x03www\x06google\x03com\x00' -> 'www.google.com'
        i=0
        r=[]
        for x in domain:
            if i == 0:
                i=x
                x=46 #ord('.') -> 46
            else:
                i=i-1
            r.append(x)
        return bytes(r)[1:-1].decode('ASCII')

    def httprequest(self, Qdata):
        self.domain=self.labelsTOdomain(Qdata[:-4])
        try:
            Rdata_tmp=urllib.request.urlopen('http://119.29.29.29/d?dn=%s&ip=%s' % (self.domain,self.ednsip)).read().split(b';')
            # 119.29.29.29, 119.28.28.28, 182.254.116.116, 182.254.118.118
        except OSError:
            print('httprequest error')
            return 0, Qdata, b''
        try:
            Rdata=[bytes([int(y) for y in x.split(b'.')]) for x in Rdata_tmp]
        except ValueError:
            print('non answer')
            return 0, Qdata, b''
        return len(Rdata), b''.join([b'\xc0\x0c\x00\x01\x00\x01',self.TTL, b'\x00\x04']).join([Qdata, *Rdata]), Rdata_tmp

class iptool(object): #prefixmatch

    def __init__(self):
        self.prefix=[ #china mobile, alicloud, tencentcloud
            '36.128.0.0/10',
            '39.128.0.0/10',
            '43.239.172.0/22',
            '43.251.244.0/22',
            '45.121.68.0/22',
            '45.121.72.0/22',
            '45.121.172.0/22',
            '45.121.176.0/22',
            '45.122.96.0/21',
            '45.123.152.0/22',
            '45.124.36.0/22',
            '45.125.24.0/22',
            '103.20.112.0/22',
            '103.21.176.0/22',
            '103.35.104.0/22',
            '103.61.156.0/22',
            '103.61.160.0/22',
            '103.62.24.0/22',
            '103.62.204.0/22',
            '103.62.208.0/22',
            '103.192.0.0/22',
            '103.192.144.0/22',
            '103.193.140.0/22',
            '111.0.0.0/10',
            '112.0.0.0/10',
            '117.128.0.0/10',
            '120.192.0.0/10',
            '183.192.0.0/10',
            '211.103.0.0/17',
            '211.136.0.0/14',
            '211.140.0.0/15',
            '211.142.0.0/17',
            '211.142.128.0/17',
            '211.143.0.0/16',
            '218.200.0.0/14',
            '218.204.0.0/15',
            '218.206.0.0/15',
            '221.130.0.0/15',
            '221.176.0.0/13',
            '223.64.0.0/11',
            '223.96.0.0/12',
            '223.112.0.0/14',
            '223.116.0.0/15',
            '223.120.0.0/13',
            '39.108.0.0/16',
            '42.96.128.0/17',
            '42.120.0.0/16',
            '42.121.0.0/16',
            '42.156.128.0/17',
            '45.113.40.0/22',
            '47.92.0.0/14',
            '59.110.0.0/16',
            '60.205.0.0/16',
            '101.37.0.0/16',
            '101.200.0.0/15',
            '103.52.196.0/22',
            '106.11.0.0/16',
            '106.14.0.0/15',
            '110.75.0.0/16',
            '110.76.0.0/19',
            '110.76.32.0/20',
            '110.76.48.0/20',
            '110.173.192.0/19',
            '112.74.0.0/16',
            '112.124.0.0/16',
            '112.125.0.0/16',
            '112.126.0.0/16',
            '112.127.0.0/16',
            '114.55.0.0/16',
            '114.215.0.0/16',
            '115.28.0.0/16',
            '115.29.0.0/16',
            '115.124.16.0/20',
            '116.62.0.0/16',
            '118.178.0.0/16',
            '118.190.0.0/16',
            '119.23.0.0/16',
            '119.38.208.0/20',
            '119.42.224.0/19',
            '120.24.0.0/14',
            '120.55.0.0/16',
            '120.76.0.0/15',
            '120.78.0.0/15',
            '121.0.16.0/20',
            '121.40.0.0/14',
            '121.196.0.0/14',
            '123.56.0.0/15',
            '139.129.0.0/16',
            '139.196.0.0/16',
            '139.224.0.0/16',
            '140.205.0.0/16',
            '182.92.0.0/16',
            '203.107.0.0/24',
            '203.107.1.0/24',
            '203.209.224.0/19',
            '218.244.128.0/19',
            '223.4.0.0/14',
            '43.242.252.0/22',
            '43.247.196.0/22',
            '58.87.64.0/18',
            '103.38.116.0/22',
            '103.238.16.0/22',
            '111.230.0.0/15',
            '115.159.0.0/16',
            '118.89.0.0/16',
            '118.126.64.0/18',
            '119.27.160.0/19',
            '119.29.0.0/16',
            '121.51.0.0/16',
            '122.152.192.0/18',
            '123.206.0.0/15',
            '139.199.0.0/16',
            '140.143.0.0/16',
            '182.254.0.0/16',
            '203.195.128.0/17',
            '210.73.160.0/19',
            '211.159.128.0/17',
        ]
        self.prefix={}.fromkeys([''.join([format(int(w,10),'08b') for w in x.split('.')])[:int(y,10)] for x,y in [x.split('/') for x in self.prefix]])
        self.prefix=self.cidrunique(self.prefix)

    def prefixmatch(self,ip):
        ip=''.join([format(int(x,10),'08b') for x in ip.decode("ASCII").split('.')])
        i=''
        for x in ip:
            i=i+x
            if i in self.prefix:
                return 1
        return 0

    def cidrunique (self,cidr):
        tmp=[]
        for x in cidr:
            s=''
            v=1
            for i in x:
                s=s+i
                if s in cidr and s!=x:
                    v=0
                    break
            if v:
                tmp.append(x)
        return {}.fromkeys(tmp)

class udpdnsserver(object):
    
    def __init__(self, addr='127.0.0.1', port=53):
        self.udpfd=socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.udpfd.bind((addr, port))
        self.addr=()
        self.QID=b''
        self.flages=0

    def input(self):
        data, self.addr=self.udpfd.recvfrom(1500)
        self.flages=int(data[2:4].hex(), 16)
        self.QID=data[0:2]
        Rcode=0
        if self.flages&0x7800:
            Rcode=4
        elif self.flages&0x8000 != 0:
            Rcode=1
        elif data[4:6] == b'\x00\x01':
            i=0
            for x in data[12:]:
                i=i+1
                if x == 0:
                    break
            if data[12+i:i+16] != b'\x00\x01\x00\x01':
                Rcode=4
        else:
            Rcode=4
        if Rcode:
            qdata=data[12:]
        else:
            qdata=data[12:i+16]
        return Rcode, qdata
    
    def output(self, Rcode, Rdata, ANCOUNT=0):
        if Rcode:
            self.flages=self.flages|Rcode
        self.flages=self.flages|0x8000
        Rcount=b''.join([b'\x00\x01', ANCOUNT.to_bytes(2, byteorder='big'), b'\x00\x00\x00\x00'])
        Rdata=b''.join([self.QID, self.flages.to_bytes(2, byteorder='big'), Rcount, Rdata])
        self.udpfd.sendto(Rdata, self.addr)

if __name__ == '__main__':
    localserver=udpdnsserver(addr='0.0.0.0')
    dnspod=httpdns(ednsip='211.140.188.188')
    ipprefix=iptool()
    while 1:
        Rcode, Qdata=localserver.input()
        if Rcode:
            pass #localserver.output(Rcode, Rdata=Qdata)
        else:
            ANCOUNT, Rdata, tmp=dnspod.httprequest(Qdata)
            if ANCOUNT and ipprefix.prefixmatch(tmp[0]):
                localserver.output(Rcode, Rdata, ANCOUNT)
            else:
                pass #localserver.output(Rcode, Rdata=Qdata)
