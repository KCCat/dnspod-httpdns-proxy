#!/usr/bin/env pypy
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
            Rdata=urllib.request.urlopen('http://119.29.29.29/d?dn=%s&ip=%s' % (self.domain,self.ednsip)).read().split(b';')
        except OSError:
            print('httprequest error')
            return 0, Qdata, b''
        try:
            Rdata=[bytes([int(y) for y in x.split(b'.')]) for x in Rdata]
        except ValueError:
            print('non answer')
            return 0, Qdata, b''
        return len(Rdata), b''.join([b'\xc0\x0c\x00\x01\x00\x01',self.TTL, b'\x00\x04']).join([Qdata, *Rdata]), Rdata

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
    dnspod=httpdns(ednsip='211.138.113.115')
    while 1:
        Rcode, Qdata=localserver.input()
        if Rcode:
            localserver.output(Rcode, Rdata=Qdata)
        else:
            ANCOUNT, Rdata, tmp=dnspod.httprequest(Qdata)
            localserver.output(Rcode, Rdata, ANCOUNT)
