#!/usr/bin/env python3
# encoding: utf-8

'''
       +-------------------------+
       |                         |
+---+  |      mian udp loop      |
|      |                         |
|      +-------------------------+
|                                              +--------------------------+
|                                              |                          |
|                                       +---+  |       workerhttp         |
|      +-------------------------+      |      |                          |
|      |                         |      |      +--------------------------+
+---+  |         worker          |  +---+
       |                         |      |      +--------------------------+
       +-------------------------+      |      |                          |
                                        +---+  |       workerudp          |
                                               |                          |
                                               +--------------------------+



                   +------------+
                   |            |
                   |  ipv4 DNS  |
                   |            |
                   +------------+

                          +
                          |
                          |
              +-----------+-----------+
              |                       |
              |                       |
              |                       |
              v                       v

   +--------------------+   +-------------------+
   |                    |   |                   |
   |   dnspod http dns  |   |   udp dns server  |
   |       tpye A       |   |      type ALL     |
   |                    |   |                   |
   +--------------------+   +-------------------+

              +                       +
              |                       |
              |                       |
              |                       |
              v                       |
                                      |
  +---------------------+             |
  |                     |             |
  |       filter        |             |
  |  china_ip_list.txt  |             |
  |                     |             |
  +---------------------+             |
                                      |
              +                       |
not in list   |      in list          |
return None   |   return Answer       |
              |                       |
              v                       v

           +----------------------------+
           |                            |
           |  if dnspod answer is None  |
           |        use udp answer      |
           |  else use dnspod           |
           |                            |
           +----------------------------+

'''


import asyncio, socket

fserver=[
	('10.250.251.1',10242),
	('10.250.250.1',53535),
]

hserver=[
	('119.29.29.29',80),
	('182.254.116.116',80),
]


def labelsTOdomain(domain=b''):
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
	return bytes(r)[1:].decode('ASCII')


def findtype(fdata=b''):
	i=12
	while not fdata[i] == 0: #b'\x03www\x06google\x03com\x00'
		i += fdata[i] +1
	return i+1


async def forwardudp(fdata=b'',fserver=('127.0.0.1',53), u_family=socket.AF_INET):
	fd = socket.socket(family=u_family, type=socket.SOCK_DGRAM)
	fd.setblocking(0)
	fd.sendto(fdata, fserver)
	time = 0
	while time < 1:
		try:
			data, addr = fd.recvfrom(1500)
			fd.close()
			return data, addr
		except:
			await asyncio.sleep(0.05)
			time += 0.05
	fd.close()
	return None


async def workerudp(fdata=b'',fserver=[('127.0.0.1',53),]):
	done, pending = await asyncio.wait(
		{ *[forwardudp(fdata,i) for i in fserver]
		},
		#timeout=1,
		return_when = asyncio.FIRST_COMPLETED
	)
	if not len(done):
		print("warn: udpdns timeout")
		return None
	return done.pop().result()


async def _awaithttp(domain='',fserver=('119.29.29.29',80)):
	try:
		reader, writer = await asyncio.open_connection(*fserver)
		query = (
			f"GET /d?dn={domain} HTTP/1.1\r\n"
			f"\r\n"
		)
		writer.write(query.encode('latin-1'))
		line = await reader.read()
		line = line.split(b'\r\n\r\n')[-1].decode('latin1')
		writer.close()
		return line
	except OSError:
		print(f"WARN: httpdns OSError")
		await asyncio.sleep(2)
		return None


async def workerhttp(domain='',hserver=[('119.29.29.29',80),]):
	# 119.29.29.29, 119.28.28.28, 182.254.116.116, 182.254.118.118
	done, pending = await asyncio.wait(
		{ *[asyncio.create_task(_awaithttp(domain,i)) for i in hserver]
		},
		timeout=1,
		return_when = asyncio.FIRST_COMPLETED
	)
	if not len(done):
		print(f"WARN: httpdns {domain} timeout")
		return None
	body = done.pop().result()
	if body:
		if china.find(body.split(";")[0]):
			return body
	else: 
		print(f"WARN: httpdns {domain} None Answer")
	return None


async def worker(queue):
	while True:
		fdata, faddr = await queue.get()
		task = []
		Tid, flags = fdata[0:2], int(fdata[2:4].hex(), 16)
		if ((flags & 0xF900) == 0x0100) and (fdata[4:8] == b'\x00\x01\x00\x00'):
			#Flags Standard query                      #Questions: 1
			try:
				typeindex = findtype(fdata)
			except IndexError:
				typeindex = 2 #Magic number -> flags
			if fdata[typeindex: typeindex+2] == b'\x00\x01':
				domain = labelsTOdomain(fdata[12: typeindex])
				task.append(workerhttp(domain, hserver))
		task.append(workerudp(fdata, fserver))
		done = await asyncio.gather(*task)
		#type(done) = list
		if len(done) == 1 and done[0] != None:
			udpfd.sendto(done[0][0], faddr)
		if len(done) == 2 and done[0] != None:
			list_str = done[0].split(';')
			Answer = len(list_str).to_bytes(2, byteorder='big')
			fdata = b''.join([
				fdata[:2], 
				b'\x80\x80', # flags=0x8080 这样dnsmasq才会缓存结果
				b'\x00\x01'+ Answer +b'\x00\x00\x00\x00', #Questions: 1 Answer RRs: 1
				fdata[12:typeindex+4],
			])
			list_byt = [bytes([int(y) for y in x.split('.')]) for x in list_str]
			fdata += b''.join([ b''.join([b'\xc0\x0c\x00\x01\x00\x01', #Name,Type,Class
						b'\x00\x00\x01,', #(300).to_bytes(4, byteorder='big')
						b'\x00\x04', #length
						x
					   ]) for x in list_byt])
			udpfd.sendto(fdata, faddr)
			print(f'httpdns : {domain}')
		elif len(done) == 2 and done[-1] != None:
			udpfd.sendto(done[-1][0], faddr)
			print(f'udpdns  : {done[-1][-1][0]} : {domain}')


class mianudploop(asyncio.DatagramProtocol):
	def __init__(self, queue, loop, loopend):
		self.queue = queue
		self.loop = loop
		self.loopend = loopend
	def connection_made(self, transport):
		self.transport = transport
	def connection_lost(self, exc):
		self.loopend.cancel()
	def datagram_received(self, fdata, faddr):
		asyncio.run_coroutine_threadsafe(self.queue.put((fdata, faddr)), self.loop)


async def udploop(queue):
	global udpfd
	loop = asyncio.get_running_loop()
	loopend = loop.create_future()
	transport, protocol = await loop.create_datagram_endpoint(
		lambda: mianudploop(queue,loop,loopend),
		local_addr=('127.0.0.1', 5353))
	udpfd = transport
	try:
		await loopend
	finally:
		transport.close()


class ipv4prefixfind:
	def __init__(self, file):
		self.frozenset=[]
		self.min=64
		self.max=0
		with open(file) as f:
			for i in f:
				addr, prefix = i.split('/')
				prefix = int(prefix, 10)
				self.min=min(self.min, prefix)
				self.max=max(self.max, prefix)
				addr = ''.join([('00000000'+bin(int(_,10))[2:])[-8:] for _ in addr.split('.')])
				addr = addr[:prefix]
				self.frozenset.append(addr)
		self.max += 1
		self.frozenset = frozenset(self.frozenset)
		self.range = range(self.min, self.max)
	def find(self, addr='127.0.0.1'):
		str_bin_addr = ''.join([('00000000'+bin(int(_,10))[2:])[-8:] for _ in addr.split('.')])
		for i in self.range:
			if str_bin_addr[:i] in self.frozenset:
				return True
		return False


async def main():
	queue = asyncio.Queue()
	await asyncio.gather(udploop(queue),
						 *[worker(queue) for i in range(4)]
						)


china = ipv4prefixfind('china_ip_list.txt')
asyncio.run(main())

