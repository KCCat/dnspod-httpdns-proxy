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
'''



import asyncio, socket

fserver=[
	('10.250.251.1',10242),
	('192.168.8.1',53),
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
	Done = 0
	time = 0
	while time < 1:
		try:
			data, addr = fd.recvfrom(1500)
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


async def workerhttp(domain='',hserver=[('119.29.29.29',80),]):
	# 119.29.29.29, 119.28.28.28, 182.254.116.116, 182.254.118.118
	done, pending = await asyncio.wait(
		{ *[asyncio.create_task(_awaithttp(domain,i)) for i in hserver]
		},
		timeout=1,
		return_when = asyncio.FIRST_COMPLETED
	)
	if not len(done):
		print("warn: httpdns timeout")
		return None
	body = done.pop().result()
	proc = await asyncio.create_subprocess_exec("geoiplookup", 
		body.split(";")[0],
		stdout=asyncio.subprocess.PIPE,
		stderr=asyncio.subprocess.PIPE)
	stdout, stderr = await proc.communicate()
	if stdout.find(b'CN') == -1:
		body=None
	return body


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


async def main():
	queue = asyncio.Queue()
	await asyncio.gather(udploop(queue),
						 *[worker(queue) for i in range(4)]
						)


asyncio.run(main())




