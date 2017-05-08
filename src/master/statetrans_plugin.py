from twisted.internet import reactor
import database
import plugin
import activity
import logging
import struct
import socket
import time
import timers
import datetime
import netaddr
import sys

logger = logging.getLogger(name='statetrans')

def save_to_db(message, client):
	# parse data from client
	(timestamp,) = struct.unpack('!Q', message[:8])
	(score,family,src_port,dst_port) = struct.unpack('!HBHH', message[8:15])
	addr_len = 4 if family == 4 else 16
	src_ip  = message[15:15 + addr_len]
	src_ip  = socket.inet_ntop(socket.AF_INET if family == 4 else socket.AF_INET6, src_ip)
	dst_ip  = message[15 + addr_len:15 + addr_len + addr_len]
        dst_ip  = socket.inet_ntop(socket.AF_INET if family == 4 else socket.AF_INET6, dst_ip)

	# int score to float
	scoref = score / 100.0
	logger.debug("--> Statetrans - MSG: Time: %s, Score: %s (%s), Family: %s, Conv: %s:%s -> %s:%s", timestamp, score, scoref, family, src_ip, src_port, dst_ip, dst_port)

	# transform UNIX time (echo time) to timestamp
	timestamp = datetime.datetime.fromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S')

	values = []
	values.append((client, timestamp, score, scoref, family, src_ip, src_port, dst_ip, dst_port))

	# insert data to DB
	with database.transaction() as t:
		t.executemany("INSERT INTO statetrans (client, timestamp, score, scoref, family, src_ip, src_port, dst_ip, dst_port) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)", values)

class StatetransPlugin(plugin.Plugin):
	def __init__(self, plugins, config):
		plugin.Plugin.__init__(self, plugins)
		self.__config = config
		# __config parameters are loaded from ucollect/src/master/collect-master.conf
		self.__interval = int(config['interval'])
		# DB query 1
		self.__time = (config['time'])
		self.__score = int(config['score'])
		self.__clients = int(config['clients'])
		# DB query 2
		self.__time2 = (config['time2'])
		self.__score2 = int(config['score2'])
		self.__count2 = int(config['count2'])
		# Repeat function "__worker" every X seconds (interval)
		self.__work = timers.timer(self.__worker, self.__interval, False)

	def name(self):
		return 'Statetrans'

	def __worker(self):
		# query DB every X seconds
		logger.debug("--> Statetrans - Doing some work every %s seconds", self.__interval)
		reactor.callInThread(self.__query_db_analyse)

	def message_from_client(self, message, client):
		# C - config (client asking server for config)
		if message[0] == 'C':
			logger.debug("--> Statetrans - [C] message was recived from client: %s", client)
			# __config parameters are loaded from ucollect/src/master/collect-master.conf 
			config = struct.pack('!II', *map(lambda name: int(self.__config[name]), ['treshold', 'learn']))		
			# Send opcode C + config parameters
			self.send('C' + config, client)
			logger.debug("--> Statetrans - Replied with [C] message to client: %s", client)
			# Also send all block "dangerous" IPs + unblock "old dangerous"
			reactor.callInThread(self.__ips_to_block, client)
			reactor.callInThread(self.__ips_to_unblock, client)

		# A - data (client sending anomalies to server)
		elif message[0] == 'A':
			logger.debug("--> Statetrans - [A] message was recived from client: %s", client)
			reactor.callInThread(save_to_db, message[1:], client)

		# Wrong OP code
		else:
			logger.error("--> Statetrans - Unknown message from client %s: %s", client, message)

	def __ip2long(ip):
		# Convert an IP string to long
		packedIP = socket.inet_aton(ip)
		return struct.unpack("L", packedIP)[0]

	def __ips_to_block(self, client):
		# query DB for "dangerous" IPs
		values = []
		values.append(('t'))

		with database.transaction() as t:
			t.executemany("SELECT DISTINCT src_ip FROM statetrans_list WHERE active = %s", values)
			ips = list(t.fetchall())

		logger.debug("--> Statetrans - IPs: %s = %s",len(ips), ips)

		# only for testing
		test = '3232236014'

		# Send them to newly connected client
                for ip in ips:
			self.send('B' + struct.pack('!L', int(netaddr.IPAddress(ip[0]))), client )
			logger.debug("--> Statetrans - LONG = %s, size of LONG = %s, IP = %s", int(netaddr.IPAddress(ip[0])) ,sys.getsizeof(int(netaddr.IPAddress(ip[0]))) , ip[0])
			#self.send('B' + struct.pack('!L', long(test) ), client )

	def __ips_to_unblock(self, client):
		# query DB for "maybe not dangerous" IPs
		values = []
		values.append(('f'))

		with database.transaction() as t:
			t.executemany("SELECT DISTINCT src_ip FROM statetrans_list WHERE active = %s", values)
			ips = list(t.fetchall())

		logger.debug("--> Statetrans - IPs: %s = %s",len(ips), ips)

		# only for testing
		test = '3232236014'

		# Send them to newly connected client
                for ip in ips:
			self.send('U' + struct.pack('!L', int(netaddr.IPAddress(ip[0]))), client )
			logger.debug("--> Statetrans - LONG = %s, size of LONG = %s, IP = %s", int(netaddr.IPAddress(ip[0])) ,sys.getsizeof(int(netaddr.IPAddress(ip[0]))) , ip[0])
			#self.send('B' + struct.pack('!L', long(test) ), client )

	def __query_db_analyse(self):
		values = []
		values.append((self.__score, self.__time, self.__clients))

		# DB query 1
		with database.transaction() as t0:
			t0.executemany("SELECT src_ip FROM statetrans WHERE score >= %s AND timestamp >= (now() - time %s) AND fwup = 'f' GROUP BY src_ip HAVING count(distinct client) >= %s", values)
			ips = list(t0.fetchall())

		# DB update 1
		with database.transaction() as t1:
			t1.executemany("UPDATE statetrans SET fwup = 't' WHERE src_ip = %s", ips)

		values2 = []
                values2.append((self.__score2, self.__time2, self.__count2))

		# DB query 2
		with database.transaction() as t2:
			t2.executemany("SELECT src_ip FROM statetrans WHERE score >= %s AND timestamp >= (now() - time %s) AND fwup = 'f' GROUP BY src_ip HAVING count(src_ip) >= %s ", values2)
			ips2 = list(t2.fetchall())

		# DB update 2
		with database.transaction() as t3:
			t3.executemany("UPDATE statetrans SET fwup = 't' WHERE src_ip = %s", ips2)

#		ips.extend(ips2)

		# Just debbuging info
		logger.debug("--> Statetrans - IPs: %s = %s",len(ips), ips)

		# Insert "dangerous" IPs to separate table (statetrans_list)
		with database.transaction() as t4:
			t4.executemany("INSERT INTO statetrans_list (timestamp, src_ip) VALUES (now(), %s)", ips)

		with database.transaction() as t5:
			t5.executemany("INSERT INTO statetrans_list (timestamp, src_ip) VALUES (now(), %s)", ips2)

		values3 = []

		# Format DB query result to proper format
		for ip in ips:
			logger.debug("--> Statetrans - IP: %s", ip[0])
			values3.append((ip[0]))

		# Just debbuging info
		logger.debug("--> Statetrans - !! IPs: %s = %s",len(values3), values3)

		# Send "dangerous" IPs to every connected clients via broadcast
		for v in values3:
			logger.debug("--> Statetrans - %s = %s",v, int(netaddr.IPAddress(v)))
			self.broadcast('B'+struct.pack('!L', int(netaddr.IPAddress(v))))
