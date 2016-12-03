#!/usr/bin/env python

from __future__ import print_function
import nmap
import pickle
import os
import pprint
import argparse
import sys
import pymysql as msc
import shutil

class Scanner():
	
	def __init__(self, flags = '', network = '127.0.0.1', ports = '1-1024', parse = None, infile = None, wtd = None, async = None, preone = None, pretwo = None, prethree = None, prefour = None):
		self.parse = parse
		self.inPorts = ports
		self.inNetwork = network
		self.writeFile = wtd
		self.scanResults = dict()
		if async:
			self.nm = nmap.PortScannerAsync()
			self.completed = 0
			self.ticks = 0
			self.percent = 0
		else:
			self.nm = nmap.PortScanner()
		self.async = async
		
		if preone:
			self.flags = '-sP'
			self.inPorts = None
			self.printOption = 1
		elif pretwo:
			self.flags = '--open -sV'
			self.inPorts = pretwo
			self.printOption = 2
		elif prethree:
			self.printOption = 3
			self.flags = '-n -Pn -sU -sV -O -T4 --reason'
		elif prefour:
			slef.printOption = 4
			self.flags = ''
		else:
			self.printOption = 0
			self.flags = flags
		
		if infile:
			try: 
				self.scanResults = pickle.load(open("./.scanResults.p", "rb"))
			except IOError:
				print("No file exists, must run a scan first")
				sys.exit()
		self.cnx = msc.connect(user='root', password='password', host='127.0.0.1', database='nmap_test')
		self.cursor = cnx.cursor()
		self.cursor.execute("TRUNCATE services")
	
	def setFlags(self, inFlags):
		self.flags = inFlags

	def setNetwork(self, inNetwork):
		self.inNetwork = inNetwork

	def setPorts(self, inPorts):
		self.inPorts = inPorts

	def runScan(self):
		if self.writeFile:	
			if not os.path.exists("./nmap_results/output"):
				os.makedirs("./nmap_results/output")
			self.flags += " -oN ./nmap_results/output/%s.nmap -oG ./nmap_results/output/%s.gnmap" % (self.writeFile, self.writeFile)
		
		if self.async:
			self.scanResults = self.nm.scan(hosts=self.inNetwork, ports=self.inPorts, arguments=self.flags, callback=self.statusMonitor)
			sys.stdout.write("[%s] 0%%\r" % (" " * 50))
			sys.stdout.flush()
			while self.nm.still_scanning():
				continue
			print("\nScan results parsed into database")
		else:
			self.scanResults = self.nm.scan(hosts=self.inNetwork, ports=self.inPorts, arguments=self.flags)
	
		if self.writeFile:
			try:
				open("./nmap_results/output/%s.xml" % self.writeFile, "w").write(self.nm.get_nmap_last_output())
			except (IOError, OSError, AttributeError):
				pass
		
		pickle.dump(self.scanResults, open("./.scanResults.p", "wb"))
		self.printResults()
	
	def statusMonitor(self, host, results):
		self.completed += 1
		opercent = self.percent
		self.percent = int((self.completed / float(256)) * 100)
		if self.percent % 2 == 0 and opercent != self.percent:
			self.ticks += 1
		sys.stdout.write("[%s%s] %s%%\r" % (("=" * self.ticks), " " * (50 - self.ticks), self.percent))
		sys.stdout.flush()
		self.scanResults = results
		self.parseData()
	
	def sortByPorts(self):
		try:
			shutil.rmtree('./nmap_results/sortByPort') # THIS NEEDS TO BE CLEANER
		except OSError:
			pass

		if not os.path.exists("./nmap_results/sortByPort"):
			os.makedirs("./nmap_results/sortByPort")
		try:	
			for x in self.scanResults['scan']:
				try:
					for y in self.scanResults['scan'][x]['tcp'].keys():
						open("./nmap_results/sortByPort/%s" % (y), "a").write("%s\n" % (x))
				except (KeyError, TypeError):
					pass
		except TypeError:
			pass

	def parseData(self):
		try:
			for i in self.scanResults['scan']:
				try:
					for s in self.scanResults['scan'][i]["tcp"]:
						add_service = ('INSERT INTO services (host, tool, service, port, protocol, state, interface, version) VALUES ("%s", "%s", "%s", %s, "%s", "%s", "%s", "%s")' % (str(i), "nmap", str(self.scanResults["scan"][i]["tcp"][s]["name"]), int(s), "tcp", str(self.scanResults["scan"][i]["status"]["state"]), str(self.scanResults["scan"][i]["tcp"][s]["product"]), str(self.scanResults["scan"][i]["tcp"][s]["extrainfo"])))
						self.cursor.execute(add_service)	
						self.cnx.commit()
				except KeyError:
					pass
			for i in self.scanResults['scan']:
				try:
					for s in self.scanResults['scan'][i]["udp"]:
						add_service = ('INSERT INTO services (host, tool, service, port, protocol, state, interface, version) VALUES ("%s", "%s", "%s", %s, "%s", "%s", "%s", "%s")' % (str(i), "nmap", str(self.scanResults["scan"][i]["udp"][s]["name"]), int(s), "udp", str(self.scanResults["scan"][i]["status"]["state"]), str(self.scanResults["scan"][i]["udp"][s]["product"]), str(self.scanResults["scan"][i]["udp"][s]["extrainfo"])))
						self.cursor.execute(add_service)	
						self.cnx.commit()
				except KeyError:
					pass
		except TypeError:
			pass
		self.cnx.close()
		return "Scan results parsed into database."

	def printResults(self):
		if self.printOption == 0:
			if self.parse:
				self.parseData()
			self.sortByPorts()
		elif self.printOption == 1:
			for i in self.scanResults["scan"]:
				print("%s: %s" % (self.scanResults["scan"][i]["addresses"]["ipv4"], self.scanResults["scan"][i]["status"]["state"]))
		elif self.printOption == 2:
				for i in self.scanResults['scan']:
					try:
						print("%s:%s - %s\t%s %s" % (self.scanResults['scan'][i]['addresses']['ipv4'], self.inPorts, self.scanResults['scan'][i]['status']['state'], self.scanResults['scan'][i]['tcp'][int(self.inPorts)]['product'],self.scanResults['scan'][i]['tcp'][int(self.inPorts)]['extrainfo']))
					except KeyError:
						pass
		elif self.printOption == 3:
				self.sortByPorts()
				print(self.parseData())
		elif self.printOption == 4:
				pass

if __name__ == "__main__":
	p = argparse.ArgumentParser(description='Python NMAP Wrapper', formatter_class=argparse.RawTextHelpFormatter)

	g1 = p.add_argument_group("Pre-programmed NMAP Scans", "Suggested NMAP scans to accomplish specific tasks")
	g1.add_argument('-1', help="Basic ping sweep scan. Host that appear up print to screen.\nOPTIONS = -sP", dest="preone",  action="store_true")
	g1.add_argument('-2', help="Returns machines with port PORTNUM open.", dest="pretwo", metavar='PORTNUM')
	g1.add_argument('-3', help="Aggressive scan.  Will take a very long time. **Parsed into database**\nOPTIONS = -n -Pn -sV -O -T4 --reason", dest="prethree", action="store_true")
	g1.add_argument('-4', help="Place holder for scan type 4 with NSE support.\nCurrently does nothing.", dest="prefour", action="store_true")

	p.add_argument('-n', '--network', help='Set the network to scan. Can include CIDR.\nDEFAULT = 127.0.0.1')
	p.add_argument('-p', '--ports', help='Set the ports or port range for scan.\nDEFAULT = 1-1024')
	p.add_argument('-f', '--flags', help="Set NMAP flags for scan, space delimited. **Will override mode.**\nDEFAULT = -n -Pn -sV -O")
	p.add_argument('-w', '--wtd', help='Write output to disk (save .nmap and .gnmap to working directory.\nDEFAULT = False', metavar='FILENAME')
	p.add_argument('--infile', help="Used for debugging. Uses Python pickle file from previous scan to save time.\nDEFAULT = Looks for file ./.scanResults.p", action="store_true") 
	p.add_argument('--async', help="Used for running hosts asynchronusly.  Can get status updates with this option.\nDEFAULT = False", action="store_true") 
	p.add_argument('--parse', help="Parse into existing MySQL database. The -3 pre-programmed scan does this by default.\nDEFAULT = False", action="store_true")
	flags = vars(p.parse_args())
	userIn = ""
	
	temp = p.parse_args()
	if temp.preone is True and (temp.pretwo is True or temp.prethree is True or temp.prefour is True):
		print("Error: Only one pre-programmed scan type allowed at once.")
		sys.exit()
	elif temp.pretwo is True and (temp.prethree is True or temp.prefour is True):
		print("Error: Only one pro-programmed scan type allowed at once.")
		sys.exit()
	elif temp.prethree is True and temp.prefour is True:
		print("Error: Only one pro-programmed scan type allowed at once.")
		sys.exit()
	elif temp.prefour is True:
		print("Option 4 doesn't do anything right now.")
		sys.exit()

	for x in flags:
		if flags[x]:
			userIn += ('%s="%s",' % (x,flags[x]))
	scanner = eval("Scanner(%s)" % userIn[:-1])
	

	if p.parse_args().infile:
		scanner.printResults()
	else:
		scanner.runScan()
