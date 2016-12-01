#!/usr/bin/env python

from __future__ import print_function
import nmap
import pickle
import os
import pprint
import argparse
import sys
import shutil

class Scanner():
	
	def __init__(self, flags = '-n -Pn -sV -O', network = '127.0.0.1', ports = '1-1024', infile = None, wtd = None, async = None):
		if async:
			self.nm = nmap.PortScannerAsync()
			self.completed = 0
			self.ticks = 0
			self.percent = 0
		else:
			self.nm = nmap.PortScanner()
		self.async = async
		self.flags = flags
		self.inNetwork = network
		self.inPorts = ports
		self.writeFile = wtd
		self.scanResults = dict()
		if infile:
			try: 
				self.scanResults = pickle.load(open("scanResults.p", "rb"))
			except IOError:
				print("No file exists, must run a scan first")
				sys.exit()
	
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
			#sys.stdout.write("\b" * 51)
			#sys.stdout.flush()
			while self.nm.still_scanning():
				continue
		else:
			self.scanResults = self.nm.scan(hosts=self.inNetwork, ports=self.inPorts, arguments=self.flags)
	
		try:
			open("./nmap_results/output/%s.xml" % self.writeFile, "w").write(self.nm.get_nmap_last_output())
		except (IOError, OSError, AttributeError):
			pass
		
		pickle.dump(self.scanResults, open("scanResults.p", "wb"))
	
	def statusMonitor(self, host, results):
		self.completed += 1
		opercent = self.percent
		self.percent = int((self.completed / float(256)) * 100)
		if self.percent % 2 == 0 and opercent != self.percent:
			self.ticks += 1
		sys.stdout.write("[%s%s] %s%%\r" % (("-" * self.ticks), " " * (50 - self.ticks), self.percent))
		sys.stdout.flush()	
	
	def sortByPorts(self):
		try:
			shutil.rmtree('./nmap_results') # THIS NEEDS TO BE CLEANER
		except OSError:
			pass

		if not os.path.exists("./nmap_results/sortByPort"):
			os.makedirs("./nmap_results/sortByPort")
		
		for x in self.scanResults['scan']:
			try:
				for y in self.scanResults['scan'][x]['tcp'].keys():
					open("./nmap_results/sortByPort/%s" % (y), "a").write("%s\n" % (x))
			except (KeyError, TypeError):
				pass

	def printResults(self):
		pprint.pprint(self.scanResults)


if __name__ == "__main__":
	p = argparse.ArgumentParser(description='Python NMAP Wrapper', formatter_class=argparse.RawTextHelpFormatter)
	p.add_argument('-n', '--network', help='Set the network to scan. Can include CIDR.\nDEFAULT = 127.0.0.1')
	p.add_argument('-p', '--ports', help='Set the ports or port range for scan.\nDEFAULT = 1-1024')
	p.add_argument('-f', '--flags', help="Set NMAP flags for scan. Space delimited.\nDEFAULT = -n -Pn -sV -O")
	p.add_argument('-w', '--wtd', help='Write output to disk (save .nmap and .gnmap to working directory.\nDEFAULT=False', metavar='FILENAME')
	p.add_argument('--infile', help="Used for debugging. Uses Python pickle file from previous scan to save time.\nDEFAULT = Looks for file ./scanResults.p", action="store_true") 
	p.add_argument('--async', help="Used for running hosts asynchronusly.  Can get status updates with this option.\nDEFAULT = No", action="store_true") 
	flags = vars(p.parse_args())
	userIn = ""

	for x in flags:
		if flags[x]:
			userIn += ('%s="%s",' % (x,flags[x]))
	scanner = eval("Scanner(%s)" % userIn[:-1])
	if p.parse_args().infile:
		scanner.sortByPorts()
		scanner.printResults()
	else:
		scanner.runScan()
		#scanner.sortByPorts()
		#scanner.printResults()
