#!/usr/bin/env python

from __future__ import print_function
import nmap
import pickle
import os
import argparse
import sys
import shutil

class Scanner():
	
	def __init__(self, flags = '-n -Pn -sV -O', network = '127.0.0.1', ports = '1-1024', infile = False):
		self.nm = nmap.PortScanner()
		self.flags = flags
		self.inNetwork = network
		self.inPorts = ports
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
		self.scanResults = self.nm.scan(hosts=self.inNetwork, ports=self.inPorts, arguments=self.flags)
		pickle.dump(self.scanResults, open("scanResults.p", "wb"))
	
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
			except KeyError:
				pass


if __name__ == "__main__":
	p = argparse.ArgumentParser(description='Python NMAP Wrapper', formatter_class=argparse.RawTextHelpFormatter)
	p.add_argument('-n', '--network', help='Set the network to scan. Can include CIDR.\nDEFAULT = 127.0.0.1')
	p.add_argument('-p', '--ports', help='Set the ports or port range for scan.\nDEFAULT = 1-1024')
	p.add_argument('-f', '--flags', help="Set NMAP flags for scan. Space delimited.\nDEFAULT = -n -Pn -sV -O")
	p.add_argument('--infile', help="Used for debugging. Uses Python pickle file from previous scan to save time.\nDEFAULT = Looks for file ./scanResults.p", action="store_true") 
	flags = vars(p.parse_args())
	userIn = ""

	for x in flags:
		if flags[x]:
			userIn += ('%s="%s",' % (x,flags[x]))

	scanner = eval("Scanner(%s)" % userIn[:-1])
	if p.parse_args().infile:
		scanner.sortByPorts()
	else:
		scanner.runScan()
		scanner.sortByPorts()
