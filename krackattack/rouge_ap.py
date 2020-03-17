"""
Usage:
	python rouge_ap.py <iface>
	python rouge_ap.py -h
	
Options:
	iface..........Interface to launch on
"""
import sys, time, os, subprocess, shlex, socket, struct, string, heapq, textwrap, fileinput
from docopt import docopt
from wpaspy import *
from libclass import *
from scapy.all import *

if __name__ == '__main__':
	args 			= docopt(__doc__, version='v0.9')
	iface			= args["<iface>"]
	print iface+'it works'
