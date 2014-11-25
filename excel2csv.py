import xlrd
from xlutils.view import View
from xlrd.sheet import Cell
from xlutils.display import cell_display
import codecs
from datetime import date,datetime,time
from xlrd import open_workbook,xldate_as_tuple
import splunklib.client as client
from os import path
import sys, os

# Splunk host (default: localhost)
host = "localhost"
# Splunk admin port (default: 8089)
port = "8089"
# Splunk username
username = "admin"
# Splunk password
password = "changeme"
# Access scheme (default: https)
scheme = "https"
#input filename
inputfile = "2.xlsx"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
	from utils import *
except ImportError:
    raise Exception("Add the SDK repository to your PYTHONPATH to run the examples "
	            "(e.g., export PYTHONPATH=~/splunk-sdk-python.")

def importfile(filename, indexname):
	argv = ['tmp.csv', '--index='+indexname, '--username='+username, '--password='+password, '--eventhost='+host, '--port='+port]	
	RULES = {
	    "eventhost": {
		'flags': ["--eventhost"],
		'help': "The event's host value"
	    },
	    "host_regex": {
		'flags': ["--host_regex"],
		'help': "A regex to use to extract the host value from the file path"
	    },
	    "host_segment": {
		'flags': ["--host_segment"],
		'help': "The number of the path segment to use for the host value"
	    },
	    "index": {
		'flags': ["--index"],
		'default': "main",
		'help': "The index name (default main)"
	    },
	    "rename-source": {
		'flags': ["--source"],
		'help': "The event's source value"
	    },
	    "sourcetype": {
		'flags': ["--sourcetype"],
		'help': "The event's sourcetype"
	    }
	}

	r = 0
	wb = open_workbook(inputfile, encoding_override="cp1252")
	csvoutput = open('tmp.csv', 'wb')
	print "Processing...."
	for s in wb.sheets():
		#print 'Sheet:',s.name
		for row in range(s.nrows):
			values = []
			for col in range(s.ncols):
				values.append(s.cell(row,col).value)
			event = ""
			i = 0
			for value in values:
				i = i + 1
				r = r + 1
	
				if i==22:
					try:				
						date_value = xldate_as_tuple(value, wb.datemode)
						d = datetime(*date_value)		
						event = event +'a="'+str(d) + '",'
					except Exception:
						event = event +'"'+str(value) + '",'
				else:
					value = unicode(value)				
					if value.isdigit():
						event = event +'b="'+ repr(value) + '",'
					else:	
						event = event +'"'+ value.encode('utf-8') + '",'
			leng = len(str(event))
			#print str(event[0:leng-1])
			csvoutput.write(str(event[0:leng-1]))
			csvoutput.write("\n")
	csvoutput.close()

	usage = 'usage: %prog [options] <filename>*'
	opts = parse(argv, RULES, ".splunkrc", usage=usage)
	kwargs_splunk = dslice(opts.kwargs, FLAGS_SPLUNK)
	service = client.connect(**kwargs_splunk)

	name = opts.kwargs['index']

	if name not in service.indexes:
		error("Index '%s' does not exist." % name, 2)
	index = service.indexes[name]

	kwargs_submit = dslice(opts.kwargs,{'eventhost': "host"}, 'source', 'host_regex','host_segment', 'rename-source', 'sourcetype')

	for arg in opts.args: 	
		fullpath = path.abspath(arg)
		if not path.exists(fullpath):
		    error("File '%s' does not exist" % arg, 2)
		index.upload(fullpath, **kwargs_submit)

	os.remove("tmp.csv")
	print "Imported in index "+argv[1]

def ops(menu):
	try:
		try:
			service = client.connect(host=host, port=port, username=username, password=password)			
		except Exception as ex:
			if str(ex)=="Login failed.":
				print "\n\n\t*****Verify the crendentials*****\n\n"			
			elif str(ex)=="[Errno 111] Connection refused":
				print "\n\n\t*****Port error*****\n\n"
			else:
				print ex
			return 1
		print "\n\n\t******Connected to "+host+" on port "+port+"*****\n\n"

		while(1):
			print "1. List the indexes"
			print "2. List the apps"
			print "3. List the inputs"
			print "4. Create an index"
			print "5. Delete an index"
			print "6. Clean an index"
			print "7. Upload an excel file to an index"
			print "p. For previous menu "
			print "q. To quit\n"
			choice2 = raw_input()
			if choice2=='q':
				print "#####Bye#####"
				exit()
			elif choice2=='p':
				break
			elif choice2=='1':
				# Get the collection of indexes
				indexes = service.indexes
				# List the indexes and their event counts
				print "\n##########Indexes###########"
				for index in indexes:
				    count = index["totalEventCount"]
				    print "%s \t\t(events: %s)" % (index.name, count)
				print "#############End############\n"
			elif choice2=='2':
				# Print stalled apps to the console to verify login
				print "\n##########Apps###########"
				for app in service.apps:
    				    print app.name
				print "#############End############\n"
    			elif choice2=='3':
    				# Get the collection of data inputs
				inputs = service.inputs
				print "\n##########Inputs###########"
				# List the inputs and kind
				for item in inputs:
				    print "%s (%s)" % (item.name, item.kind)
				print "#############End############\n"
			elif choice2=='4':
				while(1):
					print "Enter new index name: "
					indexname = raw_input()
					try:
						mynewindex = service.indexes.create(indexname)
						break
					except Exception as ex:
						if str(ex)=="HTTP 409 Conflict -- In handler 'indexes': Index name=main already exists":
							print indexname+" already exists"
			elif choice2=='5':
				while(1):
					print "Enter index name: "
					indexname = raw_input()
					print "Are you sure you want delete index "+indexname+" (y/n)?"
					res = raw_input()
					if res == 'y':
						try:
							mynewindex = service.indexes.delete(indexname)
							print "\t\tDeleted successfully\n"
							break
						except Exception as ex:
							print ex
			elif choice2=='7':
				print "File name("+inputfile+"): "
				filename = raw_input()
				filename = "1.xlsx"
				print "Index name(main1): "
				indexname = raw_input()
				indexname = "main1"
				importfile(filename, indexname)
	except Exception as ex:
		if str(ex)=="Login failed.":
			print "Verify the crendentials"
		elif str(ex)=="[Errno 111] Connection refused":
			print "Port error"
		else:
			print ex


def getConnection():
	try:
		service = client.connect(host=host, port=port, username=username, password=password)			
		return 0
	except Exception as ex:
		if str(ex)=="Login failed.":
			print "\n\n\t*****Verify the crendentials*****\n\n"			
		elif str(ex)=="[Errno 111] Connection refused":
			print "\n\n\t*****Port error*****\n\n"
		else:
			print ex
		return 1


while(1):
	print "\n\t#################Welcome###################\n"
	print "1. To take Splunk server default details: "
	print "\tHost="+host+"\tPort="+str(port)+"\tUsername="+username+"\tPassword="+password+"\t"
	print "2. To STDIN Splunk server details: "
	print "q. To quit"
	choice = raw_input()
	if choice=='q':
		print "\t\t#####Bye#####"
		exit()
	elif choice=='2':
		print "Enter host name(localhost): "
		host = raw_input()
		print "Enter port name(8089): "
		port = raw_input()
		print "Enter user name(admin): "
		username = raw_input()
		print "Enter password name(changeme): "
		password = raw_input()
		if host.strip() == "":
			host = "localhost"
		if port.strip() == "":
			port = "8089"
		if username.strip() == "":
			username = "admin"
		if password.strip() == "":
			password = "changeme"		
		res = ops(2)
		if res == 1:
			print "Connection error"
	else:
		res = ops(1)
		if res == 1:
			print "Connection error"
			






