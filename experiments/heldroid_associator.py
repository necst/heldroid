import csv
from sys import argv
import sys
import logging
import os
import argparse
import re
import urllib
import urllib2
import json

MIN_LOGGING_LEVEL = logging.INFO
API_KEY = '37b64bb3f1cfdd0fa1bc66aec949431e1b8b2cc02c9bbe294d23eb6e692dee13'
URL = "https://www.virustotal.com/vtapi/v2/file/report"

def main():

	parser = argparse.ArgumentParser(description="""This program lets you download VT reports and associate them with heldoid .csv output file.
		In particular it searches all hashes from the .csv file, performs a request to VT and outputs a .txt file.
		IMPORTANT: It is assumed that the APK file name corresponds to its SHA or MD5 hash, i.e. <SHA|MD5>.apk""")
	parser.add_argument('folders', nargs='*', help="A list of .csv files to examine or a list of folders in which the CSV file(s) should be searched. See also option \"-r\".")
	parser.add_argument("-r", "--recursive", action='store_true', help="Perform a recursive search in <folders>")
	parser.add_argument("-o", "--output", default="output.txt", help="Name of the output file (the \".txt\" extension will be added, if not present)", metavar="<file_name>")

	namespace = parser.parse_args()

	recursive = namespace.recursive
	folders = namespace.folders
	output = namespace.output

	# append .txt file extension
	if not output.endswith('.txt'):
		output += '.txt'

	logging.basicConfig(
		level=MIN_LOGGING_LEVEL,
		stream=sys.stdout,
		format='%(asctime)s %(levelname)08s %(message)s',
		datefmt='%Y-%m-%d %-H:%M:%S', # %-H removes the leading zero from the hour, if present
	)

	logging.info("Starting heldroid associator.")
	logging.info("* Will examine file(s): %s", ', '.join([f for f in folders if f.endswith('.csv')]))
	logging.info("* Will search into folder(s): %s", ", ".join([f for f in folders if not f.endswith(".csv")]))
	logging.info("* The search will%s be recursive", '' if recursive else ' not')

	logging.info("Start searching.")

	# save current directory, since "searchInFolder" can change it
	currentDir = os.getcwd();

	# .csv files to be examined
	csvFiles = []

	for folder in folders:
		if folder.endswith(".csv"):
			csvFiles.append(folder)
		else:
			csvFiles.extend(searchInFolder(folder, '.csv', recursive=recursive))

	# go back to original directory
	os.chdir(currentDir)

	logging.info("Search done. Found %d CSV file(s):\n\t--> %s", len(csvFiles), '\n\t-->'.join(csvFiles))
	
	count = 1 if len(csvFiles) > 1 else None

	for csvFile in csvFiles:
		logging.info("Examining: %s", csvFile)
		outputFile = output if len(csvFiles) == 1 else output[:-4] + str(count) + '.txt'
		with open(csvFile, 'r') as f, open(outputFile, "w") as df:
			allInOneWorker(f, df)
		logging.info("Finished! Result written to file: %s", outputFile)
		if count:
			count += 1
# end of main()

def allInOneWorker(inFile, outFile):
	"""This worker request several file reports at once, since VT public API is limited at 4 req/min and 5760 req/day"""
	reader = csv.reader(inFile, delimiter=";")

	hash_list = [] # contains hashes to be seached in VT's database

	# Extract hashes from all .csv file previously found
	for row in reader:
		if reader.line_num == 1:
			continue
		# consider only first column, see this script's description above
		hash_list.append(extractHash(row[0]))

	logging.info("Found %d hashes", len(hash_list))
	hash_list = ','.join(hash_list) # VT wants a comma separated list of hashes

	parameters = {'apikey': API_KEY, 'resource': hash_list}

	data = urllib.urlencode(parameters)
	request = urllib2.Request(URL, data)
	responseObj = urllib2.urlopen(request)

	if not responseObj:
		logging.error("Error while performing the request")
		return

	rawResponse = responseObj.read()

	# Parse response as a JSON
	jsonObj = json.loads(rawResponse)

	if not jsonObj:
		logging.error("No json object retrieved")
		return

	# jsonObj should be a list
	if type(jsonObj) != list:
		jsonObj = [jsonObj]

	# position at the beginning of the file
	inFile.seek(0)

	# ignore the .csv header
	reader.next()

	i = 0 # num of lines read from .csv
	for row in reader:
		# i-th JSON object
		obj = jsonObj[i]

		heldroidObj = {}

		heldroidObj['LockDetected'] = row[1]
		heldroidObj['TextDetected'] = row[2]

		# text detected?
		if (row[2] == 'true'):
			heldroidObj['TextScore'] = row[3]
			heldroidObj['FilesWithText'] = row[7]

		heldroidObj['EncryptionDetected'] = row[4]
		heldroidObj['Comment'] = row[5]
		heldroidObj['TimedOut'] = row[6]

		obj['Heldroid'] = heldroidObj

		i += 1

	# since json.loads returns unicode fields, let's translate them
	obj = byteify(obj)

	outFile.write(json.dumps(jsonObj))
# end AllInOneWorker

def byteify(obj):
	"""This function recursively transforms possibly unicode objects into str objects"""
	if isinstance(obj, dict):
		# dict comprehension
		return { byteify(key):byteify(value) for key, value in obj.iteritems() }
	elif isinstance(obj, list):
		# list comprehension
		return [ byteify(elem) for elem in obj]
	elif isinstance(obj, unicode):
		return obj.encode("UTF-8")
	else:
		return obj

def appendCSVLine(csvFileWriter, row):
	csvFileWriter.writerow(row)

def extractHash(fileName):
	pattern = r'^.*?(?P<hash>\w+)\.apk$'
	regex = re.compile(pattern)
	result = regex.match(fileName)

	if result:
		return result.group('hash')
	return None

def searchInFolder(folder, fileExtension, recursive=False):
	"""Returns all files ending with \"fileExtension\" in \"folder\". Note that this method changes the current working directory, so you need to
	reset it after manually"""
	if not fileExtension.startswith("."):
		fileExtension = '.'+fileExtension

	if os.path.isdir(folder):
		# cd folder
		os.chdir(folder)
		
		subfolders = [ f for f in os.listdir(os.getcwd()) if os.path.isdir(f)]
		csvFiles = [ os.path.abspath(f) for f in os.listdir(os.getcwd()) if f.endswith(fileExtension) and not f.endswith('modified'+fileExtension)]
		if (recursive):
			for f in subfolders:
				tmp = searchInFolder(f, fileExtension, True)
				for t in tmp:
					csvFiles.append(t)
				# go back to parent directory
				os.chdir("..")
		return csvFiles
	else:
		return None


if __name__ == '__main__':
	main()