#!/usr/bin/env python3

import requests
import sys
import re
import os	

user = ""
password = ""
# Change this with path up hs/ directory. Can also be just a file
# If left None the script expects the first argument to be a file/directory to upload
folder = None

credentials = {"username": user, "password": password}

# Web links
login_page = "https://pandorak.go.ro/login/"
upload_page = "https://pandorak.go.ro/upload/"

# Regex for upload codes
upload_error_re = re.compile("<div style='color:red'>(.*?)</div>")
upload_success_re = re.compile("<div style='color:green'>(.*?)</div>")

# Session variable
ses = requests.session()

# Files to be uploaded
files = []


def fatal(s):
	error(s)
	sys.exit(-1)


def error(s):
	print('\033[31m' + s + '\033[0m', file=sys.stderr)


def success(s):
	print('\033[32m' + s + '\033[0m')


def login():
	ret = ses.post(login_page, credentials)

	# Check for errors
	if int(ret.status_code) != 200:
		fatal("Error code %s at login!" % str(ret.status_code))

	# Check if login credentials are correct
	if "Incorrect username/password!" in ret.text:
		fatal("Incorrect username/password!")


def send_file(file_name):
	with open(file_name, "rb") as fd:
		ret = ses.post(upload_page, files={"file": fd})

		if int(ret.status_code) != 200:
			fatal("Error code %s at upload!" % str(ret.status_code))

		# Turn returned text into a oneline for easy regex match
		one_line = re.sub(r"[\n\t\r]*", "", ret.text)

		match = upload_error_re.search(one_line)

		if match is not None:
			error("Error uploading %s: %s" % (file_name, match.group(1)))
			return

		match = upload_success_re.search(one_line)

		if match is not None:
			url_decode = match.group(1).replace("&#39;", "'")
			success(url_decode)
			# Uncomment if you want to delete file after upload
			# os.remove(file_name)
			return

		fatal("Unspecified error: %s" % ret.text)


if folder is None:
	if len(sys.argv) < 2:
		fatal("Use with %s <capture/capture_folder>" % sys.argv[0])
	folder = sys.argv[1]

if os.path.isdir(folder):
	files = [f for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]
	print("You are about to send:")
	for file in files:
		print(file)
	sys.stdout.write("Please confirm (y/n):")
	sys.stdout.flush()
	text = input()
	if text.lower()[0] != 'y':
		sys.exit(0)
elif os.path.isfile(folder):
	files.append(folder)
else:
	fatal("File/folder %s does not exist" % folder)

login()

# Upload file one by one so we minimize amount of max_size errors
for file in files:
	send_file(file)
