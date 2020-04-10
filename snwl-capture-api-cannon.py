
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
# .d88888b                    oo          dP   dP   dP          dP dP 
# 88.    "'                               88   88   88          88 88 
# `Y88888b. .d8888b. 88d888b. dP .d8888b. 88  .8P  .8P .d8888b. 88 88 
#       `8b 88'  `88 88'  `88 88 88'  `"" 88  d8'  d8' 88'  `88 88 88 
# d8'   .8P 88.  .88 88    88 88 88.  ... 88.d8P8.d8P  88.  .88 88 88 
#  Y88888P  `88888P' dP    dP dP `88888P' 8888' Y88'   `88888P8 dP dP 
#
#                    -- Capture API Cannon --
#
# Written by Jaime Escalera (jescalera@sonicwall.com)
#
# About: This Python program was written for internal stress testing
# 		of the CSa 1000 Capture Appliance and the Capture API.
#
# The program will rapidly submit file samples via Capture API.
# Optionally, you can choose to only submit unknown files. The file
#	samples submitted would be supplied in a configured directory.
#	Note: MALWARE NOT INCLUDED. BRING YOUR OWN FILE SAMPLES!
# Set the number_of_passes to the number of times you would like
#	to repeat the routine.
# Set the number_of_threads to the numbeer of concurrent threads you
#	you want to run at once.
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
# Version 1.0.0 - Initial release!
# 4/8/2020 - 4/10/2020:
#	Supports threaded file hash checks and file uploads.
#	Supports CLI and cannonconfig.ini usage. Use --conf to use config file.
#	Supports reptition via number_of_passes argument/config item.
#	Supports ignoring verdicts/upload files anyway in args/config item.
#	Includes exception handling for a write operation connection time out.
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


# Imports
import requests
import argparse
import configparser
import os
from urllib3 import exceptions
from urllib import error
from capture_api import CaptureAPI, file_hash
from requests.packages import urllib3
import concurrent.futures
import threading


# Hide the certificate warnings.
urllib3.disable_warnings(exceptions.InsecureRequestWarning)


# Set a variable for the path to the local files (serverconfig.ini, etc.)
script_path = os.path.dirname(os.path.realpath(__file__))
config_file = os.path.join(script_path, 'cannonconfig.ini')


# Argument handling
argP = argparse.ArgumentParser()


# Configuration file builder code
# Call buildNewConfigFile to create a new config.ini file.
def buildNewConfigFile():
	config = configparser.ConfigParser()
	config['DEFAULT'] = {'Malware Directory': 'malware_files',
							'Capture API Server': '',
							'Capture API Serial': '',
							'Capture API Key': '',
							'Ignore Verdict': 'no',
							'Number Of Passes': '1',
							'Number Of Threads': '5'}
	with open(config_file, 'w') as configfile:
		config.write(configfile)

#buildNewConfigFile()
#exit()


# Arguments
argP.add_argument("--malware_directory", help="Provide a directory where the malware samples are stored. Default is malware_files.", type=str, default='malware_files')
argP.add_argument("--capture_api_server", help="Provide the full URL to the Capture API Server. Ex: https://capture-api-example.com ", type=str)
argP.add_argument("--capture_api_serial", help="Provide the Capture API Serial Number.", type=str)
argP.add_argument("--capture_api_key", help="Provide the Capture API Key.", type=str)
argP.add_argument("--ignore_verdict", help="Set to yes to ignore verdicts and upload files regardless of the verdict. Set to no to only upload unknown files. Default is no.", type=str, default="no")
argP.add_argument("--number_of_passes", help="Provide the number of times to repeat the routine. Default is 1.", type=str, default="1")
argP.add_argument("--number_of_threads", help="Provide the number of threads to use for file hash verdict lookups and file uploads. Default is 1.", type=str, default="1")
argP.add_argument("--conf", help="Reads configuration from cannonconfig.ini instead of command line arguments.", action='store_true')
args = argP.parse_args()

# Initialize the configuration parser for manual configuration.
config = configparser.ConfigParser()


# If --conf argument is supplied, read configuration file.
#   and override argument variables with config file values.
if args.conf:
	print("\n--Executed using --conf argument.")
	config.read(config_file)
	print("--Configuration file:", config_file)
	args.malware_directory = config['DEFAULT']['Malware Directory']
	args.capture_api_server = config['DEFAULT']['Capture API Server']
	args.capture_api_serial = config['DEFAULT']['Capture API Serial']
	args.capture_api_key = config['DEFAULT']['Capture API Key']
	args.ignore_verdict = config['DEFAULT']['Ignore Verdict']
	args.number_of_passes = str(config['DEFAULT']['Number of Passes'])
	args.number_of_threads = str(config['DEFAULT']['Number Of Threads'])


# Print Arguments
def print_arguments():
	print("--Configuration summary:")
	print("  --> Malware Directory:", args.malware_directory)
	print("  --> Capture API Server:", args.capture_api_server)
	print("  --> Capture API Serial:", args.capture_api_serial)
	print("  --> Capture API Key:", args.capture_api_key)
	print("  --> Ignore Verdict:", args.ignore_verdict)
	print("  --> Number of Passes:", args.number_of_passes)
	print("  --> Number of Threads:", args.number_of_threads)


# Print the configuration arguments on screen
print_arguments()
print("")


# Handling of incomplete input data
if args.malware_directory is False:
	print("Malware Directory was not provided.")
	exit()
elif args.malware_directory == "None" or args.malware_directory is None:
	print("Malware Directory was not provided.")
	exit()

if args.capture_api_server is False:
	print("Capture API Server was not provided.")
	exit()
elif args.capture_api_server == "None" or args.capture_api_server is None:
	print("Capture API Server was not provided.")
	exit()

if args.capture_api_serial is False:
	print("Capture API Serial was not provided.")
	exit()
elif args.capture_api_serial == "None" or args.capture_api_serial is None:
	print("Capture API Serial was not provided.")
	exit()

if args.capture_api_key is False:
	print("Capture API Key was not provided.")
	exit()
elif args.capture_api_key == "None" or args.capture_api_key is None:
	print("Capture API Key was not provided.")
	exit()

if args.ignore_verdict is False:
	print("Ignore Verdict setting was not provided.")
	exit()
elif args.ignore_verdict == "None" or args.ignore_verdict is None:
	print("MIgnore Verdict setting was not provided.")
	exit()

if args.number_of_passes is False:
	print("Number of Passes setting was not provided.")
	exit()
elif args.number_of_passes == "None" or args.number_of_passes is None:
	print("Number of Passes setting was not provided.")
	exit()

if args.number_of_threads is False:
	print("Number of Threads setting was not provided.")
	exit()
elif args.number_of_threads == "None" or args.number_of_threads is None:
	print("Number of Threads setting was not provided.")
	exit()


# Get the file size of a given file path in bytes.
def get_file_size(filepath):
	size = os.path.getsize(filepath)
	return size


# Capture API support
# Function gets the sha256 hash from each file sample in malware_drectory.
# Function returns a list of tuples where in each tuple:
# [0] is the file path, and [1] is the sha256 hash
def get_file_hashes():
	file_list = []
	# For each file in the malware folder
	for file in os.listdir(os.path.join(args.malware_directory)):
		try:
			file_path = os.path.join(args.malware_directory, file)
			sha256 = file_hash("sha256", file_path)
			file_info = (file_path, sha256)
			file_list.append(file_info)
		except:
			print("\n--Exception in get_file_hashes()!\n",
				file, "\n", 
				file_path, "\n",
				sha256, "\n", 
				file_info)
	return file_list


# Function iterates through hashes to check the
# analysis_report and avoid unnecessary file submissions.
# Checking for "unknown" from the following responses:
# "clean", "malicious", "pending", "running", and "unknown".
# Function will act on files that are unknown.
# Function accepts a list of tuples.
def capture_processing(fl):
	print("\n-- Capture ATP --")
	print("Items:", len(fl), "\n")
	api_client = CaptureAPI(args.capture_api_server, args.capture_api_serial, args.capture_api_key)
	# For each tuple in the file_list
	for i in fl:
#		print("ITEM", i[0], "\nITEM", i[1])
		try:
			status_code, report = api_client.file_report(i[1])
			print("Capture ATP response: File is", report["analysis_result"], "(SHA256:", i[1] + ")")
#			print(status_code, report)
		except ValueError as e:
			print("\nError retrieving Capture ATP file report. ValueError:", e)
		except KeyError as e:
			print("\nError retrieving Capture ATP file report. Probably due to an invalid Capture API Serial or Key. KeyError:", e)
		except requests.exceptions.ReadTimeout as e:
			print("\nError retrieving Capture ATP file report. Connection Timed Out:", e)
		except requests.exceptions.ConnectionError as e:
			print("\nError retrieving Capture ATP file report. Connection Timed Out:", e)
		# If capture API responds that file is unknown, submit the sample.
		if "unknown" in report["analysis_result"] or args.ignore_verdict == "yes":
			print("Submitting sample to Capture ATP.\n" +
		 		"--File:", str(i[0]).split('/')[-1], "(" + str(get_file_size(i[0])), "bytes)",
				"\n--SHA256 hash:", i[1])
			try:
				status_code, data = api_client.file_scan(i[0])
				if status_code == 200:
					print("\nCapture ATP response:", data['verbose_msg'], "- Scan ID:", data["scan_id"], "(HTTP", str(status_code) + ")")
				else:
					print("Capture ATP response:", data['verbose_msg'], "(HTTP", str(status_code) + ")\n")
			except ValueError as e:
				print("\nProblem submitting sample. ValueError:", e)
			except KeyError as e:
				print("\nProblem submitting sample. Probably due to an invalid Capture API Serial or Key. KeyError:", status_code, e)
			except requests.exceptions.ReadTimeout as e:
				print("\nProblem submitting sample. Connection Timed Out", e)
			except requests.exceptions.ConnectionError as e:
				print("\nProblem submitting sample. Connection Timed Out", e)
		elif "clean" in report["analysis_result"]:
			print("Skipping file submission. Capture ATP judged this to be a clean file. -->", str(i[0]).split('/')[-1], "(" + str(get_file_size(i[0])), "bytes)", "\n")
		elif "malicious" in report["analysis_result"]:
			print("Skipping file submission. Capture ATP judged this to be a malicious file. -->", str(i[0]).split('/')[-1], "(" + str(get_file_size(i[0])), "bytes)", "\n")
		elif "pending" in report["analysis_result"]:
			print("File is pending. -->", report["analysis_result"], str(i[0]).split('/')[-1], "(" + str(get_file_size(i[0])), "bytes)", "\n")
		elif "running" in report["analysis_result"]:
			print("File scan is running. -->", report["analysis_result"], str(i[0]).split('/')[-1], "(" + str(get_file_size(i[0])), "bytes)", "\n")


# Function iterates through hashes to check the
# analysis_report and avoid unnecessary file submissions.
# Checking for "unknown" from the following responses:
# "clean", "malicious", "pending", "running", and "unknown".
# Function will act on files that are unknown.
# Function accepts a tuple from a list.
def capture_process_file(i):
	api_client = CaptureAPI(args.capture_api_server, args.capture_api_serial, args.capture_api_key)
	try:
		status_code, report = api_client.file_report(i[1])
		print("Capture ATP response: File is", report["analysis_result"], "(SHA256:", i[1] + ")")
	except ValueError as e:
		print("\nError retrieving Capture ATP file report. ValueError:", e)
	except KeyError as e:
		print("\nError retrieving Capture ATP file report. Probably due to an invalid Capture API Serial or Key. KeyError:", e)
	except requests.exceptions.ReadTimeout as e:
		print("\nError retrieving Capture ATP file report. Connection Timed Out:", e)
	except requests.exceptions.ConnectionError as e:
		print("\nError retrieving Capture ATP file report. Connection Timed Out:", e)
	# If capture API responds that file is unknown, submit the sample.
	if "unknown" in report["analysis_result"] or args.ignore_verdict == "yes":
		print("Sending:", str(i[0]).split('/')[-1], "(" + str(get_file_size(i[0])), "bytes)", "SHA256 hash:", i[1])
		try:
			status_code, data = api_client.file_scan(i[0])
			if status_code == 200:
				print("Capture ATP response:", data['verbose_msg'], "- Scan ID:", data["scan_id"], "SHA256 hash:", i[1])
			else:
				print("Capture ATP response:", data['verbose_msg'], "(HTTP", str(status_code) + ")", "SHA256 hash:", i[1])
		except ValueError as e:
			print("\nProblem submitting sample. ValueError:", e)
		except KeyError as e:
			print("\nProblem submitting sample. Probably due to an invalid Capture API Serial or Key. KeyError:", status_code, e)
		except requests.exceptions.ReadTimeout as e:
			print("\nProblem submitting sample. Connection Timed Out", e)
		except requests.exceptions.ConnectionError as e:
			print("\nProblem submitting sample. Connection Timed Out", e)
	elif "clean" in report["analysis_result"]:
		print("Skipping file submission. Capture ATP judged this to be a clean file. -->", str(i[0]).split('/')[-1], "(" + str(get_file_size(i[0])), "bytes)", "\n")
	elif "malicious" in report["analysis_result"]:
		print("Skipping file submission. Capture ATP judged this to be a malicious file. -->", str(i[0]).split('/')[-1], "(" + str(get_file_size(i[0])), "bytes)", "\n")
	elif "pending" in report["analysis_result"]:
		print("File is pending. -->", report["analysis_result"], str(i[0]).split('/')[-1], "(" + str(get_file_size(i[0])), "bytes)", "\n")
	elif "running" in report["analysis_result"]:
		print("File scan is running. -->", report["analysis_result"], str(i[0]).split('/')[-1], "(" + str(get_file_size(i[0])), "bytes)", "\n")


# Function accepts the file hash list containing tuples.
# The list is passed to executor.map where the capture_process_file
# function is called with the file list passed into it
# Iterate through the file list and create the worker threads.
def threaded_processing(fl):
    with concurrent.futures.ThreadPoolExecutor(max_workers=int(args.number_of_threads)) as executor:
        executor.map(capture_process_file, fl)


# Run the routine. Routine is repeated if the number of passes is more than 1.
for i in range(0,int(args.number_of_passes)):
	file_list = get_file_hashes()
#	capture_processing(file_list) # Single-threaded function.
	threaded_processing(file_list)