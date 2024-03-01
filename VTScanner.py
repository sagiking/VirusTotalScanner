import virustotal_python
from pprint import pprint
import datetime
import argparse
import os
import hashlib
import threading
import queue
import sys

MIN_MALICIOUS = 1
DATE_FORMAT = "%d.%m.%Y %H;%M;%S"
WRITE = 'w'
READ_BINARY = 'rb'
DESCRIPTION = "Scan tool with Virus Total (c) 2024 by Sagi Vultur"
VT_ERROR429 = 'You have exceeded one of your quotas (minute, daily or monthly). Daily quotas are reset every day at 00:00 UTC.'\
            'You may have run out of disk space and/or number of files on your VirusTotal Monitor account.'


def main():
    full_date = datetime.datetime.now()
    date = full_date.strftime(DATE_FORMAT)
    
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("-f" ,"--file", type=str,
                        help="File to scan", metavar='File')
    
    parser.add_argument("-d" ,"--dir", type=str,
                        help="Directory to scan", metavar='Directory')
   
    parser.add_argument("-k" , "--key", type=str, metavar='API_KEY', required=True,
                        help="Insert your VT API key")
    
    parser.add_argument("-t" , "--thread_number", type=int, default = 4,
                        help="Define your threads number, The default is 4")
    
    parser.add_argument("-v" , "--verbose", action='store_true',
                        help="Show advanced output")
    
    parser.add_argument("-o" , "--output", type=str, default = ".\\", metavar='Directory_Output',
                        help="Directory for the output, The default is your current directory")
    args = parser.parse_args()

    # The user selected to scan a direcotry
    if args.dir:

        # Checking if the directory exists
        if not os.path.isdir(args.dir):
            print("Invaild Input, please insert a valid directory")
            sys.exit(1) 
        
        queue_ = queue.Queue()
        scan_threads = []

        # Looping through all the files in the directory and inserting the path and md5 hash into a queue
        for root, dirs, files in os.walk(args.dir): 
            for file_name in files:
                file_path = (f'{root}\{file_name}')
                file_hash = get_md5(file_path)
                queue_.put((file_path, file_hash))


        # Creating threads 
        for i in range(0, args.thread_number):
            scan_thread = threading.Thread(target=thread_scan_file, args=(args.key, file_name, args.verbose, args.output, date, queue_))
            scan_thread.start()
            scan_threads.append(scan_thread)

        for thread in scan_threads:
            thread.join()


                                
    # The user selected to scan a single file
    elif args.file:

        # Checking if the file exists
        if not os.path.isfile(args.file):
            print("Invaild Input, please insert a valid file")
            sys.exit(1)
            
        file_name = os.path.basename(args.file)
        file_hash = get_md5(args.file)

        # The program was able to get the md5 hash value of the file
        if file_hash:
            scan_file(args.key, file_hash, file_name, args.verbose, args.output, date)
        else:
            if args.verbose:
                print(f"Permmision Denied to open the file {file_name}")
                
    # The user didn't selected a file\direcotry to scan
    else:
        print("Invaild Input, please insert File OR Directory to scan")
        sys.exit(1)


# Function using threads to scan a directory
def thread_scan_file(api_key, file_name, verbose, output, date, queue_):

    # While there are files
    while not queue_.empty():
        file_path, file_hash = queue_.get()

        # The program was able to get the md5 hash value of the file
        if file_hash:
            scan_file(api_key , file_hash, file_path, verbose, output, date)
        else:
            if verbose:
                print(f"Permmision Denied to open the file {file_name}")
    return


# Get a file and returns his md5 hash value
def get_md5(file_path):
    try:
        # Open to read the file content
        with open(file_path, READ_BINARY) as file_to_check:
            data = file_to_check.read()    
            file_md5 = hashlib.md5(data).hexdigest()
        return file_md5

    # Can't open the fole for permission reasons
    except PermissionError:
        return


# Scan a file and send him to VT servers, if the file is malicious he will save the data in a file
def scan_file(api_key, file_hash, file_path, verbose, output_path, date):
    av_detects = 0
    with virustotal_python.Virustotal(api_key) as vtotal:
        try:
            resp = vtotal.request(f"files/{file_hash}")

        # Catch Exceptions of the request
        except virustotal_python.virustotal.VirustotalError as err:

            # Too much requests, VT Limit the free account to 500 requests per day
            if 'Error QuotaExceededError (429)' in str(err):
                print(VT_ERROR429)
                sys.exit(1)

            # VT isn't familiar this file
            elif 'NotFoundError' in str(err):
                if verbose:
                    print(f'File {file_path} was not found in VirusTotal!')
                return
            else:
                print(err)
                
    av_detects = resp.data['attributes']['last_analysis_stats']['malicious']

    # Checking if any of the AV flagged the file as malicious
    if av_detects > MIN_MALICIOUS:
        print(f'DETECTED: {av_detects} AV flagged the file {file_path} as malicious')
        output_path = rf'{output_path}\[{date}]-[{os.path.basename(file_path)}].txt'
        try:
            # Recording the scan information in a file
            with open(output_path, WRITE) as file:
                pprint(resp.data, file)

        # Can't save the log file in the requested path
        except PermissionError:
             print('ERROR: Cant save output in the requested directory, please try a diffrent output directory')
             sys.exit(1)
    return


if __name__ == "__main__":
    main()



