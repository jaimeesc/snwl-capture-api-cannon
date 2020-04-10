# snwl-capture-api-cannon
A Python tool to check Capture ATP verdicts and upload file samples via Capture API.

>py snwl-capture-api-cannon.py -h

usage: snwl-capture-api-cannon.py [-h] [--malware_directory MALWARE_DIRECTORY] [--capture_api_server CAPTURE_API_SERVER]

                                 [--capture_api_serial CAPTURE_API_SERIAL] [--capture_api_key CAPTURE_API_KEY]

                                 [--ignore_verdict IGNORE_VERDICT] [--number_of_passes NUMBER_OF_PASSES]

                                 [--number_of_threads NUMBER_OF_THREADS] [--conf]



optional arguments:

 -h, --help           show this help message and exit

 --malware_directory MALWARE_DIRECTORY

                       Provide a directory where the malware samples are stored. Default is malware_files.

 --capture_api_server CAPTURE_API_SERVER

                       Provide the full URL to the Capture API Server. Ex: https://capture-api-example.com

 --capture_api_serial CAPTURE_API_SERIAL

                       Provide the Capture API Serial Number.

 --capture_api_key CAPTURE_API_KEY

                       Provide the Capture API Key.

 --ignore_verdict IGNORE_VERDICT

                       Set to yes to ignore verdicts and upload files regardless of the verdict. Set to no to only upload unknown files.

                       Default is no.

 --number_of_passes NUMBER_OF_PASSES

                       Provide the number of times to repeat the routine. Default is 1.

 --number_of_threads NUMBER_OF_THREADS

                       Provide the number of threads to use for file hash verdict lookups and file uploads. Default is 1.

 --conf               Reads configuration from cannonconfig.ini instead of command line arguments.

