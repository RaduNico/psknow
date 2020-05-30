```
______  _____ _   __                    
| ___ \/  ___| | / /                    
| |_/ /\ `--.| |/ / _ __   _____      __
|  __/  `--. \    \| '_ \ / _ \ \ /\ / /
| |    /\__/ / |\  \ | | | (_) \ V  V / 
\_|    \____/\_| \_/_| |_|\___/ \_/\_/  

```

PSKnow is a project meant to assist multiple users in assessing strength of wifi password.
It consists of two components, the backend and the crackers.
Currently PSKnow is developed in an Xubuntu 18.04 environment

# Cracker


The cracker consist of an interactive python3 script which can be run by API enabled users in order to request
jobs from the backend. Jobs consist in an authentication capture and one of the [rules](README.md#rules). The
cracker decodes the rule and starts a `hashcat` and/or a `john` process - depending on the rule data. When the
process finishes the cracker sends the outcome of the job to the backend. At this point the job resulted in
retrieving the password or the passwrod is not contained in this rule.

### Dependencies


As external dependecies you need to have the programs below system wide installed:
* [`hashcat`](https://github.com/hashcat/hashcat): Running the cracking jobs


[`John the ripper`](https://github.com/magnumripper/JohnTheRipper) is also necessary in order to run some of the rules but it is not required. In the current form
john the ripper is only used for dictionary mangling, but it is planned to have some rules run on john only.
Two extra steps need to be takend for the cracker to be able to used john the ripper:
1) Configuring the path to the john executable inside the `cracker.conf` file, on the "john_path" property.
   This needs to be done because john the ripper cannot easily be installed system wide while compiling from source
2) Open the file `run/john.conf`  and uncomment the line `#.include './john-local.conf'` by removing the '#'. This
   is needed in order to run custom rules sent from the backend.

### Configuration


The cracker needs some basic configuration in order to run. This is done by modifying the file `cracker.conf` as such:
 * apikey: This is a needed parameter in order for the cracker to run. An api key can be generated from the /api/ path
           on the backend
 * server_location: The website where the backend is running

Optional configuration:
 * hashcat_workload: This is the workload profile parameter used by hashcat. It can be between 1 and 4 where 1 means
                     it wont put too much load on the machine but it will be the slowest in terms of computing power
                     and 4 which will run the fastest but it might make the machine's graphical interface very unresponsive
 * john_path: As detailed above the path to the john the ripper executable. Needed to use for rules that run john the ripper

### Run


To run the cracker use:
```bash
export PYTHONPATH='.'
python3 psknow_cracker.py
```
Note: in the current implementation the cracker needs to be ran from the cracker/ directory, else john the ripper will
      not properly work


# Backend


The backend consists of a flask web application and is the part of the project that the users interact with.
Regular users can freely register on the platform and upload packet capture files containing WPA authentications or
"PMKID files" as obtained by using `hcxpcaptool` on a capture.

Another function that the backend fulfills is to assign jobs whenever a cracker requests one. A job consists of a
handshake/PMKID uploaded by a user and one of the [rules](README.md#rules).

### Dependencies


To install python dependencies use:
```bash
pip3 install -r requirements.txt
```

As external dependecies you need to have the programs below system wide installed. It is recommended that you install
these programs by compiling the from source to insure the latest version is used.


* [`aircrack-ng`](https://github.com/aircrack-ng/aircrack-ng): Used to test uploaded passwords by the crackers.
* [`hcxpcaptool`](https://github.com/ZerBea/hcxtools): For converting capture files to the [`hccapx`](https://hashcat.net/wiki/doku.php?id=hccapx) format
* [`hashcat`](https://github.com/hashcat/hashcat):  Verify handshake/PMKID presence in uploaded data. See note below

Despite hashcat being a requirement, no GPU needs to be installed on the system running the backend as hashcat is only
used to verify that a capture files contains a valid handshake/PMKID and to extract data from said handshake (ESSID/BSSID).

External dependencies which can be installed with apt are:
 * [mongodb](https://www.mongodb.com/): The database used to store information. This might be removed in the future in favor of a more lightweight database solution.
 * [gunicorn3](https://gunicorn.org/): The wsgi server
To install those dependencies use:
```bash
sudo apt-get install gunicorn3 mongodb

```

### Run

To run the backend use:
```bash
export PYTHONPATH='.'
gunicorn3 -t 900 --workers 2 --bind 127.0.0.1:9645 wsgi --access-logfile logs/access.log --error-logfile logs/errors.log -c gunicorn_config.py
```


### Rules

Rules come in the form of a json file. Every rule has these properties
 * `name`: Mandatory. The name of the rule. Needs to be unique
 * `type`: Mandatory. The rule type determines how it behaves - try a dictionary file or bruteforce all 8 digits
 * `priority`: Mandatory. The priority determines the order in which the rules should be ran. A lower priority means
               a rule should be ran before other higher priorities. NOTE: the scheduler might decide to choose a higher
               priority rule in some specific cases
 * `path`: The path to the resource it will use. The meaning changes depending on the rule type
 * `wordsize`: Mandatory. The number of items contained in the rule (ex. a dictionary of 10.000 entries/lines has a wordsize of 10.0000)
 * `desc`: Short description presented to the user to explain what the rule does
 * `examples`: A short list of examples of words present in the rule
 * `reqs`: The requirements needed by the cracker in order to run this rule. Based on this list it is determined whether the cracker can run a rule or not
 * `link`: The download link for some of the requirements (ex. If a dictionary is needed this provides where that dictionary is available)

### RuleTypes
TODO
