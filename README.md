# Key reinstallation attack against Android and Linux devices

## DIPENDANCIES:
This script must be run in Kali Linux, ensure that all the dependancies are installed 
```bash
apt-get update and pip update 
apt-get install libnl-3-dev libnl-genl-3-dev pkg-config libssl-dev net-tools git sysfsutils python-scapy python-pycryptodome
pip install docopt
```
To compile hostapd, navigate to the hostapd directory
``` bash
cp defconfig .config
make -j 2
```
May need to disable hardware encryption
used --disable-hw to do so, then reboot to take effect

All the files to run the exploit are located in the folder "krackattack"
krack-zero-key.py is the main script
libclass.py is a class library for the main script

## RUNNING THE SCRIPT:

USE:
-h or --help
This will print the help message and usage parameters
requires 2 interfaces, both need to be compatible with Kali and be able to run in monitor mode.
The interfaces used in testing are:

	TP-Link WN722N
	ArrisGro wireless adapter with a Ralink chipset

Note: Some adapters may not detect when a frame is injected despite checks, this can cause a feedback loop in the script. Move the interface's further appart from each other (<1 meter), or swape their roles in the script

Note: If error Too many files open in system occours, run with -r option to reset
the interface configuration. If the error still persists, then run the script without --target

OPTIONS:
```bash
-k - This will run the key reinstalltion attack
-r - Cleans up configuration done by the script, useful in the event of a crash
-v - Gives verbose output, this shows the pink debug message
--vv - Gives loads of verbose output - WARNING - shows all frames send and recived, including beacons
--target - it's reccomended to use a specific target device (Mac address), if two devices connect without a target then the 			attack might not complete
--disable-hw - to disable hardware encryption, it might interfere with the script
```
##EXAMPLE:
Launches the attack:
```bash
python krack-zero-key.py -k wlan0 wlan1 eduroam --target ff:ff:ff:ff:ff:ff 
```
Cleans up (the interfaces must be entered in the same order as when the script was last run):
```bash
python krack-zero-key.py -r wlan0 wlan1
```
