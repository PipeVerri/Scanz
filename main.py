from scapy.all import arping # scapy will be the base for the scannig requests
import netifaces # a good library for getting the ip from an interface
import argparse # argparse will be used for parsing the arguments
import sys, os, ctypes # sys for exitting and args checking, os and ctypes for determining if the program is running as root
import threading, multiprocessing # for fast scan times

# argument parsing
argumentParser = argparse.ArgumentParser(description="A fast and powerful ARP based network scanner")
argumentParser.add_argument("target", metavar="target", help="the network interface where the ip will be get from, if the ip flag is specified it will take the input as the ip directly", type=str)
argumentParser.add_argument("--ip", help="if specified, the program will expect you to provide the ip and not the interface name to the network_interface argument", action="store_true")
argumentParser.add_argument("--timeout", metavar="seconds", help="scan response timeout, defaults to 2 seconds", default=2, type=int)
argumentParser.add_argument("--subnetting", metavar="levels", help="hoe many subnetting levels go deep, defaults to one", default=1, type=int)
arguments = argumentParser.parse_args() # parse and store all arguments into this variable

# function declaration

def isAdmin():
    try:
        is_admin = (os.getuid() == 0)
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    return is_admin

# permission verification and simple argument verification

if not isAdmin():
    # print error message and exit the program
    print("[-]ERROR: You need to run the program as root!")
    sys.exit(2)
if arguments.subnetting > 4:
    print("[-]ERROR: A subnetting level higher than four is impossible, check the documentation!")

# target verification

ip = "" # the place where the ip is going to be stored at the end of the verification
# if an ip is going to be feeded, validate the ip. If an interface name is going to be feeded, validate the interface name.
if arguments.ip:
    # check if any octet(fragment) of the ip is higher than 255, if it is, the ip cant be valid and it will exit
    # if it couldn't convert the octets into ints, it means there are chars inside the octets, wich returns a ValueError
    try:
        if True in [int(x) > 255 for x in arguments.target.split(".")]:
            print("[-]ERROR: The ip isn't valid!")
            sys.exit(2)
    except ValueError:
        print("[-]ERROR: The ip contains characters into it!")
        sys.exit(2)

else:
    # checks if it can fetch the ip from the interface name, if it cant, then its invalid
    try:
        ip = netifaces.ifaddresses(arguments.target)[netifaces.AF_INET][0]['addr']
    except ValueError:
        print("[-]ERROR: The provided network interface isn't valid!")
        sys.exit(2)

