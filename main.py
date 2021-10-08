from scapy.layers.l2 import arping  # arping is the base for the scan.
import netifaces  # a good library for getting the ip from an interface.
import argparse  # argparse will be used for parsing the arguments.
import sys  # for exiting the program if there's an error on the options.
import os  # for determining permissions on linux.
import ctypes  # for determining permissions on windows.
import concurrent.futures  # for faster runtimes.
import itertools  # for easier ip generation.

# argument parsing.

argumentParser = argparse.ArgumentParser(description="A fast and powerful ARP based network scanner")

argumentParser.add_argument("target", metavar="target", help="the network interface or which the program will use")
argumentParser.add_argument("--use_ip", help="specifies to the target that an ip will be used", action="store_true")
argumentParser.add_argument("--timeout", metavar="seconds", help="scan response timeout, defaults to 2 seconds",
                            default=2, type=int)
argumentParser.add_argument("--threads", metavar="threads", help="how many threads run, defaults to 256", default=256,
                            type=int)
argumentParser.add_argument("--subnets", metavar="levels", help="how many subnet levels scan, defaults to one",
                            default=1, type=int)

arguments = argumentParser.parse_args()  # parse and store all arguments into this variable.


# function declaration.

def is_admin():
    # tries getting the uid for linux. If it doesnt work, it will try checking for windows using ctypes.
    try:
        admin_bool = (os.getuid() == 0)  # check for linux.
    except AttributeError:
        admin_bool = ctypes.windll.shell32.IsUserAnAdmin() != 0  # check for windows.
    return admin_bool


def scan_ip(target):
    # check if element exists(successful answer), if it does, return true to the filter function.
    result = arping(target, timeout=arguments.timeout, verbose=0)
    # safely check index using slicing.
    if not result[0:1][0:1]:
        return False
    else:
        return True


# permission verification and simple argument verification.

if not is_admin():
    # the program needs to run as administrator to create the ARP packages.
    print("[-]ERROR: You need to run the program as root!")
    sys.exit(2)
# there's only four octets on an ipv4 ip
if arguments.subnets > 3:
    print("[-]ERROR: A subnet level higher than four is will be an empty ip, check the documentation!")
    sys.exit(2)
# target verification

ip = ""  # the place where the ip is going to be stored at the end of the verification.
# if an ip is going to be fed, validate the ip. But if an interface name is going to be fed, validate the interface.
if arguments.use_ip:
    # check if any octet(fragment) of the ip is higher than 255, if it is, the ip cant be valid and it will exit.
    # if it couldn't convert an octet into int, it means there is a char inside the octet, which returns a ValueError.
    try:
        # use a list comprehension to check if any of the octets is higher than 255.
        if True in [int(x) > 255 for x in arguments.target.split(".")]:
            print("[-]ERROR: The ip isn't valid!")
            sys.exit(2)
    # if it cant convert an octet to int, it means there's probably a char there.
    except ValueError:
        print("[-]ERROR: The ip contains characters into it!")
        sys.exit(2)

else:
    # checks if it can fetch the ip from the interface name, if it cant, then its invalid.
    try:
        ip = netifaces.ifaddresses(arguments.target)[netifaces.AF_INET][0]["addr"]
    # if netifaces cant find the network interface, we will try to check the ip for none, it will throw a ValueError.
    except ValueError:
        print("[-]ERROR: The provided network interface isn't valid!")
        sys.exit(2)

# ip template generation, we are going to feed it to the scanning section where we will generate all its variations.

# we need to find the dot index, we reverse the ip and find the first one's, which will be the last.
reversedIp = [*reversed(ip)]
octetsToDelete = arguments.subnets  # how many octets we want to delete.
# we repeat the octet deleting process how many times we need to.
for x in range(octetsToDelete):
    # we find the last dot(the first one reversed) and then remove it and the octet.
    sliceEndPosition = reversedIp.index(".")
    reversedIp = reversedIp[sliceEndPosition + 1:]  # plus one because we want to remove the dot too.
# we convert our reversed list to a normal string and add a dot at the end.
ipTemplate = "".join(map(str, reversed(reversedIp))) + "."
