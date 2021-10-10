from scapy.layers.l2 import arping  # arping is the base for the scan.
import netifaces  # a good library for getting the ip from an interface.
import argparse  # argparse will be used for parsing the arguments.
import sys  # for exiting the program if there's an error on the options.
import os  # for determining permissions on linux.
import ctypes  # for determining permissions on windows.
import concurrent.futures as futures  # for threading the scanner runtimes.
import multiprocessing  # for bypassing the GIL.
import itertools  # for easier ip generation.

# argument parsing.

argumentParser = argparse.ArgumentParser(description="A fast and powerful ARP based network scanner")

argumentParser.add_argument("target", metavar="target", help="the network interface or which the program will use")
argumentParser.add_argument("--use_ip", help="specifies to the target that an ip will be used", action="store_true")
argumentParser.add_argument("--timeout", metavar="seconds", help="scan response timeout, defaults to 2 seconds",
                            default=2, type=int)
argumentParser.add_argument("--process_threads", metavar="process_threads", type=int, default=256,
                            help="how many threads run in each processs, defaults to 256")
argumentParser.add_argument("--process_num", metavar="process_number", type=int, default=20,
                            help="how many process run, defaults to 20")
argumentParser.add_argument("--output", metavar="filename", type=str, default=None,
                            help="where to save the output, wont save if not specified")
argumentParser.add_argument("--subnets", metavar="levels", help="how many subnet levels scan, defaults to one",
                            default=1, type=int)

arguments = argumentParser.parse_args()  # parse and store all arguments into this variable.


# functions declarations. Keep reading the code past this area and come back when a function is used

def is_admin():
    # tries getting the uid for linux. If it doesnt work, it will try checking for windows using ctypes.
    try:
        admin_bool = (os.getuid() == 0)  # check for linux.
    except AttributeError:
        admin_bool = ctypes.windll.shell32.IsUserAnAdmin() != 0  # check for windows.
    return admin_bool


def scan_ip(target):
    # check if result[0][0] exists(successful answer), if it does, return the target ip.
    # if we are using an ip, we dont know which interface specify to arping.
    if arguments.use_ip:
        result = arping(target, timeout=arguments.timeout, verbose=0)
    # if we are using an interface, then we specify it.
    else:
        result = arping(target, timeout=arguments.timeout, verbose=0, iface=arguments.target)
    # check if element exists in the result using try-catch.
    try:
        var = result[0][0]  # tries to get the element.
        return target  # returns the ip.
    except IndexError:
        pass  # doesnt do anything if there's an error.


def generate_ip(octets):
    # add a dot after every octet except at the end which will be added as is
    octets_formatted = [x + "." for x in octets[:-1]] + list(octets[-1])
    return ipTemplate + "".join(octets_formatted)  # join the list to the template and return it.


def scanner_process(ip_list):
    # thread the map function that executes the scanner.
    with futures.ThreadPoolExecutor(max_workers=arguments.process_threads) as executor:
        results = [*executor.map(scan_ip, ip_list)]  # get the results from map and unpack them into a list.
        hosts = [x for x in results if x is not None]  # remove the empty results.
        return hosts  # return our found hosts to the process pool

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

host_ip = ""  # the place where the ip is going to be stored at the end of the verification.
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
    host_ip = arguments.ip  # after the verifications set the host ip to the target
else:
    # checks if it can fetch the ip from the interface name, if it cant, then its invalid.
    try:
        host_ip = netifaces.ifaddresses(arguments.target)[netifaces.AF_INET][0]["addr"]
    # if netifaces cant find the network interface, we will try to check the ip for none, it will throw a ValueError.
    except ValueError:
        print("[-]ERROR: The provided network interface isn't valid!")
        sys.exit(2)

# ip template generation, we are going to feed it to the scanning section where we will generate all its variations.

# we need to find the dot index, we reverse the ip and find the first one's, which will be the last.
reversedIp = [*reversed(host_ip)]
octetsToDelete = arguments.subnets  # how many octets we want to delete.
# we repeat the octet deleting process how many times we need to.
for x in range(octetsToDelete):
    # we find the last dot(the first one reversed) and then remove it and the octet.
    sliceEndPosition = reversedIp.index(".")
    reversedIp = reversedIp[sliceEndPosition + 1:]  # plus one because we want to remove the dot too.
# we convert our reversed list to a normal string and add a dot at the end.
ipTemplate = "".join(map(str, reversed(reversedIp))) + "."


# ip generation
# tuple of strings containing all the possible octets of the ip
combinations_tuples = tuple(itertools.product(map(str, range(256)), repeat=arguments.subnets))
# generate a list of all the possible ip's using combinations_tuple and ipTemplates with generate_ip.
ip_combinations = [*map(generate_ip, combinations_tuples)]
# split all the ip's for the processes
ip_split = []  # list where we are gonna store all the split ip's
for x in range(0, len(ip_combinations), 256):  # i want every process to scan 256 ip's, that's the step of 256.
    # even if x + 256 got out of range, python will just omit those illegal index's
    ip_split.append(ip_combinations[x:x + 256])

# scanning

# the process spawning pool
with multiprocessing.Pool(arguments.process_num) as executor:
    results = executor.map(scanner_process, ip_split)  # run our scanner process using map.
    activeHosts = [x for x in [*results] if results is not []]  # remove our null returns.
    activeHosts = [y for x in activeHosts for y in x]  # merge our sublists into one list.


# output
outStr = ""  # the place were we are gonna dump the list into a string.
for x in activeHosts:
    outStr += x + "\n"  # append the ip plus a newline.

print(outStr)

if arguments.output is not None:  # check if we should write the output to a file.
    fileToWrite = open(arguments.output, "w")
    fileToWrite.write(outStr)
    fileToWrite.close()
