import socket, sys, threading, os, re, ipaddress, time
from manuf import manuf

def TCP_connect(ip, port_number, delay, output):
    TCPsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    TCPsock.settimeout(delay)
    try:
        TCPsock.connect((ip, port_number))
        output[port_number] = 'Open'
    except:
        output[port_number] = ''


# check to see which ports are open
def scan_ports(host_ip, delay, maxport):

    maxport = maxport + 1   # due to behavior of range function, we want maxport to be included
    threads = []        # To run TCP_connect concurrently
    openports = []
    output = {}         # For printing purposes

    # Spawning threads to scan ports
    for i in range(maxport):
        t = threading.Thread(target=TCP_connect, args=(host_ip, i, delay, output))
        threads.append(t)

    # Starting threads
    for i in range(maxport):
        threads[i].start()

    # Locking the script until all threads complete
    for i in range(maxport):
        threads[i].join()

    # Printing listening ports from small to large
    for i in range(maxport):
        if output[i] == 'Open':
            openports.append(i)
            #print('    Port ' + str(i) + ': ' + output[i])
    return openports


# determine vendor based on mac address
def get_vendor(mac):
    p = manuf.MacParser(update=True)
    man = p.get_manuf(mac)
    if man is None:
        return ''
    else:
        return man

def validate_mask(s):
    mask_vals = [0, 128, 224, 240, 248, 252, 254, 255]
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i not in mask_vals:
            return False
    return True


def validate_ip(s):
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True

# make sure that output of arp command matches a format that we expect
def validwindowsarp(test):
    pattern = '(\d{1,3}\.){3}\d{1,3}\s*?([a-f0-9]{2}-){5}[a-f0-9]{2}'
    if re.search(pattern, test) is not None:
        return True
    return False

#execute arp command on command line to collect list of devices on local network
def parsewindows():
    arp_output = os.popen('arp -a', mode='r').read()
    arp_output = arp_output.split('\n')
    devices = []

    #parse arp output
    for line in arp_output:
        if validwindowsarp(line):
            ip_address = line.split()[0]
            mac_address = line.split()[1]
            devices.append({'ip': ip_address, 'mac': mac_address})

    return devices

def parsemac():
    arp_output = os.popen('arp -a', mode='r').read()
    arp_output = arp_output.split('\n')[3:-1]
    devices = []
    for line in arp_output:
        dhcp_bs = line.split()[0]
        ip_address = line.split()[1].strip('(').strip(')')
        at_bs = line.split()[2]
        mac_address = line.split()[3]
        devices.append({'ip': ip_address, 'mac': mac_address})
    return devices


def findipsub():
    config = os.popen('ipconfig', mode='r').read()
    config = config.split('\n')
    ip = '0.0.0.0'
    mask = '0.0.0.0'
    for l in config:
        line = l.split()
        if 'IPv4 Address' in l:
            ip = line[-1]
        if 'Subnet Mask' in l:
            mask = line[-1]
    return ip, mask


def pingsweep(network):
    for ip in ipaddress.ip_network(network, strict=False):
        os.popen('ping ' + str(ip), mode='r')
    #time.sleep(0.5)

# Print iterations progress
def printProgressBar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█'):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print('\r%s |%s| %s%% %s' % (prefix, bar, percent, suffix), end = '\r')
    # Print New Line on Complete
    if iteration == total:
        print()
