import socket, sys, threading, os
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
            print('    Port ' + str(i) + ': ' + output[i])


# determine vendor based on mac address
def get_vendor(mac):
    p = manuf.MacParser(update=True)
    man = p.get_manuf(mac)
    if man is None:
        return ''
    else:
        return man


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


#execute arp command on command line to collect list of devices on local network
def parsewindows():
    arp_output = os.popen('arp -a', mode='r').read()
    arp_output = arp_output.split('\n')[3:-1]
    devices = []

    #parse arp output
    for line in arp_output:
        ip_address = line.split()[0]
        mac_address = line.split()[1]
        devices.append({'ip': ip_address, 'mac': mac_address})

    return devices