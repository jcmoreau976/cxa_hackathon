import os
import sys
import ipaddress
import hackathon
import getopt
import argparse
from prettytable import PrettyTable

usage = '\nEx: python main.py [-c 192.168.1.0/24] [-s subnet -m netmask] [-p ports] \n'
network = '0.0.0.0/0'   # search all subnets by default
ports = 1024            # scan 1024 ports by default
timeout = 0.5           # 0.5 second port scan timeout default
vendors = {}
skip_arp = False

parser = argparse.ArgumentParser()
parser.add_argument('--network', '-c', help='Subnet in CIDR notation', default='0.0.0.0/0')
parser.add_argument('-n', dest='skip', action='store_true', help='Skip ARP table update', default=False)
parser.add_argument('-p', '--ports', help='Range of ports to scan for each device', default=1024)
parser.add_argument('-t', '--timeout', help='Time to wait for each port connection', default=0.5, type=float)
args = parser.parse_args()
network = args.network
skip_arp = args.skip
timeout = args.timeout

# try:
#     opts, r = getopt.getopt(sys.argv[1:], 't:c:s:m:p:')
# except getopt.GetoptError:
#     print(usage)
#     sys.exit('ERROR: Bad input')
#
#
# for o, a in opts:
#     if o == '-c':
#         network = a
#     elif o == '-s':
#         subnet = a
#     elif o == '-m':
#         mask = a
#     elif o == '-p':
#         ports = int(a)
#     elif o == '-t':
#         timeout = float(a)
#     elif o == '-n':
#         skip_arp = True
#     else:
#         assert False, usage

if not hackathon.validate_ip(subnet):
    print('Invalid subnet given. Subnet must be given as three octet string, ex: \'192.168.1.0\'')
    sys.exit('Bad subnet input')

if not hackathon.validate_mask(mask):
    print('Invalid subnet mask given.')
    sys.exit('Bad mask input')

local_ip, local_mask = hackathon.findipsub()

if not skip_arp:
    hackathon.pingsweep(local_ip + '/' + local_mask)

if sys.platform == 'win32':
    devices = hackathon.parsewindows()
else:
    devices = hackathon.parsemac()

devices_in_network = 0

for device in devices:
    addr = ipaddress.ip_address(device['ip'])
    if addr in ipaddress.ip_network(network, strict=False):
        devices_in_network = devices_in_network + 1

i = 0
print('Scanning ports...')
hackathon.printProgressBar(0, devices_in_network, prefix='Progress: ',suffix='Complete',length=50)

for device in devices:
    device['vendor'] = ''
    device['ports'] = []
    addr = ipaddress.ip_address(device['ip'])
    #check whether device is in subnet we're looking at
    if addr in ipaddress.ip_network(network, strict=False):
        i = i + 1
        device['vendor'] = hackathon.get_vendor(device['mac'])
        device['ports'] = hackathon.scan_ports(device['ip'], delay=timeout, maxport=ports)
        if device['vendor'] not in vendors:
            vendors[device['vendor']] = 1
        else:
            vendors[device['vendor']] = vendors[device['vendor']] + 1
    hackathon.printProgressBar(i, devices_in_network,
                               prefix='Progress: {} of {} devices scanned'.format(i, devices_in_network),
                               suffix='Complete', length=50)

vendors['Unknown'] = vendors['']
del vendors['']

device_table = PrettyTable()
device_table.field_names = ['IP', 'Open Ports', 'Manufacturer']
device_table.title = 'Devices'

for device in devices:
    addr = ipaddress.ip_address(device['ip'])
    if addr in ipaddress.ip_network(network, strict=False):
        try:
            firstport = device['ports'][0]
        except IndexError:
            firstport = ''
        device_table.add_row([addr, firstport, device['vendor']])
        for port in device['ports'][1:]:
            device_table.add_row(['', port, ''])

vendor_table = PrettyTable()
vendor_table.title = 'Vendors'
vendor_table.field_names = vendors.keys()
vendor_table.add_row([v for v in vendors.values()])

print(' ')
print(device_table)
print()
print(vendor_table)

