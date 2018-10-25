import sys
import ipaddress
import hackathon
import argparse
from prettytable import PrettyTable

vendors = {'':0}
skip_scan = True

parser = argparse.ArgumentParser()
parser.add_argument('--network', '-c', help='Subnet in CIDR notation', default='0.0.0.0/0')
parser.add_argument('-n', dest='skip', action='store_true', help='Skip ARP table update', default=False)
parser.add_argument('-p', '--ports', help='Range of ports to scan for each device', default=[0,0], type=int, nargs=2)
parser.add_argument('-t', '--timeout', help='Time to wait for each port connection', default=0.5, type=float)
args = parser.parse_args()
network = args.network
skip_arp = args.skip
timeout = args.timeout
ports = args.ports
skip_scan = ports[0] == ports[1]

if sys.platform == 'win32':
    if not skip_arp:
        local_ip, local_mask = hackathon.findipsubwindows()
        hackathon.pingsweep(local_ip + '/' + local_mask, '-n')
    devices = hackathon.parsewindows()
else:
    if not skip_arp:
        local_ip, local_mask = hackathon.findipsubmac()
        hackathon.pingsweep(local_ip + '/' + local_mask, '-c')
    devices = hackathon.parsemac()
    skip_scan = True

devices_in_network = 0

# count available addresses
available_addresses = 0
for ip in ipaddress.ip_network(network, strict=False):
    available_addresses = available_addresses + 1
available_addresses = available_addresses - 2 #broadcast and subnet

for device in devices:
    addr = ipaddress.ip_address(device['ip'])
    if addr in ipaddress.ip_network(network, strict=False):
        devices_in_network = devices_in_network + 1

if devices_in_network == 0:
    print('There are no devices in subnet {}'.format(network))
    sys.exit()

print('Scanning ports...')
i = 0   # iterator for progress bar
hackathon.printProgressBar(0, devices_in_network, prefix='Progress: ',suffix='Complete',length=50)

for device in devices:
    device['vendor'] = ''
    device['ports'] = []
    addr = ipaddress.ip_address(device['ip'])
    #check whether device is in subnet we're looking at
    if addr in ipaddress.ip_network(network, strict=False):
        i = i + 1
        try:
            device['vendor'] = hackathon.get_vendor(device['mac'])
        except ValueError:
            device['vendor'] = ''
        if not skip_scan:
            device['ports'] = hackathon.scan_ports(device['ip'], delay=timeout, maxport=ports)
        if device['vendor'] not in vendors:
            vendors[device['vendor']] = 1
        else:
            vendors[device['vendor']] = vendors[device['vendor']] + 1
    hackathon.printProgressBar(i, devices_in_network,
                               prefix='Progress: {} of {} devices scanned'.format(i, devices_in_network),
                               suffix='Complete', length=50)

##################################
# Format output into nice tables #
##################################

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
vendor_table.field_names = ['Vendor', 'Devices']
for k, v in vendors.items():
    vendor_table.add_row([k, v])

util_table = PrettyTable()
util = (devices_in_network/available_addresses) * 100
util = round(util, 2)
util_table.field_names = ['Network Utilization']
util_table.add_row(['{} out of {} addresses in use ({}%)'.format(devices_in_network,available_addresses,util)])

print('\n')
print(util_table)
print()
print(device_table)
print()
print(vendor_table)

