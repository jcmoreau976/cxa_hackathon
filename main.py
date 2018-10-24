import os
import sys
import ipaddress
import hackathon
import getopt

usage = '\nEx: python main.py [-c 192.168.1.0/24] [-s subnet -m netmask] [-p ports] \n'
network = '0.0.0.0/0'   # search all subnets by default
subnet = '0.0.0.0'
mask = '0.0.0.0'
ports = 1024            # scan 1024 ports by default
timeout = 0.5           # 0.5 second port scan timeout default

try:
    opts, r = getopt.getopt(sys.argv[1:], 't:c:s:m:p:')
except getopt.GetoptError:
    print(usage)
    sys.exit('ERROR: Bad input')


for o, a in opts:
    if o == '-c':
        network = a
    elif o == '-s':
        subnet = a
    elif o == '-m':
        mask = a
    elif o == '-p':
        ports = int(a)
    elif o == '-t':
        timeout = float(a)
    else:
        assert False, usage

if not hackathon.validate_ip(subnet):
    print('Invalid subnet given. Subnet must be given as three octet string, ex: \'192.168.1.0\'')
    sys.exit('Bad subnet input')

if not hackathon.validate_mask(mask):
    print('Invalid subnet mask given.')
    sys.exit('Bad mask input')

local_ip, local_mask = hackathon.findipsub()

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

hackathon.printProgressBar(0, devices_in_network, prefix='Progress: ',suffix='Complete',length=50)
i = 0
for device in devices:
    device['vendor'] = ''
    device['ports'] = []
    i = i + 1
    addr = ipaddress.ip_address(device['ip'])
    #check whether device is in subnet we're looking at
    if addr in ipaddress.ip_network(network, strict=False):
        #print(addr,'    ', hackathon.get_vendor(device['mac']))
        device['vendor'] = hackathon.get_vendor(device['mac'])
        device['ports'] = hackathon.scan_ports(device['ip'], delay=timeout, maxport=ports)
    hackathon.printProgressBar(i, len(devices), prefix='Progress: ', suffix='Complete', length=50)

print('\n------------------------')
print('Device IP   Manufacturer')
print('------------------------\n')

for device in devices:
    addr = ipaddress.ip_address(device['ip'])
    if addr in ipaddress.ip_network(network, strict=False):
        print(device['ip'], '   ',device['vendor'])
        for port in device['ports']:
            print('     Port {}: Open'.format(port))

print('\n')
