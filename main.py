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

print('\n------------------------')
print('Device IP   Manufacturer')
print('------------------------\n')

for device in devices:
    addr = ipaddress.ip_address(device['ip'])

    #check whether device is in subnet we're looking at
    if addr in ipaddress.ip_network(network, strict=False):
        print(addr,'    ', hackathon.get_vendor(device['mac']))
        hackathon.scan_ports(device['ip'], delay=timeout, maxport=ports)
