#
# To do:
# * Method to search for target IP and return radix object or info
# * Check if physical (and VLAN) interface is up/up - if not, account for so prefix not used
# * Add regexp search for interfaces and routes
# * Add IPv6 support
#

from __future__ import print_function
from __future__ import unicode_literals

import netaddr
# If want this to run on non-Windows platforms need some logic around this:
import win_inet_pton    # Must be imported before radix in Windows
                        # inet_pton not in stdlib socket library in Windows until v3.4
                        # However, radix uses C extension modules which still fail to
                        # import even in v3.4+
import radix
import requests
import sys

MGMT = '198.51.100.164'
USER = 'cisco'
PASSWD = 'cisco'
TIMEOUT = 5.0
VERIFY = False  # Validate X.509 Certificate? Typically self-signed so default to no.

# Ignore certificate errors since typically using self-signed certs
requests.packages.urllib3.disable_warnings()

class Asa(object):
    def __init__(self, mgmt=MGMT, user=USER, passwd=PASSWD, timeout=TIMEOUT, verify=VERIFY):
        self.mgmt = mgmt
        self.user = user
        self.passwd = passwd
        self.timeout = timeout
        self.verify = verify
        self.data = {}
        self.rtree = radix.Radix()

    def get(self, resource):
        # headers = {'user-agent': 'my-app/0.0.1'}
        # resp = requests.get('https://' + ASA + '/api/' + resource, headers=headers)

        # resp.status_code
        # resp.status_code == requests.codes.ok

        # Note - ASA returns up to 100 records per query
        data_loc = 0  # Current range of data (i.e., 0-99)
        get_payload = {'offset': 0}

        while True:
            resp = requests.get('https://' + self.mgmt + '/api/' + resource,
                                auth=(self.user, self.passwd),
                                timeout=self.timeout, verify=self.verify,
                                params=get_payload)
            if resp.ok:
                # Get JSON data
                resp_dict = resp.json()

                # First time through - keep everything
                if data_loc == 0:
                    resp_data = resp_dict
                # Subsequent results, just want to keep items data
                else:
                    resp_data['items'].extend(resp_dict['items'])

                start = resp_dict['rangeInfo']['offset']
                end = start + resp_dict['rangeInfo']['limit'] - 1
                total = resp_dict['rangeInfo']['total']
                # print('Retrieved items {}-{} out of {}...'.format(start, end, total))

                data_loc += 100
                # We have everything
                if data_loc >= resp_data['rangeInfo']['total']:
                    return resp_data
                # Don't have everything, get the next range
                else:
                    get_payload['offset'] = data_loc
            else:
                resp.raise_for_status()

    # Comment these out until implemented
    '''
    def post(self, resource):
        pass

    def delete(self, resource):
        pass

    def put(self, resource):
        pass

    def patch(self, resource):
        pass
    '''

    def populate_ints(self, resp_data, itype):
        intkey = 'interfaces'
        intdata = {itype: {'kind': resp_data['kind'],
                        'count': resp_data['rangeInfo']['total'],
                        'items': {}}
                }

        if intkey not in self.data:
            self.data[intkey] = intdata
        else:
            self.data[intkey].update(intdata)

        # Also create a logical (nameif) to physical mapping table:
        if 'logical' not in self.data['interfaces']:
            self.data['interfaces']['logical'] = dict(
                        kind='collection#nameif',
                        count=0,
                        items={}
                    )

        for item in resp_data['items']:
            self.data['interfaces'][itype]['items'][item['hardwareID']] = dict(
                        descr=item['interfaceDesc'],
                        managementOnly=item['managementOnly'],
                        name=item['name'],
                        objectId=item['objectId'],
                        securityLevel=item['securityLevel'],
                        shutdown=item['shutdown']
                    )

            # If logical name exists, update logical table:
            if item['name']:
                self.data['interfaces']['logical']['items'][item['name']] = dict(
                            physical=item['hardwareID'],
                            securityLevel=item['securityLevel'],
                            ipv4=dict(
                                addr=item['ipAddress']['ip']['value'],
                                mask=item['ipAddress']['netMask']['value']
                            )
                        )
                # Update count
                self.data['interfaces']['logical']['count'] += 1

            if item['ipAddress'] != 'NoneSelected':
                self.data['interfaces'][itype]['items'][item['hardwareID']]['ipv4'] = dict(
                            addr=item['ipAddress']['ip']['value'],
                            mask=item['ipAddress']['netMask']['value'],
                            kind=item['ipAddress']['kind']
                        )

                # Allow searching for longest match with:  res = self.rtree.search_best(<IP>)
                # res.prefix = answer, res.data = data added with rnode...
                address = item['ipAddress']['ip']['value']
                subnet_mask = item['ipAddress']['netMask']['value']
                prefix = str(netaddr.IPNetwork(address + '/' + subnet_mask).cidr)

                # Two sets of data - interface address, interface network
                # Interface address:
                rnode = self.rtree.add(address)
                rnode.data['physical'] = item['hardwareID']
                rnode.data['logical'] = item['name']
                rnode.data['via'] = 'self'

                # Interface network:
                rnode = self.rtree.add(prefix)
                rnode.data['physical'] = item['hardwareID']
                rnode.data['logical'] = item['name']
                rnode.data['via'] = 'connected'
            else:
                self.data['interfaces'][itype]['items'][item['hardwareID']]['ipv4'] = (
                        'NoneSelected')
            if itype == 'vlan':
                self.data['interfaces'][itype]['items'][item['hardwareID']]['vlanID'] = (
                        item['vlanID'])

                # If logical name exists, update logical table:
                if item['name']:
                    self.data['interfaces']['logical']['items'][item['name']]['vlanID'] = item[
                                'vlanID']

    def populate_routes(self, resp_data, rtype):
        rtkey = 'routes'
        rtdata = {rtype: {'kind': resp_data['kind'],
                        'count': resp_data['rangeInfo']['total'],
                        'items': {'ipv4': {}}}
                }

        if rtkey not in self.data:
            self.data[rtkey] = rtdata
        else:
            self.data[rtkey].update(rtdata)

        for item in resp_data['items']:
            if item['kind'] != 'object#IPv4Route':
                sys.exit('Error:  Unexpected {} route type "{}" - aborting...'.format(rtype,
                         item['kind']))
            if item['gateway']['kind'] != 'IPv4Address':
                sys.exit('Error:  Unexpected {} route gateway type "{}" - aborting...'.format(
                         rtype, item['gateway']['kind']))

            # Change 'any4' to 'default':
            if item['network']['value'] == 'any4':
                address = 'default'
            else:
                address = item['network']['value']

            self.data['routes'][rtype]['items']['ipv4'][address] = dict(
                        netkind=item['network']['kind'],
                        gateway=item['gateway']['value'],
                        ad=item['distanceMetric'],
                        interface=item['interface']['name'],
                        tracked=item['tracked'],
                        tunneled=item['tunneled'],
                        objectId=item['objectId']
                    )

            # Allow searching for longest match with:  res = self.rtree.search_best(<IP>)
            # res.prefix = answer, res.data = data added with rnode...
            prefix = item['network']['value']
            if prefix == 'any4':
                prefix = '0.0.0.0/0'
            rnode = self.rtree.add(prefix)
            ## Figure out how to get physical interface???
            rnode.data['logical'] = item['interface']['name']
            rnode.data['via'] = rtype

    def print_ints(self, itype='all'):
        if itype == 'all':
            for k in self.data['interfaces'].keys():
                self.print_ints(k)
                print()
        elif itype == 'available':
            return self.data['interfaces'].keys()
        else:
            ic = self.data['interfaces'][itype]['kind']
            # Remove leading description (e.g., "collection#")
            ic = ic[ic.find('#') + 1:]
            print(' \Interfaces/{} - {}:'.format(itype, ic))
            for item in sorted(self.data['interfaces'][itype]['items']):
                if 'ipv4' in self.data['interfaces'][itype]['items'][item]:
                    # Check for IPv4 Address Components
                    if self.data['interfaces'][itype]['items'][item]['ipv4'] != 'NoneSelected':
                        ac1 = self.data['interfaces'][itype]['items'][item]['ipv4']['addr']
                        ac2 = self.data['interfaces'][itype]['items'][item]['ipv4']['mask']
                    else:
                        ac1 = '-'
                        ac2 = '-'

                if 'name' in self.data['interfaces'][itype]['items'][item]:
                    # Check for Logical Name
                    nc = self.data['interfaces'][itype]['items'][item]['name']
                    if nc == '':
                        nc = '-unset-'

                if 'securityLevel' in self.data['interfaces'][itype]['items'][item]:
                    # Check for Logical Security Level
                    sc = self.data['interfaces'][itype]['items'][item]['securityLevel']
                    if sc == -1:
                        sc = '-unset-'

                if 'physical' in self.data['interfaces'][itype]['items'][item]:
                    # Check for Physical Interface Name
                    pc = self.data['interfaces'][itype]['items'][item]['physical']

                if 'vlanID' in self.data['interfaces'][itype]['items'][item]:
                    vc = self.data['interfaces'][itype]['items'][item]['vlanID']
                else:
                    vc = '-'

                # Is this a physical/VLAN interface or a logical one?
                if itype == 'physical':
                    # print('  \{:>18}, {:>16}/{:<7}:  {}/{}'.format(item, nc, sc, ac1, ac2))
                    print('  \{:>18}, {:>16}/{:<7}:  {:<15} {}'.format(item, nc, sc, ac1, ac2))
                elif itype == 'vlan':
                    # print('  \{:<23}<{:>4}>, {:>16}/{:<7}:  {}/{}'.format(item, vc, nc, sc, ac1,
                    #         ac2))
                    print('  \{:<23}<{:>4}>, {:>16}/{:<7}:  {:<15} {}'.format(item, vc, nc, sc,
                            ac1, ac2))
                elif itype == 'logical':
                    # print('  \{:>16}-->{:<18}'.format(item, pc))
                    print('  \{:>16}/{:<3}, {:<23}<{:>4}>:  {:<15} {}'.format(item, sc, pc, vc,
                            ac1, ac2))

    def print_routes(self, rtype='static'):
        ic = self.data['routes'][rtype]['kind']
        # Remove leading description (e.g., "collection#")
        ic = ic[ic.find('#') + 1:]
        print(' \Routes/{} - {}:'.format(rtype, ic))
        for item in sorted(self.data['routes'][rtype]['items']['ipv4']):
            print('  \{:<18} [{:>3}/0] via {:<15} - {}'.format(item,
                    self.data['routes'][rtype]['items']['ipv4'][item]['ad'],
                    self.data['routes'][rtype]['items']['ipv4'][item]['gateway'],
                    self.data['routes'][rtype]['items']['ipv4'][item]['interface']))

    def get_nexthop(self, address):
        rnode = self.rtree.search_best(address)
        prefix = rnode.prefix
        # Modify if it's the default route:
        if prefix == '0.0.0.0/0':
            prefix = 'default'
        if 'physical' in rnode.data:
            physical = rnode.data['physical']
        else:
            physical = self.data['interfaces']['logical']['items'][rnode.data['logical']][
                                    'physical']
            # vlan = self.data['interfaces']['logical']['items'][rnode.data['logical']]['vlan']
        logical = rnode.data['logical']
        via = rnode.data['via']

        return prefix, physical, logical, via

def main(display=False):
    resources = ['interfaces/physical', 'interfaces/vlan', 'routing/static']
    asa = Asa()

    print('Processing Cisco ASA ({})...'.format(asa.mgmt))
    for resource in resources:
        # Strip off leading part and slash:
        rc = resource[resource.find('/') + 1:]
        resp = asa.get(resource)
        if resp:
            if resource == 'interfaces/physical':
                asa.populate_ints(resp, rc)
                if display:
                    asa.print_ints(rc)
            elif resource == 'interfaces/vlan':
                asa.populate_ints(resp, rc)
                if display:
                    asa.print_ints(rc)
            elif resource == 'routing/static':
                asa.populate_routes(resp, rc)
                if display:
                    asa.print_routes(rc)
            else:
                sys.exit('Error:  resource "{}" not handled, aborting...'.format(resource))
        else:
            sys.exit('Error:  Didn\'t get response from ASA, aborting...')

    return asa


if __name__ == '__main__':
    main(display=True)

