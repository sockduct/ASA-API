from __future__ import print_function
from __future__ import unicode_literals

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

    def post(self, resource):
        pass

    def delete(self, resource):
        pass

    def put(self, resource):
        pass

    def patch(self, resource):
        pass

    def populate_ints(self, resp_data, itype):
        self.data['interfaces'] = {itype: {'kind': resp_data['kind'],
                                        'count': resp_data['rangeInfo']['total'],
                                        'items': {}}
                                }

        for item in resp_data['items']:
            self.data['interfaces'][itype]['items'][item['hardwareID']] = dict(
                        descr=item['interfaceDesc'],
                        managementOnly=item['managementOnly'],
                        name=item['name'],
                        objectId=item['objectId'],
                        securityLevel=item['securityLevel'],
                        shutdown=item['shutdown']
                    )
            if item['ipAddress'] != 'NoneSelected':
                self.data['interfaces'][itype]['items'][item['hardwareID']]['ipv4'] = dict(
                            addr=item['ipAddress']['ip']['value'],
                            mask=item['ipAddress']['netMask']['value'],
                            kind=item['ipAddress']['kind']
                        )
            else:
                self.data['interfaces'][itype]['items'][item['hardwareID']]['ipv4'] = (
                        'NoneSelected')
            if itype == 'vlan':
                self.data['interfaces'][itype]['items'][item['hardwareID']]['vlanID'] = (
                        item['vlanID'])

    def populate_routes(self, resp_data, rtype):
        self.data['routes'] = {rtype: {'kind': resp_data['kind'],
                                    'count': resp_data['rangeInfo']['total'],
                                    'items': {'ipv4': {}}}
                            }
        for item in resp_data['items']:
            if item['kind'] != 'object#IPv4Route':
                sys.exit('Error:  Unexpected {} route type "{}" - aborting...'.format(rtype,
                         item['kind']))
            if item['gateway']['kind'] != 'IPv4Address':
                sys.exit('Error:  Unexpected {} route gateway type "{}" - aborting...'.format(
                         rtype, item['gateway']['kind']))

            self.data['routes'][rtype]['items']['ipv4'][item['network']['value']] = dict(
                        netkind=item['network']['kind'],
                        gateway=item['gateway']['value'],
                        ad=item['distanceMetric'],
                        interface=item['interface']['name'],
                        tracked=item['tracked'],
                        tunneled=item['tunneled'],
                        objectId=item['objectId']
                    )

    def print_ints(self, itype):
        ic = self.data['interfaces'][itype]['kind']
        # Remove leading description (e.g., "collection#")
        ic = ic[ic.find('#') + 1:]
        print(' \Interfaces/{} - {}:'.format(itype, ic))
        for item in sorted(self.data['interfaces'][itype]['items']):
            # Check for IPv4 Address Components
            if self.data['interfaces'][itype]['items'][item]['ipv4'] != 'NoneSelected':
                ac1 = self.data['interfaces'][itype]['items'][item]['ipv4']['addr']
                ac2 = self.data['interfaces'][itype]['items'][item]['ipv4']['mask']
            else:
                ac1 = '-'
                ac2 = '-'
            nc = self.data['interfaces'][itype]['items'][item]['name']
            if nc == '':
                nc = '-unset-'
            sc = self.data['interfaces'][itype]['items'][item]['securityLevel']
            if sc == -1:
                sc = '-unset-'
            if itype == 'physical':
                print('  \{:>18}, {:>16}/{:<7}:  {}/{}'.format(item, nc, sc, ac1, ac2))
            elif itype == 'vlan':
                vc = self.data['interfaces'][itype]['items'][item]['vlanID']
                print('  \{:<23}<{:>4}>, {:>16}/{:<7}:  {}/{}'.format(item, vc, nc, sc, ac1, ac2))

    def print_routes(self, rtype):
        ic = self.data['routes'][rtype]['kind']
        # Remove leading description (e.g., "collection#")
        ic = ic[ic.find('#') + 1:]
        print(' \Routes/{} - {}:'.format(rtype, ic))
        for item in sorted(self.data['routes'][rtype]['items']['ipv4']):
            print('  \{:<18} [{:>3}/0] via {:<15} - {}'.format(item,
                    self.data['routes'][rtype]['items']['ipv4'][item]['ad'],
                    self.data['routes'][rtype]['items']['ipv4'][item]['gateway'],
                    self.data['routes'][rtype]['items']['ipv4'][item]['interface']))


if __name__ == '__main__':
    resources = ['interfaces/physical', 'interfaces/vlan', 'routing/static']
    asa = Asa()

    print('Cisco ASA ({}):'.format(asa.mgmt))
    for resource in resources:
        # Strip off leading part and slash:
        rc = resource[resource.find('/') + 1:]
        resp = asa.get(resource)
        if resp:
            if resource == 'interfaces/physical':
                asa.populate_ints(resp, rc)
                asa.print_ints(rc)
            elif resource == 'interfaces/vlan':
                asa.populate_ints(resp, rc)
                asa.print_ints(rc)
            elif resource == 'routing/static':
                asa.populate_routes(resp, rc)
                asa.print_routes(rc)
            else:
                sys.exit('Error:  resource "{}" not handled, aborting...'.format(resource))
        else:
            sys.exit('Error:  Didn\'t get response from ASA, aborting...')

