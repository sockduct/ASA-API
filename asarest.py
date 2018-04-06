#!/usr/bin/env python2
'''Asa - class to facilitate interaction with Cisco ASA via its REST API'''
###################################################################################################
# To do:
# * Finish methods - post, delete, put, patch, ptrace
# * Packet-trace interpretation
#   * Show matched policies (e.g., WCCP-Redirect, NAT, INSPECT, QoS, Flow-Export, BTF, User-Stats,
#     Logged, ...
#   * Show NAT results (NATed to ...)
#   * Allow input of names/FQDNs
#   * Allow input of service names
#   * Make service name input easier
#   * Should etree be stored in the class/instance?
# * Check if physical (and VLAN) interface is up/up - if not, account for so prefix not used
# * Add regexp search for interfaces and routes
# * Add IPv6 support
###################################################################################################

from __future__ import print_function
from __future__ import unicode_literals

import netaddr
# If want this to run on non-Windows platforms need some logic around this:
import win_inet_pton    # Must be imported before radix in Windows
                        # inet_pton not in stdlib socket library in Windows until v3.4
                        # However, radix uses C extension modules which still fail to
                        # import even in v3.4+
# 2.x only (3.x = html.parser)
import HTMLParser
import radix
import random
import requests
from requests.exceptions import ConnectTimeout
import sys
from xml.etree import ElementTree


MGMT = '198.51.100.164'
USER = 'cisco'
PASSWD = 'cisco'
RETRY = 2
TIMEOUT = 3.0
VERIFY = False  # Validate X.509 Certificate? Typically self-signed so default to no.

# Ignore certificate errors since typically using self-signed certs
requests.packages.urllib3.disable_warnings()


class Asa(object):
    rng = random.SystemRandom()

    def __init__(self, mgmt=MGMT, user=USER, passwd=PASSWD, timeout=TIMEOUT, verify=VERIFY):
        self.mgmt = mgmt
        self.user = user
        self.passwd = passwd
        self.timeout = timeout
        self.verify = verify
        self.data = {}
        self.rtree = radix.Radix()

    def __repr__(self):
        return ('<Cisco ASA:  management address={}, username={}, timeout={}, validate '
                'certificate={}>\n\t<{{data keys:  {}}}, {{radix tree size:  {} prefixes'
                '}}>\n\t<{{data/routes/static:  {} prefixes ({} ipv4)}}>\n\t<{{data/'
                'interfaces:  physical - {}, logical - {}, vlan - {}}}>'.format(self.mgmt,
                    self.user, self.timeout, self.verify, self.data.keys(),
                    len(self.rtree.prefixes()), self.data['routes']['static']['count'],
                    len(self.data['routes']['static']['items']['ipv4']),
                    self.data['interfaces']['physical']['count'], self.data['interfaces'][
                        'logical']['count'], self.data['interfaces']['vlan']['count']))

    def get(self, resource, verbose=False):
        # headers = {'user-agent': 'my-app/0.0.1'}
        # resp = requests.get('https://' + ASA + '/api/' + resource, headers=headers)

        # resp.status_code
        # resp.status_code == requests.codes.ok

        # Note - ASA returns up to 100 records per query
        data_loc = 0  # Current range of data (i.e., 0-99)
        get_payload = {'offset': 0}
        retries = 0

        while True:
            try:
                if verbose:
                    print('Attempting get connection to ASA...')
                resp = requests.get('https://' + self.mgmt + '/api/' + resource,
                                    auth=(self.user, self.passwd),
                                    timeout=self.timeout, verify=self.verify,
                                    params=get_payload)
            except ConnectTimeout:
                retries += 1
                if verbose:
                    print('get connection timed out/failed to complete within timeout '
                          'period ({}s) - retry # {}...'.format(self.timeout, retries))
                if retries <= RETRY:
                    continue
                else:
                    sys.exit('Error:  Exceeded maximum number of retries ({}) for get'
                             ' - giving up.'.format(RETRY))

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
    def post(self, resource, payload, verbose=False):
        retries = 0

        while True:
            try:
                if verbose:
                    print('Attempting post connection to ASA...')
                resp = requests.post('https://' + self.mgmt + '/api/' + resource,
                                    auth=(self.user, self.passwd),
                                    timeout=self.timeout, verify=self.verify,
                                    json=payload)
            except ConnectTimeout:
                retries += 1
                if verbose:
                    print('post connection timed out/failed to complete within timeout '
                          'period ({}s) - retry # {}...'.format(self.timeout, retries))
                if retries <= RETRY:
                    continue
                else:
                    sys.exit('Error:  Exceeded maximum number of retries ({}) for post'
                             ' - giving up.'.format(RETRY))
            else:
                break

        if resp.ok:
            # Get JSON data
            resp_dict = resp.json()

            return resp_dict
        else:
            resp.raise_for_status()

    '''
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

    def get_ptrace(self, src_ip, dst_ip, ingress_int=None, proto='tcp', src_port=-1,
                   dst_port=80, verbose=False):
        _, _, ingress_logical, _ = self.get_nexthop(src_ip)
        valid_protos = ['icmp', 'rawip', 'tcp', 'udp']
        if not ingress_int:
            ingress_int = ingress_logical
        elif ingress_int != ingress_logical:
            sys.exit('Error: {} input as ingress interface, but ASA says it should be {}!'
                     ''.format(ingress_int, ingress_logical))

        if proto.lower() not in valid_protos:
            sys.exit('Error: {} input as protocol, ASA only accepts {}.'.format(proto,
                        valid_protos))

        if src_port < 0:
            # Default Windows ephemeral port range, also acceptable range for other OS
            src_port = Asa.rng.randint(49152, 65535)

        ptcmd = 'packet-tracer input {} {} {} {} {} {} detailed xml'.format(ingress_int,
                    proto, src_ip, src_port, dst_ip, dst_port)

        # Invoke packet-tracer through generic CLI API
        payload = {'commands': [ptcmd]}
        res = self.post('cli', payload, verbose=True)

        # "Decode" HTML Character Entity References
        html_parser = HTMLParser.HTMLParser()
        # 3.x:
        # html_parser = html.parser.HTMLParser()
        decoded = html_parser.unescape(res['response'][0])

        # Invalid XML - repeated elements without a root, fix:
        decoded = '<ASA-PT>\n' + decoded + '</ASA-PT>\n'
        etree = ElementTree.fromstring(decoded)

        return etree

    def print_ptrace(self, etree):
        # Walk tree:
        for child in etree:
            print('> {}'.format(child.tag))
            for subchild in child:
                sctext = subchild.text.strip() if subchild.text else ''
                if '\n' in sctext:
                    sctext = '\n\t\t' + sctext.replace('\n', '\n\t\t')
                print('    {:>7}:  {}'.format(subchild.tag, sctext))

    def show_ptrace(self, etree, verbose=False):
        pt_res = {}
        summary = {}

        for child in etree.find('result'):
            pt_res[child.tag] = child.text.strip()

        if verbose:
            print('pt-res:\n{}\n'.format(pt_res))

        # Get Egress Next-Hop
        # XPath query string to locate section of packet-tracer output with
        # next-hop info:
        target = './/*[subtype="Resolve Egress Interface"]/subtype/..'
        nexthop = etree.find(target)
        # Using is not None per library requirement
        if nexthop is not None:
            nexthop_str = nexthop.find('extra').text.strip()
            nexthop_ip = nexthop_str.split()[2]
            nexthop_int = nexthop_str.split()[-1]

        # Get First top-level element with result of 'DROP'
        target = './/*[result="DROP"]/result/..'
        deny_elmt = etree.find(target)
        # Using is not None per library requirement
        if deny_elmt is not None:
            deny_info = ('type={}, subtype={}, result={}, matching configuration:\n'
                         ''.format(deny_elmt.find('type').text.strip(),
                                   deny_elmt.find('subtype').text.strip(),
                                   deny_elmt.find('result').text.strip()))
            temp = deny_elmt.find('config').text.strip()
            temp = '\t' + temp.replace('\n', '\n\t')
            deny_info += temp

        summary['input'] = '{}[{}/{}]'.format(pt_res['input-interface'],
                            pt_res['input-status'], pt_res['input-line-status'])
        summary['output'] = '{}[{}/{}]'.format(pt_res['output-interface'],
                            pt_res['output-status'], pt_res['output-line-status'])
        summary['action'] = pt_res['action']

        print('\nFrom {} --> {}\nResult:  {}'.format(summary['input'],
              summary['output'], summary['action']))
        if pt_res['action'] == 'allow':
            print('\t(Egress next-hop:  {})\n'.format(nexthop_ip))
        elif pt_res['action'] == 'drop':
            print('  Drop reason:  {}'.format(pt_res['drop-reason']))
            print('  Details:  {}\n'.format(deny_info))
        else:
            print('Unexpected result "{}"\n\n'.format(pt_res['action']))
            


def test():
    asa = main()
    res = asa.get_ptrace('172.16.1.1', '8.8.8.8')
    asa.print_ptrace(res)
    asa.show_ptrace(res)


def main(display=False):
    resources = ['interfaces/physical', 'interfaces/vlan', 'routing/static']
    asa = Asa()

    print('Processing Cisco ASA ({})...'.format(asa.mgmt))
    for resource in resources:
        # Strip off leading part and slash:
        rc = resource[resource.find('/') + 1:]
        resp = asa.get(resource, verbose=True)
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
    # main(display=True)
    test()

