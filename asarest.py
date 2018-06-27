#!/usr/bin/env python
'''Asa - class to facilitate interaction with Cisco ASA via its REST API'''
# Supported in Python v2.7 and 3.5+
###################################################################################################
# To do:
# * Packet-trace interpretation
#   * Show matched policies (e.g., in order of interest:
#     NAT, INSPECT, WCCP-Redirect, (dynamic vs. static?) Shun, BTF, IPS-Module,
#     QoS, Flow-Export, User-Stats, Logged, Others?
#   * Show NAT results (NATed to ...)
#     * Outside to inside
#     * Inside to outside
#     * Both
#   * Allow input of names/FQDNs
#   * Allow input of service names
#   * Make service name input easier
#   * Should etree be stored in the class/instance?
# * Create CLI version of this using click to support paging
# * Support ICMP Type/Code options
# * populate_ints only supports physical and vlan types, improve to check for all interface
#   types (bvi, ethernet, firepower, portchannel, redundant, setup), should also check if
#   in single or multi mode as the latter requires a different API
# * Check if physical (and VLAN) interface is up/up - if not, account for so prefix not used
# * Support getting authentication token vs. username/password auth
# * g
# * Consider re-factoring
#   * Base supports HTTP verbs and auth
#   * Separate class which inherits base and adds retrieval type info
#   * Separate class which inherits base and adds display/output options
#   * Asa clas which inherits all the above
# * Finish methods - delete, put, patch
# * Consider separating ASA REST interface and packet-tracer interpretation functionality
#   into separate modules
# * Add regexp search for interfaces and routes
# * Add IPv6 support
###################################################################################################
# packet-tracer functionality/options v9.4.4.13:
# packet-tracer input <nameif> <icmp>|<rawip>|<tcp>|<udp> [inline-tag <#>]
#     <srcip>|[fqdn <strsrc>]|[security-group [name <str>]|[tag <#>]|[user [<domain>\]<user>]
#         <srcport>|<srcsvc>
#     <dstip>|[fqdn <strdst>]|[security-group [name <str>]|[tag <#>]
#         <dstport>|<dstsvc>
#     [vxlan-inner <#> <icmp>|<rawip>|<tcp>|<udp> <srcip> <srcport>|<srcsvc>
#         <dstip> <dstport>|<dstsvc> <srcmac> <dstmac>]
#     [detailed] [xml]
###################################################################################################

from __future__ import print_function
# Removed to make click happy!
# from __future__ import unicode_literals

# stdlib
from collections import OrderedDict
from pprint import pprint
import random
import sys
from xml.etree import ElementTree

# stdlib conditional on Python version
if sys.version_info.major == 2:
    import HTMLParser as html_parser
# Renamed in 3.x
else:
    import html.parser as html_parser

# 3rd party
import click
import netaddr
# If want this to run on non-Windows platforms need some logic around this:
import win_inet_pton    # Must be imported before radix in Windows
                        # inet_pton not in stdlib socket library in Windows until v3.4
                        # However, radix uses C extension modules which still fail to
                        # import even in v3.4+
import radix            # Note:  pip install py-radix
import requests
from requests.exceptions import ConnectTimeout, ReadTimeout


# Globals
MGMT = '198.51.100.164'
USER = 'cisco'
PASSWD = 'cisco'
RETRY = 2
TIMEOUT = 3.0
VERIFY = False  # Validate X.509 Certificate? Typically self-signed so default to no.

# Ignore certificate errors since typically using self-signed certs
requests.packages.urllib3.disable_warnings()


class Asa(object):
    # Keep in the class to facilitate thread safety
    rng = random.SystemRandom()

    def __init__(self, mgmt=MGMT, user=USER, passwd=PASSWD, timeout=TIMEOUT, verify=VERIFY):
        self.mgmt = mgmt
        self.user = user
        self.passwd = passwd
        self.timeout = timeout
        self.verify = verify
        self.data = {}
        self.rtree = radix.Radix()
        self.ptrace_data = {}

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

    def get(self, resource, params=None, verbose=False):
        '''ASA REST API - GET:  retrieve data from specified object
           Requires user with privilege level 5 or higher
           Requires user with privilege level 3 or greater for monitoring
           commands (i.e., /api/monitoring/*)'''
        # headers = {'user-agent': 'my-app/0.0.1'}
        # resp = requests.get('https://' + ASA + '/api/' + resource, headers=headers)

        # resp.status_code
        # resp.status_code == requests.codes.ok

        # Note - ASA returns up to 100 records per query
        data_loc = 0  # Current range of data (i.e., 0-99)
        if params:
            get_payload.update({'offset': 0})
        else:
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

                if resp_dict.get('rangeInfo'):
                    start = resp_dict['rangeInfo']['offset']
                    end = start + resp_dict['rangeInfo']['limit'] - 1
                    total = resp_dict['rangeInfo']['total']
                    if verbose:
                        print('Retrieved items {}-{} out of {}...'.format(start, end, total))

                    data_loc += 100
                    # We have everything
                    if data_loc >= resp_data['rangeInfo']['total']:
                        return resp_data
                    # Don't have everything, get the next range
                    else:
                        get_payload['offset'] = data_loc
                else:
                    return resp_data
            else:
                resp.raise_for_status()

    def post(self, resource, payload, verbose=False):
        '''ASA REST API - POST:  create object with supplied information
           Requires user with privilege level 15'''
        retries = 0

        while True:
            try:
                if verbose:
                    print('Attempting post connection to ASA as {}...'.format(self.user))
                resp = requests.post('https://' + self.mgmt + '/api/' + resource,
                                    auth=(self.user, self.passwd),
                                    timeout=self.timeout, verify=self.verify,
                                    json=payload)
            except (ConnectTimeout, ReadTimeout) as err:
                retries += 1
                if verbose:
                    print('post connection timed out/failed to complete within timeout '
                          'period ({}s/{}) - retry # {}...'.format(self.timeout,
                                                               err.__class__, retries))
                if retries <= RETRY:
                    continue
                else:
                    sys.exit('Error:  Exceeded maximum number of retries ({}) for post'
                             ' - giving up.'.format(RETRY))
            else:
                break

        if resp.status_code in [200, 201, 204, 400, 403]:
            if resp.status_code == 400:
                print('Warning:  Asa.post:  ASA states request is bad (400).  Did you mistype '
                      'something?')
            elif resp.status_code == 403:
                print('Warning:  Asa.post:  ASA states request not authorized (403).  Do you '
                      'have sufficient privileges?')

            if verbose:
                print('Debug:  Asa.post:  Response status code is {}'.format(resp.status_code))

            # Get JSON data
            resp_dict = resp.json()

            return resp_dict
        else:
            resp.raise_for_status()

    def delete(self, resource):
        '''ASA REST API - DELETE:  deletes specified object
           Requires user with privilege level 15'''
        raise(NotImplementedError)

    def put(self, resource):
        '''ASA REST API - PUT:  add supplied information to specified object
           Returns 404 (resource not found) error if object does not exist
           Requires user with privilege level 15'''
        raise(NotImplementedError)

    def patch(self, resource):
        '''ASA REST API - PATCH:  applies partial modifications to specified object'''
        raise(NotImplementedError)

    # Need to deal with errors - if get 400, output error instead of dying...
    def send_cmds(self, cmds, verbose=False):
        cmd_array = [c.strip() for c in cmds.split(';')]
        # Remove empty strings, use list for 3.x to iterate iterable
        cmd_array = list(filter(None, cmd_array))
        if verbose:
            print('Asa.send_cmds/parsed out:  {}'.format(cmd_array))

        payload = {'commands': cmd_array}
        res = self.post('cli', payload, verbose)
        error = res.get('messages')
        if error:
            sys.exit('Error:  Asa.send_cmds:  Level={}, Code={}, Details:  {}'.format(
                     error[0]['level'], error[0]['code'], error[0]['details']))
        output = res.get('response')
        if verbose:
            print('Asa.send_cmds/received response of {} element(s)'.format(len(output)))

        # If no command/response output:
        if len(output) == 0:
            return '-->Empty response<--'
        # If a single command/response, return raw output
        elif len(output) == 1:
            return output[0]
        # Otherwise return list
        else:
            out_dict = OrderedDict()
            for i, c in enumerate(cmd_array):
                out_dict[c] = output[i]
            return out_dict

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

    # Load Asa interfaces and routes
    def populate(self, verbose=False):
        # Note - this may be incomplete - better to move this to populate_ints and have it
        # dynamically discover all available interface types and interfaces
        resources = ['interfaces/physical', 'interfaces/vlan', 'routing/static']
    
        for resource in resources:
            # Strip off leading part and slash:
            rc = resource[resource.find('/') + 1:]
            resp = self.get(resource, verbose)
            if resp:
                if resource == 'interfaces/physical':
                    self.populate_ints(resp, rc)
                elif resource == 'interfaces/vlan':
                    self.populate_ints(resp, rc)
                elif resource == 'routing/static':
                    self.populate_routes(resp, rc)
                else:
                    sys.exit('Error:  resource "{}" not handled, aborting...'.format(resource))
            else:
                sys.exit('Error:  Didn\'t get response from ASA, aborting...')

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

    # Depends on interfaces and routes being loaded
    def ptrace(self, *args, **kwargs):
        if 'show' in kwargs:
            show_arg = kwargs.pop('show').lower()
        else:
            show_arg = None
        if 'verbose' in kwargs:
            verbose = kwargs['verbose']
        else:
            verbose = False
        self.get_ptrace(*args, **kwargs)
        if show_arg == 'full':
                self.print_ptrace()
        else:
            self.show_ptrace(verbose)

    def get_ptrace(self, src_ip, dst_ip, dst_port=80, proto='tcp', ingress_int=None, src_port=-1,
                   override=False, verbose=False):
        _, _, ingress_logical, _ = self.get_nexthop(src_ip)
        valid_protos = ['icmp', 'rawip', 'tcp', 'udp']
        if not ingress_int:
            ingress_int = ingress_logical
        elif ingress_int != ingress_logical and not override:
            sys.exit('Error: {} input as ingress interface, but ASA says it should be {}!'
                     ''.format(ingress_int, ingress_logical))

        if proto.lower() not in valid_protos:
            sys.exit('Error: {} input as protocol, ASA only accepts {}.'.format(proto,
                        valid_protos))

        if not src_port or src_port < 0:
            # Default Windows ephemeral port range, also acceptable range for other OS
            src_port = Asa.rng.randint(49152, 65535)

        ptcmd = 'packet-tracer input {} {} {} {} {} {} detailed xml'.format(ingress_int,
                    proto, src_ip, src_port, dst_ip, dst_port)

        # Invoke packet-tracer through generic CLI API
        res = self.send_cmds(ptcmd)

        # "Decode" HTML Character Entity References
        hparser = html_parser.HTMLParser()
        decoded = hparser.unescape(res)

        # Invalid XML - repeated elements without a root, fix:
        decoded = '<ASA-PT>\n' + decoded + '</ASA-PT>\n'
        etree = ElementTree.fromstring(decoded)

        self.ptrace_data['etree'] = etree
        self.ptrace_data.update(src_ip=src_ip, dst_ip=dst_ip, ingress_int=ingress_int,
                           proto=proto, src_port=src_port, dst_port=dst_port)

    def print_ptrace(self):
        etree = self.ptrace_data.get('etree')

        if etree is None:
            return

        # Walk tree:
        for child in etree:
            if child.tag.lower() == 'phase':
                print('\n> {} - '.format(child.tag), end='')
            else:
                print('\n> {}:'.format(child.tag))
            for subchild in child:
                sctext = subchild.text.strip() if subchild.text else 'None'
                if '\n' in sctext:
                    sctext = '\n\t\t' + sctext.replace('\n', '\n\t\t')
                if subchild.tag in ['id', 'type', 'subtype']:
                    print('{}={}, '.format(subchild.tag, sctext), end='')
                elif subchild.tag == 'result':
                    print('{}={}'.format(subchild.tag, sctext))
                elif subchild.tag in ['config', 'extra']:
                    print('    {:>6}:  {}'.format(subchild.tag, sctext))
                else:
                    print('  {:>18}:  {}'.format(subchild.tag, sctext))

    def strip_elmts(self, etree):
        res = {}

        for target_type in ['type', 'subtype', 'result', 'config', 'extra']:
            etype = etree.find(target_type).text
            if etype is not None:
                etype.strip()
            res[target_type] = etype

        return res

    def show_ptrace(self, verbose=False):
        etree = self.ptrace_data.get('etree')

        if etree is None:
            return

        pt_res = {}
        summary = {}
        nexthop_valid = False
        exit_asa = True
        orig_src_ip = self.ptrace_data['src_ip']
        orig_src_port = self.ptrace_data['src_port']
        orig_dst_ip = self.ptrace_data['dst_ip']
        orig_dst_port = self.ptrace_data['dst_port']
        new_src_ip = orig_src_ip
        new_src_port = orig_src_port
        new_dst_ip = orig_dst_ip
        new_dst_port = orig_dst_port

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
            nexthop_valid = True
            if verbose:
                print('Found nexthop of {} out {}...'.format(nexthop_ip, nexthop_int))

        # Get First top-level element with result of 'DROP'
        target = './/*[result="DROP"]/result/..'
        deny_elmt = etree.find(target)

        # Using is not None per library requirement
        if deny_elmt is not None:
            if verbose:
                print('Found deny element...')

            res = self.strip_elmts(deny_elmt)
            deny_info = ('type={}, subtype={}, result={}, matching configuration:\n'
                         ''.format(res['type'], res['subtype'], res['result']))
            temp = res['config']
            temp = '\t' + temp.replace('\n', '\n\t')
            deny_info += temp
            exit_asa = False

        # Look for NAT Rewrite
        target = './/*[type="NAT"]/type/..'
        nat_elmts = etree.findall(target)
        nat_match = 0
        for elmt in nat_elmts:
            res = self.strip_elmts(elmt)
            if res['subtype'] is None and res['result'] == 'ALLOW':
                if verbose:
                    # print('Found NAT rewrite element... {}'.format(res['extra']))
                    print('Found NAT rewrite element...'.format(res['extra']))
                nat_match += 1
                if nat_match > 1:
                    sys.exit('Error:  Expected only one matching NAT entry, found more.')
                temp = res['extra'].split()
                src = temp[2]
                dst = temp[4]
                tmp_src_ip, tmp_src_port = src.split('/')
                if tmp_src_ip != orig_src_ip and tmp_src_port != orig_src_port:
                    sys.exit('Error:  Source IP and port don\'t match original.')
                new_src_ip, new_src_port = dst.split('/')

        # Look for UN-NAT Rewrite
        target = './/*[type="UN-NAT"]/type/..'
        nat_elmts = etree.findall(target)
        nat_match = 0
        for elmt in nat_elmts:
            res = self.strip_elmts(elmt)
            if res['subtype'] == 'static' and res['result'] == 'ALLOW':
                if verbose:
                    print('Found UN-NAT rewrite element...')
                nat_match += 1
                if nat_match > 1:
                    sys.exit('Error:  Expected only one matching UN-NAT entry, found more.')
                temp = res['extra'].split()
                egress_int = temp[5]
                old_dst = temp[7]
                new_dst = temp[9]
                new_dst_ip, new_dst_port = new_dst.split('/')
                if egress_int != nexthop_int:
                    nexthop_valid = False

        summary['input'] = '{}[{}/{}]'.format(pt_res['input-interface'],
                            pt_res['input-status'], pt_res['input-line-status'])
        summary['output'] = '{}[{}/{}]'.format(pt_res['output-interface'],
                            pt_res['output-status'], pt_res['output-line-status'])
        summary['action'] = pt_res['action']

        print('\nEnter ASA on {} named logical interface - {}:{} --> {}:{}'.format(
                summary['input'], orig_src_ip, orig_src_port, orig_dst_ip, orig_dst_port))
        if exit_asa:
            print('Exit ASA on {} named logical interface - {}:{} --> {}:{}'.format(
                    summary['output'], new_src_ip, new_src_port, new_dst_ip, new_dst_port))
        print('Result:  {}'.format(summary['action']))
        if pt_res['action'] == 'allow' and nexthop_valid:
            print('\t(Egress next-hop:  {})\n'.format(nexthop_ip))
        elif pt_res['action'] == 'drop':
            print('  Selected egress interface:  {}'.format(pt_res['output-interface']))
            print('  Drop reason:  {}'.format(pt_res['drop-reason']))
            print('  Details:  {}\n'.format(deny_info))
        elif pt_res['action'] == 'allow' and not nexthop_valid:
            pass
        else:
            print('Unexpected result "{}"\n\n'.format(pt_res['action']))
            

def test():
    '''Test cases:
       * Permit from inside to outside
         * 172.16.1.1 --> 8.8.8.8
       * Deny from inside to outside
         * 172.16.2.3 --> 128.102.3.230
       * Deny from outside to inside
         * 191.96.249.11 --> 12.40.205.159
         * 201.2.5.137 --> 12.187.127.69:8888
       * Permit from outside to inside
         * 201.2.3.19 --> 12.40.205.159
       * Various drops

       Example Test Run:
       asa = asarest.main()
       asa.ptrace('172.16.1.1', '8.8.8.8') --> Allow
       asa.ptrace('172.16.2.3', '128.102.3.230') --> Drop
       asa.ptrace('191.96.249.11', '12.40.205.159') --> Drop
       asa.ptrace('201.2.5.137', '12.187.127.69', '8888') --> Drop
       asa.ptrace('201.2.3.19', '12.40.205.159') --> Allow

       Debug:
       asa.ptrace('172.16.2.4', '8.8.8.8', show='full') --> Full packet-tracer output
    '''
    asa = main()
    ## res = asa.get_ptrace('172.16.1.1', '8.8.8.8')
    ## asa.print_ptrace(res)
    ## asa.show_ptrace(res)


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


@click.group()
@click.option('--interface', '-i', default='0.0.0.0', prompt='ASA Management Interface IP Address',
              help='IP Address of ASA interface to connect to')
@click.option('--username', '-u', prompt='Username', help='Username to authenticate to ASA')
@click.option('--password', '-pw', prompt='Password', hide_input=True,
              help='Password to authenticate to ASA')
@click.option('--debug/--no-debug', default=False)
@click.pass_context
def cli(ctx, interface, username, password, debug):
    '''CLI tool to interact with Cisco ASA via its REST API.'''
    # Initialize Asa instance and its management interface (how to connect to
    # its API endpoint)
    asa = Asa(mgmt=interface, user=username, passwd=password)

    # Populate context object:
    ctx.obj = {'asa': asa}
    for k, v in [('interface', interface), ('username', username), ('password', password),
                 ('debug', debug)]:
        ctx.obj[k] = v


@cli.command()
@click.option('--source_ip', '-sip', default='0.0.0.0', prompt='Packet Source Address',
              help='Source IP Address for packet-tracer')
@click.option('--destination_ip', '-dip', default='0.0.0.0', prompt='Packet Destination Address',
              help='Destination IP Address for packet-tracer')
@click.option('--source_port', '-sp',
              help='Source Port for packet-tracer, default=random-high-port')
@click.option('--destination_port', '-dp', default='80',
              help='Destination Port for packet-tracer, default=80 (http)')
@click.option('--protocol', '-p', default='tcp', type=click.Choice(['rawip', 'icmp', 'udp',
              'tcp']), help='Protocol for packet-tracer, default=tcp')
@click.option('--ingress_interface', '-I', default=None,
              help='Ingress interface for packet-tracer, default to dynamic lookup '
                   'via ASA routing table.')
@click.pass_context
def ptrace(ctx, source_ip, destination_ip, source_port, destination_port, protocol, ingress_interface):
    '''Leverage ASA's packet-tracer command and routes to summarize policy applied
       to a packet transiting the ASA.'''
    # Populate Asa interfaces and routes
    asa = ctx.obj['asa']
    asa.populate()
    res = asa.ptrace(src_ip=source_ip, dst_ip=destination_ip, src_port=source_port,
                     dst_port=destination_port, proto=protocol, ingress_int=ingress_interface,
                     override=False, verbose=ctx.obj['debug'])
    # print(res)  # Currently printed in method as side effect instead of being returned...


@cli.command()
@click.argument('commands')
@click.pass_context
def cmd(ctx, commands):
    '''Send one or more commands (; delimited) to ASA and display results.
       From a shell will need to supply command(s) in quotes, e.g., "show version"'''
    asa = ctx.obj['asa']
    res = asa.send_cmds(commands, verbose=ctx.obj['debug'])

    # Multiple commands?
    if isinstance(res, OrderedDict):
        for k, v in res.items():
            # Desired length - length of command + length of existing string below
            l = 75 - len(k) + 16
            print('/-----<{}>-{}-\\'.format(k, ('-' * l)))
            print(v, end='')
            print('\\-----</{}>-{}-/\n'.format(k, ('-' * (l - 1))))
    else:
        print(res)


@cli.command()
@click.option('--method', '-m', default='GET', help='HTTP method '
              '[GET|POST|PUT|PATCH|DELETE]')
@click.argument('apiresource')
@click.option('--params', '-pa', help='HTTP query parameter(s) for API resource')
@click.pass_context
def apires(ctx, method, apiresource, params):
    '''Interaction with API Resource using specified HTTP method (default = GET).
       APIResource is the URL part following /api/, e.g., monitoring/apistats
       Optionally include query parameter(s).'''
    asa = ctx.obj['asa']
    method = method.lower()
    res = getattr(asa, method)(apiresource, params=params, verbose=ctx.obj['debug'])

    pprint(res)


if __name__ == '__main__':
    # main(display=True)
    # test()
    cli()

