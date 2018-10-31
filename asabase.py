#!/usr/bin/env python
'''AsaBase - class to facilitate interaction with Cisco ASA via RESTful API'''
# Supported in Python v2.7 and 3.5+
###################################################################################################
# To do:
# * See asacli.py
###################################################################################################

###################################################################################################
# Cisco ASA Base Class
# Comments???
#==================================================================================================
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

# Python 2.x/3.x compatibility for print:
from __future__ import print_function
# Python 2.x/3.x compatibiltiy for strings:
from __future__ import unicode_literals

# stdlib
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
# If want this to run on non-Windows platforms need some logic around this:
import win_inet_pton    # Must be imported before radix in Windows
                        # inet_pton not in stdlib socket library in Windows until v3.4
                        # However, radix uses C extension modules which still fail to
                        # import even in v3.4+
import radix            # Note:  pip install py-radix
import requests
from requests.exceptions import ConnectTimeout, ReadTimeout

# Globals
RETRY = 2
TIMEOUT = 3.0
VERIFY = False  # Validate X.509 Certificate? Typically self-signed so default to no.

# Ignore certificate errors since typically using self-signed certs
requests.packages.urllib3.disable_warnings()


# Inherit from object for 2.x/3.x compatibility (always use new-style classes)
# Incomplete - need to mixin either AsaRestApi or AsaJRestApi
class AsaBase(object):
    # Keep in the class to facilitate thread safety
    rng = random.SystemRandom()

    def __init__(self, mgmt, user, passwd, retry=RETRY, timeout=TIMEOUT, verify=VERIFY):
        self.mgmt = mgmt
        self.user = user
        self.passwd = passwd
        self.retry = retry
        self.timeout = timeout
        self.verify = verify
        self.data = {}
        self.rtree = radix.Radix()
        self.ptrace_data = {}

    def __repr__(self):
        return ('<Cisco ASA:  management address={}, username={}, retry={} timeout={}, '
                'validate certificate={}>\n\t<{{data keys:  {}}}, {{radix tree size:  {} '
                'prefixes}}>\n\t<{{data/routes/static:  {} prefixes ({} ipv4)}}>\n\t<{{data/'
                'interfaces:  physical - {}, logical - {}, vlan - {}}}>'.format(self.mgmt,
                    self.user, self.retry, self.timeout, self.verify, self.data.keys(),
                    len(self.rtree.prefixes()), self.data['routes']['static']['count'],
                    len(self.data['routes']['static']['items']['ipv4']),
                    self.data['interfaces']['physical']['count'], self.data['interfaces'][
                        'logical']['count'], self.data['interfaces']['vlan']['count']))

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
            src_port = AsaBase.rng.randint(49152, 65535)

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

