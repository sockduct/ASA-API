#!/usr/bin/env python
'''Asa - class to facilitate interaction with Cisco ASA via RESTful API'''
# Supported in Python v2.7 and 3.5+
###################################################################################################
# To do:
# * Add support for Bulk API
# * Support getting authentication token vs. username/password auth
# * Benchmark requests using user/password vs. token-based authentication
# * Finish methods - delete, put, patch
# * Make sure API-based get requests can process more than 100 items
# * Add support for "legacy" HTTP interface used by ASDM
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
#   * Support ICMP Type/Code options
# * populate_ints only supports physical and vlan types, improve to check for all interface
#   types (bvi, ethernet, firepower, portchannel, redundant, setup), should also check if
#   in single or multi mode as the latter requires a different API
# * Check if physical (and VLAN) interface is up/up - if not, account for so prefix not used
# * Add regexp search for interfaces and routes
# * Add IPv6 support
###################################################################################################

# Python 2.x/3.x compatibility:
from __future__ import print_function
# Removed to make click happy, but this results in a disparity between 2.x and
# 3.x strings:
# from __future__ import unicode_literals

# stdlib
from collections import OrderedDict
import pprint
import sys

# 3rd party
import click

# Package
from asa import Asa


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
    '''CLI tool to interact with Cisco ASA via RESTful API.'''
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
@click.option('--body', '-b', help='HTTP request body in JSON format (POST/PUT/PATCH only)')
@click.pass_context
def apires(ctx, method, apiresource, params, body):
    '''Interaction with API Resource using specified HTTP method (default = GET).
       APIResource is the URL part following /api/, e.g., monitoring/apistats
       Optionally include query parameter(s).'''
    asa = ctx.obj['asa']
    method = method.lower()
    if (method == 'get' or method == 'delete') and body:
        sys.exit('Error:  GET/DELETE methods do not support a request body!')
    elif method not in ['get', 'post', 'put', 'patch', 'delete']:
        sys.exit('Error:  Supported methods are GET, POST, PUT, PATCH, DELETE.')
    else:
        res = getattr(asa, method)(apiresource, params=params, body=body, verbose=ctx.obj['debug'])

    # Nicely format JSON output
    fres = pprint.pformat(res)
    # Use click to page through results
    click.echo_via_pager(fres)


if __name__ == '__main__':
    # main(display=True)
    # test()
    cli()

