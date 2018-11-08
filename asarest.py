#!/usr/bin/env python
'''AsaRestApi - class to facilitate interaction with Cisco ASA via its REST API'''
# Supported in Python v2.7 and 3.5+
###################################################################################################
# To do:
# * See alacli.py
###################################################################################################

###################################################################################################
# Cisco ASA RESTful API, Supported Methods (request body in JSON format):
# * GET - Retrieve data from specified object (no request body)
# * PUT - Adds supplied information to specified object (update/replace/modify *existing*
#         resource); If object doesn't exist, returns a 404 Resource Not Found error
# * POST - Creates (new) object with supplied information
# * DELETE - Removes specified object (no request body)
# * PATCH - Applies partial modifications to specified object
#==================================================================================================
# RESTful Responses:
# Location Header - newly created resource ID, for POST only holds the new resource ID as URI
# HTTP Status Codes:
# * 20x - A two-hundred series code indicates successful operation, including:
#   * 200 OK - Standard response for successful (GET) requests
#   * 201 Created - Request completed; new resource created (POST)
#   * 202 Accepted - Request accepted, but processing not complete
#   * 204 No Content - Server successfully processed request; no content is being returned
#         (PUT|PATCH|DELETE)
# * 4xx - A four-hundred series code indicates a client-side error, including:
#   * 400 Bad Request - Invalid query parameters, including unrecognized parameters, missing
#         parameters, or invalid values
#   * 401 Unauthorized - Invalid credentials supplied to perform requested operation
#   * 403 Forbidden - User has insufficient privileges to perform requested operation
#   * 404 Not Found - The provided URL does not match an existing resource. e.g, an HTTP DELETE
#         may fail because the resource is unavailable
#   * 405 Method not Allowed - An HTTP request was presented that is not allowed on the resource;
#         e.g., a POST on a read-only resource
# * 5xx - A five-hundred series code indicates a server-side error
#   * 500 Server Error - A catch-all for any other failure, this should be the last choice when
#         no other response code makes sense
#   * 503 Service Unavailable - Exceeded maximum session limit for authentication tokens
# Additional error/diagnostic information:
# * In the case of an error, the return response may inclulde a list of one or more dicts each
#   with:  code: Error/Warning/Info_code-as-string, details: Detailed_message_corresponding_to_
#          error/warning/info_code-as-string, context: <attribute-name>,
#          level: "Error" or "Warning" or "Info" as-string
#==================================================================================================
# Notes:
# * ASA RESTful API documentation portal:  https://<ASA-Mgmt-Address>/doc/
# * Changes via RESTful API non-persistent, to save you can POST a writemem API request
###################################################################################################

# Python 2.x/3.x compatibility for print:
from __future__ import print_function
# Python 2.x/3.x compatibiltiy for strings:
from __future__ import unicode_literals

# stdlib
from collections import OrderedDict
import sys

# 3rd party
import netaddr
# If want this to run on non-Windows platforms need some logic around this:
import requests
from requests.exceptions import ConnectTimeout, ReadTimeout


# Inherit from object for 2.x/3.x compatibility (always use new-style classes)
class AsaRestApi(object):
    def get(self, resource, params=None, verbose=False, *args, **kwargs):
        '''ASA REST API - GET:  retrieve data from specified object
           Requires user with privilege level 3 or greater for /api/monitoring/*
           Requires user with privilege level 5 or higher for /api/*'''
        # Note:  Additional arguments (args/kwargs) are ignored - e.g., if body=... passed
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
                if retries <= self.retry:
                    continue
                else:
                    sys.exit('Error:  Exceeded maximum number of retries ({}) for get'
                             ' - giving up.'.format(self.retry))

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
            elif resp.status_code == 400:
                sys.exit('Error:  Asa.get:  ASA states request is bad (400).  Please '
                         'check the supplied arguments and make sure the API path is '
                         'valid (include the part after "/api/":  Good - "monitoring/'
                         'arp", Bad - "api/monitoring/arp" or "/monitoring/arp"), '
                         'check that any additional arguments are correctly formatted.')
            elif resp.status_code == 401:
                sys.exit('Error:  Asa.get:  ASA states invalid user credentials supplied'
                         ' for requested operation (401).  Did you enter the wrong '
                         'username and/or password?')
            elif resp.status_code == 403:
                sys.exit('Error:  Asa.get:  ASA states user credentials have insufficient'
                         ' privileges for requested operation (403).')
            else:
                resp.raise_for_status()

    def post(self, resource, payload, params=None, verbose=False):
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
                if retries <= self.retry:
                    continue
                else:
                    sys.exit('Error:  Exceeded maximum number of retries ({}) for post'
                             ' - giving up.'.format(self.retry))
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

    # Similar to get, no body and only status code back
    def delete(self, resource):
        '''ASA REST API - DELETE:  deletes specified object
           Requires user with privilege level 15'''
        raise(NotImplementedError)

    # Similar to post - see if can combine
    def put(self, resource):
        '''ASA REST API - PUT:  add supplied information to specified object
           Returns 404 (resource not found) error if object does not exist
           Requires user with privilege level 15'''
        raise(NotImplementedError)

    # Similar to post - see if can combine
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
            resp = self.get(resource, verbose=verbose)
            if resp:
                if verbose:
                    print('Processing {} from {}...'.format(resource, self.mgmt))
                    print('View with object method print_ints or print_routes '
                          'passing in {}.'.format(rc))
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

