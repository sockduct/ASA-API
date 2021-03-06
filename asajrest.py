#!/usr/bin/env python
'''AsaJRestApi - class to facilitate interaction with Cisco ASA via its
   undocumented Java REST API used by ASDM'''
# Supported in Python v2.7 and 3.5+
###################################################################################################
# To do:
# * See alacli.py
###################################################################################################

###################################################################################################
# Cisco ASA RESTful API, Supported Methods (request body in JSON format):
# * GET - Retrieve data from specified object (no request body)
# * POST - Creates (new) object with supplied information
#==/Not sure if these are implemented...\==========================================================
# * PUT - Adds supplied information to specified object (update/replace/modify *existing*
#         resource); If object doesn't exist, returns a 404 Resource Not Found error
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
# * Since using undocumented, non-public API - not sure when changes will occur or how stable
#   the interface is...
###################################################################################################

# Python 2.x/3.x compatibility for print:
from __future__ import print_function
# Python 2.x/3.x compatibiltiy for strings:
from __future__ import unicode_literals

# stdlib
from collections import OrderedDict  # Needed?
import sys  # sys.exit

# 3rd party
import netaddr  # Prefer Python 3 ipaddress library?
# If want this to run on non-Windows platforms need some logic around this:
import requests
from requests.exceptions import ConnectTimeout, ReadTimeout


# Inherit from object for 2.x/3.x compatibility (always use new-style classes)
class AsaJRestApi(object):
    __header = {'User-Agent': 'ASDM/ Java/1.8.0_131'}

    def _auth(self, verbose=False):
        '''Check if current session is authenticated to ASA and if not then
           authenticate.'''
        payload = {'username': self.user, 'password': self.passwd, 'group_list': '', 'tgroup':
                   'DefaultADMINGroup', 'Login': 'Login'}

        # Check for session attribute
        if 'sess' not in self.__dict__:
            self.sess = None

        # If session empty then setup
        if self.sess is None:
            self.sess = requests.Session()
            self.sess.headers.update(AsaJRestApi.__header)
            self.sess.verify = self.verify

            retries = 0
            while True:
                # Initial request
                try:
                    resp = self.sess.get('https://' + self.mgmt + '/admin/login_banner',
                                         timeout=self.timeout)
                    # Debug
                    if verbose:
                        print('AsaJRestAPI._auth.resp after GET /admin/login_banner:\n'
                              '{}'.format(resp.__dict__))
                        print('\nresp.text (length={}):\n{}'.format(len(resp.text), resp.text))

                    # Check if resp.content length is 0
                    if len(resp.text) > 0:
                        # Login
                        resp = self.sess.post('https://' + self.mgmt + '/+webvpn+/index.html',
                                              data=payload, timeout=self.timeout)
                        # Debug
                        if verbose:
                            print('AsaJRestAPI._auth.resp after POST:\n{}'.format(resp.__dict__))
                        # Should have webvpn cookie now, appears to be auth token

                        # Remove webvpnlogin cookie
                        self.sess.cookies.pop('webvpnlogin')

                        # Check for session cookie:
                        if 'webvpn' in self.sess.cookies and self.sess.cookies['webvpn']:
                            return True
                        else:
                            return False
                    # Plan B
                    else:
                        self.sess.auth=(self.user, self.passwd)
                        resp = self.sess.get('https://' + self.mgmt + '/admin/version.prop',
                                             timeout=self.timeout, auth=(self.user, self.passwd))
                        # Debug
                        if verbose:
                            print('AsaJRestAPI._auth.resp after GET /admin/version.prop:\n'
                                  '{}'.format(resp.__dict__))

                        if resp.ok:
                            return True
                except ConnectTimeout:
                    retries += 1
                    if verbose:
                        print('auth connection timed out/failed to complete within timeout '
                              'period ({}s) - retry # {}...'.format(self.timeout, retries))
                    if retries <= self.retry:
                        continue
                    else:
                        sys.exit('Error:  Exceeded maximum number of retries ({}) for get'
                                 ' - giving up.'.format(self.retry))

                if not resp.ok:
                    resp.raise_for_status()
                else:
                    return False
        # If session populated, assume valid
        else:
            return True


    def get(self, resource, params=None, verbose=False, *args, **kwargs):
        '''ASA Java REST API - GET:  retrieve data via specified URL'''
        pass

    def post(self, resource, payload, verbose=False):
        '''ASA Java REST API - POST:  submit data in body'''

    def delete(self, resource):
        '''ASA Java REST API - DELETE:  deletes specified object
           Requires user with privilege level 15'''
        raise(NotImplementedError)

    def put(self, resource):
        '''ASA Java REST API - PUT:  add supplied information to specified object
           Returns 404 (resource not found) error if object does not exist
           Requires user with privilege level 15'''
        raise(NotImplementedError)

    def patch(self, resource):
        '''ASA Java REST API - PATCH:  applies partial modifications to specified object'''
        raise(NotImplementedError)

    def send_cmds(self, cmds, verbose=False):
        '''Send one or more commands to ASA.  Some commands may have to use
           alternate POST interface but not clear which ones...'''
        if not self._auth(verbose):
            sys.exit('Problem authenticating to ASA')

        cmd_array = [c.strip() for c in cmds.split(';')]
        # Remove empty strings, use list for 3.x to iterate iterable
        cmd_array = list(filter(None, cmd_array))
        if verbose:
            print('Asa.send_cmds/parsed out:  {}'.format(cmd_array))

        cmd_array = [c.replace(' ', '+') for c in cmd_array]
        url_suffix = '/' + '/'.join(cmd_array) + '/'

        resp = self.sess.get('https://' + self.mgmt + '/admin/exec' + url_suffix)
        # Error handling
        # Parsing out responses?

        return resp.text

    def populate_ints(self, resp_data, itype):
        '''Populate internal ASA interface table for use by other methods.'''
        raise(NotImplementedError)

    def populate_routes(self, resp_data, rtype):
        '''Populate internal ASA routing table for use by other methods.'''
        raise(NotImplementedError)

    def populate(self, verbose=False):
        '''Populate internal ASA tables for use by other methods.'''
        raise(NotImplementedError)

    def print_ints(self, itype='all'):
        '''Display ASA interfaces from internal table.'''
        raise(NotImplementedError)

    def print_routes(self, rtype='static'):
        '''Display ASA routes from internal table.'''
        raise(NotImplementedError)

    def get_nexthop(self, address):
        '''Return tuple with best match prefix, egress physical interface,
           egress logical interface, egress next-hop.'''
        raise(NotImplementedError)

