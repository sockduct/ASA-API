# ASA REST API Requirements/Info

## Requirements
* ASA version 9.3.2 or greater

## Information
* [ASA 5500-X Documentation, Configuration Guides](https://www.cisco.com/c/en/us/support/security/asa-5500-series-next-generation-firewalls/products-installation-and-configuration-guides-list.html)
  * [ASA REST API - About v1.3.2, Main Guide](https://www.cisco.com/c/dam/en/us/td/docs/security/asa/api/asapedia_rest_api_132.pdf)
* [ASA 5500-X Documentation, Install and Upgrade Guides](https://www.cisco.com/c/en/us/support/security/asa-5500-series-next-generation-firewalls/products-installation-guides-list.html)
  * [ASA REST API Quick Start Guide](https://www.cisco.com/c/en/us/td/docs/security/asa/api/qsg-asa-api.html)
* [ASA 5500-X Documentation, Release Notes](https://www.cisco.com/c/en/us/support/security/asa-5500-series-next-generation-firewalls/products-release-notes-list.html)
  * [ASA REST API Release Notes, v1.3.x](https://www.cisco.com/c/en/us/td/docs/security/asa/api/13/asa-api-rn-13.html)
* ASA REST API Status Codes (standard HTTP):
  * 200 OK - request completed successfully
  * 201 Created - request completed successfully and object created
  * 202 Accepted - request accepted, being processed (not finished)
  * 204 No Content - request accepted, no content (e.g., query empty object?)
  * 400 - Bad Request
  * 404 - Not Found
  * 405 - Method not Allowed
  * 5xx - Server-side Error

## ASA CLI Configuration
```
http server enable
!
http <access-network> <netmask> <mgmt-nameif>
! access-network - the network from which you're accessing the ASA REST API
! mgmt-nameif - the logical name (nameif) of the interface you're connecting to
! Note:  You cannot connect through the ASA - you must connect to the address of the interface you enter the firewall at.  In other words, if you're on the "inside" interface, you must connect to the "inside" interface IP and not for example to the "dmz" interface IP.
!
aaa authentication http console LOCAL
!
username <user> password <password> privilege 15
! Note:
!        priv >= 3: invoke monitoring requests
!        priv >= 5: invoke get requests
!        priv >= 15: invoke put/post/delete requests
!
! Note:  if aaa authorization enabled, REST agent requires user "enable_1" with priv 15 to exist - used by agent
!
rest-api image <path-to-image>
! e.g., rest-api image disk0:/asa-restapi-132100-lfbff-k8.SPA
!
rest-api agent
! Note:  Redirects requests to /api to the agent
!        Confirm it's enabled:  show rest-api agent
```

## Troubleshooting
* Confirm REST API Agent active:
  `show rest-api agent`
* Debugs:
  ```
  debug rest-api [agent | cli | client | daemon | process | token-auth] {event, error}
  debug http [1-255]
  ```

## Examples
* User Privilege Levels:
  * priv <= 2: no access via REST API
  * priv >= 3: invoke monitoring requests (/api/monitoring/*)
  * priv >= 5: invoke get requests
  * priv = 15: invoke put/post/patch?/delete requests
* GET - Retrieve data from specified object (no request body)
  * Monitoring Example (priv >= 3):
    * Get ASA Serial Number (https://<ASA>/api/monitoring/serialnumber):
      ```
      asacli -i 198.51.100.164 -u cisco3 -pw cisco apires monitoring/serialnumber
      {'kind': 'object#QuerySerialNumber', 'serialNumber': '9ALHB4GTPD7'}
      ```
  * General Example (priv >= 5):
    * Get configured NTP Servers (https://<ASA>/api/devicesetup/ntp/servers):
      ```
      asacli -i 198.51.100.164 -u cisco5 -pw cisco apires devicesetup/ntp/servers
      {'items': [{'interface': {
                      'kind': 'objectRef#Interface',
                      'name': 'inside',
                      'objectId': 'GigabitEthernet0_API_SLASH_2',
                      'refLink': 'https://198.51.100.164/api/interfaces/physical/GigabitEthernet0_API_SLASH_2'
                     },
                  'ipAddress': '172.16.116.7',
                  'isPreferred': True,
                  'kind': 'object#NTPServer',
                  'objectId': '172.16.116.7',
                  'selfLink': 'https://198.51.100.164/api/devicesetup/ntp/servers/172.16.116.7'
                 }],
       'kind': 'collection#NTPServer',
       'rangeInfo': {'limit': 1, 'offset': 0, 'total': 1},
       'selfLink': 'https://198.51.100.164/api/devicesetup/ntp/servers?offset=0'
      }
      ```
* PUT - Adds supplied information to specified object (update/replace/modify *existing* resource); If object doesn't exist, returns a 404 Resource Not Found error
  * General Example (priv = 15):
* POST - Creates (new) object with supplied information
  * General Example 1 (priv = 15):
    * Send command to ASA (https://<ASA>/api/cli, body={"commands": ["cmd1", "cmd2"]}
      ```
      # In PowerShell - Note that PowerShell escape character is the backquote:
      asacli -i 198.51.100.164 -u cisco -pw cisco apires -m post cli -b "`"{'commands': ['show firewall', 'show asdm image']}`""
      {'response': ['Firewall mode: Router\n',
                    'Device Manager image file, boot:/asdm-79247.bin\n']}
      ```
  * General Example 2 (priv = 15):
    * Add NTP Server to ASA (https://<ASA>/api/devicesetup/ntp/servers, body={"interface": {"kind": "objectRef#Interface", "objectId": "GigabitEthernet0_API_SLASH_4"}, "isPreferred": false, "ipAddress": "3.3.3.3", "key": { "isTrusted": false, "number": "3", "value": "test3"}}
      ```
       asacli -i 198.51.100.164 -u cisco -pw cisco apires -m post devicesetup/ntp/servers -b "`"{'interface': {'kind': 'objectRef#Interface', 'objectId': 'GigabitEthernet0_API_SLASH_2'}, 'isPreferred': false, 'ipAddress': '172.16.126.8'}`""
      ```
* DELETE - Removes specified object (no request body)
  * General Example (priv = 15):
    * Remove NTP Server from ASA (https://<ASA>/api/devicesetup/ntp/servers/<NTP-Srv-IP>)
      ```
      asacli -i 198.51.100.164 -u cisco5 -pw cisco apires -m delete devicesetup/ntp/servers/172.16.126.8
      ```
* PATCH - Applies partial modifications to specified object
  * General Example (priv = 15):
 
