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
  * 200 - OK, request completed successfully
  * 201 - Created, request completed successfully and object created
  * 202 - Accepted, request accepted, being processed (not finished)
  * 204 - No Content, request accepted, no content (e.g., query empty object?)
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
! Note:  You cannot connect through the ASA - you must connect to the address of the interface
!        you enter the firewall at.  In other words, if you're on the "inside" interface, you
!        must connect to the "inside" interface IP and not for example to the "dmz" interface IP.
!
! Also possible to use external AAA Servers, but not shown here:
aaa authentication http console LOCAL
!
username <user> password <password> privilege <0-15>
! Note:
!        priv >= 3: invoke monitoring requests
!        priv >= 5: invoke get requests
!        priv = 15: invoke put/post/delete requests
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
  * priv = 15: invoke post/put/patch?/delete requests
* Notes:
  * All usernames use the password "cisco"
  * Usernames end with a number corresponding to their privilege level, e.g., cisco5 = user with privilege level 5
  * Examples tested on Windows 10 x64 with PowerShell v5.1
  * PowerShell prompt represented as:  `PS>`
  * Response from ASA REST API represented as:  `<-- ASA REST Response: -->`
  * Questions on other platforms/shells (e.g., Windows Legacy Command Prompt, Linux w/ bash, etc.) welcome - please open an issue or submit a PR
* GET - Retrieve data from specified object (no request body)
  * Monitoring Example (priv >= 3):
    * Get ASA Serial Number (https://\<ASA\>/api/monitoring/serialnumber):
      ```
      PS> asacli -i 198.51.100.164 -u cisco3 -pw cisco apires monitoring/serialnumber
      
      <-- ASA REST Response: -->
      ASA Response Status Code:  200
      {'kind': 'object#QuerySerialNumber', 'serialNumber': '9ALHB4GTPD7'}
      ```
  * General Example (priv >= 5):
    * Get configured NTP Servers (https://\<ASA\>/api/devicesetup/ntp/servers):
      ```
      PS> asacli -i 198.51.100.164 -u cisco5 -pw cisco apires devicesetup/ntp/servers
      
      <-- ASA REST Response: -->
      ASA Response Status Code:  200
      {'items': [{'interface': {'kind': 'objectRef#Interface',
                                'name': 'outside',
                                'objectId': 'GigabitEthernet0_API_SLASH_0',
                                'refLink': 'https://198.51.100.164/api/interfaces/physical/GigabitEthernet0_API_SLASH_0'},
                  'ipAddress': '203.0.113.33',
                  'isPreferred': True,
                  'kind': 'object#NTPServer',
                  'objectId': '203.0.113.33',
                  'selfLink': 'https://198.51.100.164/api/devicesetup/ntp/servers/203.0.113.33'},
                 {'ipAddress': '203.0.113.254',
                  'isPreferred': False,
                  'kind': 'object#NTPServer',
                  'objectId': '203.0.113.254',
                  'selfLink': 'https://198.51.100.164/api/devicesetup/ntp/servers/203.0.113.254'}],
       'kind': 'collection#NTPServer',
       'rangeInfo': {'limit': 2, 'offset': 0, 'total': 2},
       'selfLink': 'https://198.51.100.164/api/devicesetup/ntp/servers?offset=0'}
      ```
    * Get specific NTP Server (https://\<ASA\>/api/devicesetup/ntp/servers/\<Address\>):
      ```
      PS> asacli -i 198.51.100.164 -u cisco5 -pw cisco apires devicesetup/ntp/servers/203.0.113.254
      
      <-- ASA REST Response: -->
      ASA Response Status Code:  200
      {'ipAddress': '203.0.113.254',
       'isPreferred': False,
       'kind': 'object#NTPServer',
       'objectId': '203.0.113.254',
       'selfLink': 'https://198.51.100.164/api/devicesetup/ntp/servers/203.0.113.254'}    
      ```
* POST - Creates (new) object with supplied information
  * General Example 1 (priv = 15):
    * Send command to ASA (https://\<ASA\>/api/cli<br>
      Request Body:  {"commands": ["cmd1", "cmd2"]}
      ```
      # Note:  PowerShell escape character is the backquote (\`).
      PS> asacli -i 198.51.100.164 -u cisco15 -pw cisco apires -m post cli -b "`"{'commands': ['show firewall', 'show asdm image']}`""
      
      <-- ASA REST Response: -->
      ASA Response Status Code:  200
      {'response': ['Firewall mode: Router\n',
                    'Device Manager image file, boot:/asdm-79247.bin\n']}
      ```
  * General Example 2 (priv = 15):
    * Add NTP Server to ASA (https://\<ASA\>/api/devicesetup/ntp/servers<br>
      Request Body:  { "interface": {
                           "kind": "objectRef#Interface",
                           "objectId": "GigabitEthernet0_API_SLASH_1"
                       },
                       "isPreferred": false,
                       "ipAddress": "172.17.1.254" }
      ```
      PS> asacli -i 198.51.100.164 -u cisco15 -pw cisco apires -m post devicesetup/ntp/servers -b "`"{'interface': {'kind': 'objectRef#Interface', 'objectId': 'GigabitEthernet0_API_SLASH_1'}, 'isPreferred': false, 'ipAddress': '172.17.1.254'}`""
      
      <-- ASA REST Response: -->
      ASA Response Status Code:  201
      ```
* PUT - Adds supplied information to specified object (update/replace/modify *existing* resource); If object doesn't exist, returns a 404 Resource Not Found error
  * General Example (priv = 15):
    * Update NTP Server on ASA (https://\<ASA\>/api/devicesetup/ntp/servers/\<Address\><br>
      Request Body:  { "interface": {
                           "kind": "objectRef#Interface",
                           "objectId": "GigabitEthernet0_API_SLASH_0"
                       },
                       "isPreferred": false,
                       "ipAddress": "192.0.2.254"}
      ```
      PS> asacli -i 198.51.100.164 -u cisco15 -pw cisco apires -m put devicesetup/ntp/servers/172.17.1.254 -b "`"{'interface': {'kind': 'objectRef#Interface', 'objectId': 'GigabitEthernet0_API_SLASH_0'}, 'ipAddress': '192.0.2.254'}`""
      
      <-- ASA REST Response: -->
      ASA Response Status Code:  204
      ```
* PATCH - Applies partial modifications to specified object
  * General Example (priv = 15):
    * Update NTP Server on ASA (https://\<ASA\>/api/devicesetup/ntp/servers/\<Address\><br>
      Request Body:  {"ipAddress": "192.0.2.254"}
      ```
      PS> asacli -i 198.51.100.164 -u cisco15 -pw cisco apires -m patch devicesetup/ntp/servers/192.0.2.254 -b "`"{'ipAddress': '192.0.2.1'}`""
      
      <-- ASA REST Response: -->
      ASA Response Status Code:  204
      ```
* DELETE - Removes specified object (no request body)
  * General Example (priv = 15):
    * Remove NTP Server from ASA (https://\<ASA\>/api/devicesetup/ntp/servers/<NTP-Srv-IP>)
      ```
      PS> asacli -i 198.51.100.164 -u cisco15 -pw cisco apires -m delete devicesetup/ntp/servers/192.0.2.1
      
      <-- ASA REST Response: -->
      ASA Response Status Code:  204
      ```
 
