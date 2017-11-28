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

## Configuration
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
  
