import requests

requests.packages.urllib3.disable_warnings()

headers = {'User-Agent': 'ASDM/ Java/1.8.0_131'}

payload = {'username': 'cisco', 'password': 'cisco', 'group_list': '', 'tgroup':
           'DefaultADMINGroup', 'Login': 'Login'}


# Use session object
s = requests.Session()
# s.auth = ('cisco', 'cisco')  # Username, Password
s.headers.update(headers)
s.verify = False

# Initial request
r = s.get('https://198.51.100.164/admin/login_banner')

# Login
r = s.post('https://198.51.100.164/+webvpn+/index.html', data=payload)
# Should have webvpn cookie now, appears to be auth token

# Remove webvpnlogin cookie
s.cookies.pop('webvpnlogin')

# Get ASDM Version Info (binary version, size, launcher version)
r = s.get('https://198.51.100.164/admin/version.prop')
print(r.text)

# Get ASDM Banner (if exists)
r = s.get('https://198.51.100.164/admin/asdm_banner')
print(r.text)

# Execute one or more commands
# Single:
r = s.get('https://198.51.100.164/admin/exec/show+version')
print(r.text)

# Multiple:
# Convenient but no separation between commands!
r = s.get('https://198.51.100.164/admin/exec/show+version/show+curpriv/perfmon+interval+10/'
          'show+asdm+sessions/show+firewall/show+mode/changeto+system/show+admin-context')
print(r.text)

# Packet-tracer:
r = s.get('https://198.51.100.164/admin/exec/packet-tracer+input+inside+tcp+172.16.1.101'
          '+32768+8.8.8.8+80+detailed+xml')
print(r.text)

