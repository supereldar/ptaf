import requests, sys
import re
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET

class bcolors:
 HEADER = '\033[95m'
 OKBLUE = '\033[94m'
 OKGREEN = '\033[92m'
 WARNING = '\033[93m'
 FAIL = '\033[91m'
 ENDC = '\033[0m'
 BOLD = '\033[1m'
 UNDERLINE = '\033[4m'

attack = 0
wafjs = 0
token = 0
header = 0
serverheader = 0
xpoweredbyheader = 0
if len(sys.argv) < 2:
 print 'Usage: %s <url>'  % sys.argv[0]
 print 'Usage: %s <url> safe'  % sys.argv[0]
 sys.exit(-1)

url = sys.argv[1]
try:
 safeflag = sys.argv[2]
except:
 safeflag = 0
print bcolors.HEADER + "Check based on response headers (high false positive rate)" + bcolors.ENDC
r = requests.get(url,allow_redirects = False)
i=1
try:
 if r.headers['Server']:
  print "(-) Server header exist, must be removed by PT AF"
  serverheader = 1
except:
 pass
try:
 if r.headers['X-Powered-By']:
  print "(-) X-powered-by header exist, must be removed by PT AF"
  xpoweredbyheader = 1
except:
 pass
try:
 if r.headers['X-XSS-Protection'] == "1; mode=block":
  print "(+) X-XSS-Protection is set (%d/4)" % i
  i = i + 1
except:
 pass
try:
 if r.headers['X-Content-Type-Options'] == "nosniff":
  print "(+) X-Content-Type is set (%d/4)" % i
  i = i + 1
except:
 pass
try:
 if r.headers['X-Frame-Options'] == "SAMEORIGIN":
  print "(+) X-Frame-Options is set (%d/4)" % i
  i = i + 1
except:
 pass
try:
 if r.cookies['session-cookie']:
  print "(+) session-cookie is set (%d/4)" % i
  i = i + 1
except:
 pass
if i == 1:
  print "(-) No PT AF headers were found"
else:
 headers = 1

print bcolors.HEADER + "\nCheck based on tokens in meta tags (low false positive rate)" + bcolors.ENDC
r = requests.get(url)
try:
 soup = BeautifulSoup(r.text, "html.parser")
 metatags = re.findall("<meta.*/>", str(soup.find('head')))
except:
 pass
i=1
for metatag in metatags:
 try:
  xml = ET.fromstring(metatag)
 except:
  pass
 try:
  if xml.attrib['content'] == "csrftoken" and xml.attrib['name'] == "csrf-token-name":
   print "(+) csrftoken is set (%d/3)" % i
   i = i + 1
 except:
  pass
 try:
  if xml.attrib['content'] == "Ajax-Token" and xml.attrib['name'] =="hmac-token-name" : 
   print "(+) Ajax-token is set (%d/3)" % i
   i = i + 1
 except:
  pass
 try:
  if xml.attrib['name'] == "csrf-token-value":
   print "(+) csrf-token-value is set (%d/3)" % i 
   i = i + 1
 except:
  pass
if i == 1:
 print "(-) No PT AF tokens were found"
else:
 token = 1

print bcolors.HEADER + "\nCheck based on attacks (low false positive rate)" + bcolors.ENDC
r = requests.put(url)
try:
 if re.findall("<h1>Forbidden</h1><pre>Request ID: [0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[A-F0-9]{16}</pre>",r.text):
  print "(+) PUT method trigger defaults block page"
  attack = 1
 else:
  print "(-) PUT method didn't trigger defaults page"
except:
 pass

if not safeflag == 'safe': 
 r = requests.get(url,data={'testparamXRDCYGBU23567': '/../../'})
 try:
  if re.findall("<h1>Forbidden</h1><pre>Request ID: [0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[A-F0-9]{16}</pre>",r.text):
   print "(+) Path traversal trigger defaults block page"
   attack = 1
  else:
   print "(-) Path traversal didn't trigger defaults page"
 except:
  pass

print bcolors.HEADER + "\nCheck based on waf.js presence (low false positive rate)" + bcolors.ENDC
if re.findall("[a-f0-9]{24}\.js\?[0-9]{13}",r.text):
 print "(+) waf.js is present"
 wafjs = 1
else:
 print "(-) waf.js is not present"

if attack or wafjs or token:
 print bcolors.OKGREEN + '\nANSWER: PT AF detected.' + bcolors.ENDC
 sys.exit(0)

if serverheader or xpoweredbyheader:
 print bcolors.FAIL + '\nANSWER: PT AF is not installed.' + bcolors.ENDC
 sys.exit(0)

if headers:
 print bcolors.WARNING +'\nANSWER: PT AF might be installed.' + bcolors.ENDC
 sys.exit(0)

 print '\nPT AF is not installed.'
