# CertificateAlerter
Script that checks HTTPS hostnames to verify is there is a trust issue or if renewal is needed.

You can configure it by copying config.ini.example into config.ini and edit it afterwards.
You need to install Python3 and the dependencies can be installed with pip install -r requirements.txt.
This script also has the ability to check "local" certificates that have been issued by your own certificate authority.
This script currently supports email alerts and/or Zendesk integration.

# Usage

The below example will check the certificate for www.example.com
python alerter.py --site www.example.com

The below example will check all hostnames in the file hosts.txt. Every host name needs to be on a single line.
python alerter.py --file c:\hosts.txt

# Checking non default ports
By default it will check port 443. If your certificate is installed on a different port this can be checked by adding the port 
to the hostname seperated by a colon (i.e. www.example.com:8443 will check port 8443 on the host www.example.com)


