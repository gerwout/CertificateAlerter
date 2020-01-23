import argparse
import os
import sys
import ssl
import OpenSSL.crypto
import socket

from urllib.parse import urlparse
import time
from datetime import datetime
import math
import configparser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib

# Give it 4 seconds max, before timing out
socket.setdefaulttimeout(4)

def get_configuration():
    dir_path = os.path.dirname(os.path.realpath(__file__))
    config_file = dir_path + "/config.ini"

    try:
        f = open(config_file, "r")
        content = f.read()
    except:
        print("Could not open configuration file " + config_file)
        exit(0)

    config = configparser.ConfigParser()
    config.read_string(content)

    return config

def send_mail(config, send_from, send_to, subject, text):
    assert isinstance(send_to, list)
    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = ",".join(send_to)
    msg['Subject'] = subject
    msg.attach(MIMEText(text, "plain"))
    smtp = smtplib.SMTP(config.get('mail', 'SMTPSERVER'))
    smtp.connect(config.get('mail', 'SMTPSERVER'), 587)
    smtp.starttls()

    if (config.getboolean('mail', 'SMTPAUTH')):
        smtp.login(config.get('mail', 'SMTPUSER'), config.get('mail', 'SMTPPASS'))

    smtp.sendmail(send_from, send_to, msg.as_string())
    smtp.quit()

def return_relevant_cert_data(raw_der_cert):
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, raw_der_cert)
    subject = x509.get_subject()
    new_dict = {}
    new_dict['notAfter'] = datetime.strptime(x509.get_notAfter().decode('latin1'), "%Y%m%d%H%M%SZ")
    new_dict['commonName'] = subject.commonName
    new_dict['subjectAltName'] = []
    ext_count = x509.get_extension_count()
    for i in range(0, ext_count):
        ext = x509.get_extension(i)
        if b'subjectAltName' in ext.get_short_name():
            san = ext.__str__()
            san_tmp = san.split(", ")
            for item in san_tmp:
                new_dict['subjectAltName'].append(item[4:len(item)])

    return new_dict

def get_certificate_details(host_name, port):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    not_trusted = False
    s = ctx.wrap_socket(socket.socket(), server_hostname=host_name)
    try:
        s.connect((host_name, port))
    except (ssl.SSLError, ssl.CertificateError):
        cert_details = {}
        cert_details['not_trusted'] = True
        return cert_details
    except (TimeoutError, socket.timeout):
        cert_details = {}
        cert_details['host_does_not_respond'] = True
        cert_details['not_trusted'] = True
        return cert_details

    cert_details = return_relevant_cert_data(s.getpeercert(binary_form=True))

    if not_trusted:
        cert_details['not_trusted'] = True
    else:
        cert_details['not_trusted'] = False

    return cert_details

def get_url_details(url):
    url = url.lower()
    if not url.startswith('https://'):
        url = "https://" + url
    url_details = urlparse(url)
    domain_and_port = url_details[1]
    tmp_list = domain_and_port.split(":", 2)
    return_dict = {"host": tmp_list[0]}
    if len(tmp_list) == 1:
        return_dict['port'] = 443
    else:
        return_dict['port'] = tmp_list[1]

    return return_dict

def get_days_left(details):
    valid_until = details['notAfter']
    current_time_stamp = time.time()
    cert_timestamp = datetime.timestamp(valid_until)
    days_left = math.floor((cert_timestamp - current_time_stamp) / 3600 / 24)

    return days_left

def has_wildcard_record_match(valid_for, host_name):
    for host in valid_for:
        if "*" in host:
            pos = host.find('*')
            if pos == 0 and host_name.endswith(host[1:len(host)]):
                return True
            elif pos != 0 and host_name.endswith(host[pos + 1:len(host)]) and host_name.startswith(host[0:pos]):
                return True
    return False

def get_certificate_status(site):
    details = get_url_details(site)
    host_name = details['host']
    port = int(details['port'])
    cert_details = get_certificate_details(host_name, port)

    if cert_details.get('host_does_not_respond', False):
        msg = "Host " + host_name + " does not seem to respond, can't check certificate status!" \

        return msg

    if cert_details['not_trusted']:
        msg = "Certificate for host " + host_name + " is not trusted!, please issue a new certificate!"
        return msg

    valid_for = []
    if len(cert_details.get('commonName', "")) > 0:
        valid_for.append(cert_details['commonName'])
    if len(cert_details.get('subjectAltName', [])) == 0:
        msg = "No SAN for: " + host_name + ", this hostname does not comply with the newer RFC2818 and RFC6125 standards"
        msg = msg + ", please create a certificate with a subject alternative name!, Chrome will not trust this certificate!"
        return msg
    else:
        for item in cert_details['subjectAltName']:
            valid_for.append(item)
        valid_for = list(set(valid_for))
        if host_name not in valid_for and not has_wildcard_record_match(valid_for, host_name):
            msg = "The certificate has not been issued for hostname " + host_name + '!'
            return msg
        else:
            days_left = get_days_left(cert_details)
            if days_left == 14:
                msg = "Only 2 weeks left to renew the certificate for " + host_name
                return msg
            elif days_left == 7:
                msg = "Only 1 weeks left to renew the certificate for " + host_name
                return msg
            elif days_left == 1:
                msg = "Only 1 day left to renew the certificate for " + host_name
                return msg

def main():
    parser = argparse.ArgumentParser(description='Check certificates for expiry date')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--file', '-f', required=False, help='Filename with sites to check')
    group.add_argument('--site', '-s', required=False, help='Single site to check')

    # show help when no arguments are given
    if len(sys.argv) == 1:
        parser.print_help(sys.stdout)
        sys.exit(0)
    args = parser.parse_args()
    site = args.site
    file = args.file

    if site is not None:
        site = site.lower()
        msg = get_certificate_status(site)
        if msg is None:
            print("Nothing to do for the certificate " + site)
        else:
            print(msg)
    elif file is not None:
        config = get_configuration()
        send_email = config.getboolean('mail', 'SENDMAIL')
        return_msg = ""
        f = open(file, "r")
        lines = f.readlines()
        f.close()
        for line in lines:
            host_name = line.strip().lower()
            if len(host_name) != 0:
                msg = get_certificate_status(host_name)
                if msg is not None:
                    return_msg = return_msg + msg + "\n"
        if return_msg != "" and send_email:
            if (send_email):
                receivers = config.get('mail', 'RECEIVERS').split(";")
                from_address = config.get('mail', 'FROMADDRESS')
                print("Going to send email...\n")
                send_mail(config, from_address, receivers, "HTTP Certificates Alert " + str(datetime.now()), return_msg)
                print(return_msg)

if __name__ == "__main__":
    main()