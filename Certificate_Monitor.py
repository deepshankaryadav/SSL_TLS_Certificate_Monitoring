#!/usr/bin/env python
# Initial Code Written by Br0wn_Sugar
__author__ = "Deep Shankar Yadav"
__credits__ = ["Nishtha Wadhwan for Idea"]
__license__ = "BUBBU - Buy Us Beer Before Use"
__version__ = "0.2"
__email__ = "mail@deepshankaryadav.net"
__status__ = "Development"

import ssl
import OpenSSL
import logging.handlers
from ndg.httpsclient.subj_alt_name import SubjectAltName
from ndg.httpsclient.ssl_peer_verification import SUBJ_ALT_NAME_SUPPORT
from pyasn1.codec.der import decoder as der_decoder
from datetime import datetime


# Evaluate Certificate Expiry Date
def eval_expiry_date(dateeval):
    expire_date = datetime.strptime(dateeval, "%Y%m%d%H%M%SZ")
    expire_in = expire_date - datetime.now()
    return expire_in


# Get SSl Certificate and Verify CN and SAN
def get_remote_certificate(host, port):
    hostx = host
    portx = port
    cert = ssl.get_server_certificate((str(hostx.rstrip()), portx))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    subjectaltnames = get_subj_alt_name(x509)
    common_name = x509.get_subject().commonName.decode()
    common_name_split = common_name.split('.')
    host_split = host.split('.')
    if common_name_split[1] == host_split[0]:
        log.info("CN Matched for Host %s" % host)
    else:
        log.error("CN not Matched for host %s" % host)
    datex = x509.get_notAfter()
    for i in subjectaltnames:
        if i == host:
            log.info ("SAN Matched for Host %s" % host)
    return hostx, datex


# Get SubjectAltName
def get_subj_alt_name(peer_cert):
    dns_name = []
    if not SUBJ_ALT_NAME_SUPPORT:
        return dns_name
    general_names = SubjectAltName()
    for i in range(peer_cert.get_extension_count()):
        ext = peer_cert.get_extension(i)
        ext_name = ext.get_short_name()
        if ext_name != 'subjectAltName':
            continue
        ext_dat = ext.get_data()
        decoded_dat = der_decoder.decode(ext_dat, asn1Spec=general_names)
        for name in decoded_dat:
            if not isinstance(name, SubjectAltName):
                continue
            for entry in range(len(name)):
                component = name.getComponentByPosition(entry)
                if component.getName() != 'dNSName':
                    continue
                dns_name.append(str(component.getComponent()))
    return dns_name


# Use Case Logic
def mainevaluation(url):
    ehost = url
    aname, bdate = get_remote_certificate(ehost, 443)
    expire_in = eval_expiry_date(bdate)
    if (expire_in.days < 40 and expire_in.days > 1):
        log.info("Certificate for host %s expire in %s day" %ehost %expire_in.days)
    elif expire_in.days < 1:
        log.error("Certificate for Host %s already expired" + str(aname))


# logging functionality
LOGFILE = 'sslmonitor.log'
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
logfile_handler = logging.handlers.RotatingFileHandler(LOGFILE, maxBytes=2097152, backupCount=3)  # 8MB
logfile_handler.setFormatter(logging.Formatter('%(asctime)s %(name)s: %(levelname)s: %(message)s'))
log.addHandler(logfile_handler)


# Read the Host File
def readhost(filename):
    entries = []
    with open(filename, mode='r') as f:
        lines = f.readlines()
        for i in lines:
            entry = i.rstrip("\n")
            entries.append(entry)
    return entries


if __name__  == '__main__':
    for j in readhost('host.txt'):
        mainevaluation(j)
