# -*- encoding: utf-8 -*-
# requires a recent enough python with idna support in socket
# pyopenssl, cryptography and idna

from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna

from socket import socket
import time
import datetime
import smtplib
from datetime import date

from email.mime.text import MIMEText
from subprocess import Popen, PIPE
from email.mime.multipart import MIMEMultipart
import smtplib, ssl

def verify_cert(cert, hostname):
    # verify notAfter/notBefore, CA trusted, servername/sni/hostname
    cert.has_expired()
    # service_identity.pyopenssl.verify_hostname(client_ssl, hostname)
    # issuer

def get_certificate(hostname, port):
    hostname_idna = idna.encode(hostname)
    sock = socket()

    print('Connecting to » {hostname} « …'.format(hostname=hostname), end=' ')
    sock.connect((hostname, port))
    print('connected', sock.getpeername())

    ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE

    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.set_tlsext_host_name(hostname_idna)
    sock_ssl.do_handshake()
    cert = sock_ssl.get_peer_certificate()
    sock_ssl.close()
    return cert.to_cryptography()

def get_alt_names(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return None

def get_common_name(cert):
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None

def get_issuer(cert):
    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
       
        return names[0].value

    except x509.ExtensionNotFound:
        return None

def get_validate(cert):
    #try:
    cur_date = datetime.datetime.utcnow()
    expire_days = int((cert.not_valid_after - cur_date).days)
    msg = MIMEMultipart()
    
    if expire_days < 30:
        comm_nm = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        data = "expire in %s days" %expire_days
        marker = "\n\nVairam"
        # sender = ['vlakshumanasamy@stanfordhealthcare.org']
        # receivers = ['vlakshumanasamy@stanfordhealthcare.org']
        # msg['subject'] = "Certificate %s %s" %(comm_nm[0].value,data)
        # SUBJECT = "Certificate %s %s" %(comm_nm[0].value,data)
        cert = """\n\nCertificate name : %s """ % (comm_nm[0].value)
        sender_email = "vlakshumanasamy@stanfordhealthcare.org"
        receiver_email = "DL-HCL-MW-IIS@stanfordhealthcare.org"
        message = MIMEMultipart("alternative")
        message['subject'] = "Certificate %s %s" %(comm_nm[0].value,data)
        message["From"] = sender_email
        message["To"] = receiver_email
        body = "Hello,\t\n\nCertificate going to expired in %s days %s %s" % (expire_days,cert,marker)
        
        message.attach(MIMEText(body,'plain'))
        
        # message = "Certificate going to expired in 30 days"
        # msg = message.as_string()
        # smtpObj = smtplib.SMTP('smtp.stanfordmed.org')
        # smtpObj.sendmail(sender, receivers, msg)         
        # print ("Successfully sent email")
        #marker = "Vairam"

    #     body = """Certificate going to expired in %s""" % (expire_days)
    #     cert = """Certificate name %s""" % (comm_nm[0].value)
    #     # Define the main headers.
    #     # Define the message action
    #     part2 = """Content-Type: text/plain
    #     Content-Transfer-Encoding:8bit

    #     %s
    #     --%s
    #      """ % (body,cert)
    #     message_n = part2
        smtpObj = smtplib.SMTP('smtp.stanfordmed.org')
           
        smtpObj.sendmail(sender_email,receiver_email,message.as_string())
        
   
             #msg.as_string())       
        print ("Successfully sent email")
        return expire_days
        
    #else: 
    #     print ("Error: unable to send email")
        #print(expire_days)
    #except x509.ExtensionNotFound:
    #    return None


def print_basic_info(cert):
    print('\tcommonName:', get_common_name(cert))
    print('\tSAN:', get_alt_names(cert))
    print('\tissuer:', get_issuer(cert))
    print('\tnotBefore:', cert.not_valid_before)
    print('\tnotAfter: ', cert.not_valid_after)
    print('\tDifferent1:', get_validate(cert))
    print()

def check_it_out(hostname, port):
    cert = get_certificate(hostname, port)
    print_basic_info(cert)

if __name__ == '__main__':
    check_it_out('prism.stanfordhealthcare.org', 443)
    check_it_out('infor.stanfordmed.org', 443)
    check_it_out('96.47.48.243', 443)
    check_it_out('96.47.50.157', 443)