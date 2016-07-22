#!/usr/bin/env python
"""
  decrypts and downloads a file from Detron
"""
import os
import re
import random
import string
import struct
import logging
import subprocess
import socket
import argparse
import smtplib
import ConfigParser
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import gnupg
import paramiko
from Crypto.Cipher import AES


def parse():
    """ pass arguments to the script """
    parser = argparse.ArgumentParser(description="retrieve and decrypt files from detron")
    parser.add_argument('-p', '--platform', help='Platform name', required=True)
    parser.add_argument('-f', '--file', help='File name to restore', required=True)
    parser.add_argument('-e', '--email', help='E-mail to send a job notification', required=True)

    return parser.parse_args()


def get_detron_file(sftp_file, local_file, recipient, subject, platform):
    """ Get file from detron """
    config_ssh = ConfigParser.RawConfigParser()
    config_ssh.readfp(open('/etc/encryptonator/encryptonator.conf'))
    host = config_ssh.get('sftp', 'host')
    port = config_ssh.get('sftp', 'port')
    proxy_host = config_ssh.get('sftp', 'proxy_host')
    proxy_port = config_ssh.get('sftp', 'proxy_port')
    sftp_user = config_ssh.get(platform, 'sftp_username')
    platform_ssh_key = "/home/encryptonator/.ssh/{0}".format(platform)
    proxy_command = '/usr/bin/connect -H {0}:{1} {2} {3}'.format(proxy_host, proxy_port, host, port)

    try:
        ssh_key = paramiko.RSAKey.from_private_key_file(platform_ssh_key)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        sock = paramiko.ProxyCommand(proxy_command)
        client.connect(
            hostname=host,
            port=int(port),
            username=sftp_user,
            pkey=ssh_key,
            sock=sock)
        sftp = client.open_sftp()
        sftp.get(sftp_file, local_file)
        logging.info('OK: got file: {0}'.format(sftp_file))
    except Exception, e:
        sftp.close()
        logging.info('ERR: Failed to get file: {0} ({1})'.format(sftp_file, e))
        send_mail('Failed to get file: {0}'.format(e), recipient, subject)
    finally:
        sftp.close()


def decrypt_file(enc_file, gpgfile, passphrase, recipient, subject):
    """ Decrypt file """
    aes_file = re.sub(r'.aes.gpg$', '.aes', gpgfile)
    gpg = gnupg.GPG(gnupghome='/home/encryptonator/.gnupg')
    # decrypt gpg file
    with open(gpgfile, 'rb') as gpg_in_file:
        gpg.decrypt_file(gpg_in_file, passphrase=passphrase, output=aes_file)
    os.remove(gpgfile)
    # check if the gpg decrypted file was created
    if not os.path.exists(aes_file):
        try:
            os.remove(enc_file)
        except OSError:
            pass
        finally:
            logging.info(
                'ERR: Failed to decrypt GPG file {}: wrong passphrase?'.format(
                    gpgfile))
            send_mail(
                'Failed to decrypt GPG file {}: wrong passphrase?'.format(
                    gpgfile), recipient, subject)
    # read aes key file
    with open(aes_file, 'rb') as aes_in_file:
        aes_key = aes_in_file.read()

    out_filename = re.sub(r'.enc$', '', enc_file)
    chunksize = 24*1024

    with open(enc_file, 'rb') as in_file:
        origsize = struct.unpack('<Q', in_file.read(struct.calcsize('Q')))[0]
        iv = in_file.read(16)
        decryptor = AES.new(aes_key, AES.MODE_CBC, iv)
        with open(out_filename, 'wb') as out_file:
            while True:
                chunk = in_file.read(chunksize)
                if len(chunk) == 0:
                    break
                out_file.write(decryptor.decrypt(chunk))
            out_file.truncate(origsize)
    for remove_file in aes_file, enc_file:
        os.remove(remove_file)


def send_mail(text_body, mail_recipient, mail_subject, html_body=None):
    """ send notification e-mail """
    mail_relay = '127.0.0.1'
    fqdn = socket.getfqdn()
    mail_sender = '"Encryptonator" <encryptonator@{0}>'.format(fqdn)

    if html_body:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = mail_subject
        msg['From'] = mail_sender
        msg['To'] = ', '.join([mail_recipient])
        part1 = MIMEText(text_body, 'plain')
        part2 = MIMEText(html_body, 'html')
        msg.attach(part1)
        msg.attach(part2)
    else:
        msg = MIMEText(text_body)
        msg['Subject'] = mail_subject
        msg['From'] = mail_sender
        msg['To'] = ', '.join([mail_recipient])

    s = smtplib.SMTP(mail_relay)
    s.sendmail(mail_sender, mail_recipient, msg.as_string())
    s.quit()
    quit()


def unpredictable_url(source_file, url_email, url_subject):
    """ create a directory with an unpredictable name
        and put a synlink inside
    """
    vol_dir = '/etc/encryptonator/volatile'
    rnd_str = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(40))
    rnd_dir = os.path.join(vol_dir, rnd_str)
    try:
        os.mkdir(rnd_dir)
    except Exception, e:
        logging.info('ERR: Failed to create {0}: {1}'.format(rnd_dir, e))
        send_mail('Failed to create {0}: {1}'.format(rnd_dir, e), url_email, url_subject)
    dest_file = os.path.join(rnd_dir, os.path.basename(source_file))
    try:
        os.symlink(source_file, dest_file)
    except Exception, e:
        logging.info('ERR: Failed to symlink from {0} to {1}: {2}'.format(source_file, dest_file, e))
        send_mail(
            'Failed to symlink from {0} to {1}: {2}'.format(
                source_file, dest_file, e), url_email, url_subject)
    return rnd_dir


if __name__ == "__main__":

    log_file = '/var/log/encryptonator/decryptonator.log'
    log_format = '%(asctime)-15s %(levelname)s %(message)s'
    logging.basicConfig(filename=log_file, level=logging.DEBUG, format=log_format)

    logging.getLogger("paramiko").setLevel(logging.INFO)
    logging.getLogger("gnupg").setLevel(logging.INFO)

    ARGS = parse()
    SUBJ = "Encryptonator: job notification for file {0}".format(ARGS.file)

    try:
        restore_pass_phrase = os.environ['PASSPHRASE']
    except KeyError, e:
        logging.info('Error: ENV variable PASSPHRASE not set')
        send_mail('Error: ENV variable PASSPHRASE not set', ARGS.email, SUBJ)

    # check if the specified platform exists
    config = ConfigParser.RawConfigParser()
    config.readfp(open('/etc/encryptonator/encryptonator.conf'))
    platforms = config.sections()
    platforms.remove('sftp')

    if ARGS.platform not in platforms:
        logging.info('{0} is an unrecognized platform'.format(ARGS.platform))
        send_mail(
            "{0} is an unrecognized platform".format(ARGS.platform),
            ARGS.email, SUBJ)

    remote_path = os.path.dirname(ARGS.file)
    restore_path = os.path.join('/mnt', ARGS.platform, 'decrypt')
    gpg_file = re.sub(r'.enc$', '.aes.gpg', ARGS.file)
    restore_gpg_file = os.path.join(restore_path, os.path.basename(gpg_file))
    restore_file = os.path.join(restore_path, os.path.basename(ARGS.file))

    for download_file in restore_file, gpg_file:
        get_detron_file(
            os.path.join(remote_path, os.path.basename(download_file)),
            os.path.join(restore_path, os.path.basename(download_file)),
            ARGS.email, SUBJ, ARGS.platform)

    try:
        decrypt_file(
            restore_file, restore_gpg_file,
            restore_pass_phrase, ARGS.email, SUBJ)
    except Exception, e:
        logging.info('Error while decrypting: {0}'.format(e))
        send_mail('Error while decrypting: {0}'.format(e), ARGS.email, SUBJ)

    # setup an at command to remove the restored file 2 hours from now
    restored_fpath = re.sub(r'.enc$', '', restore_file)
    if not os.path.exists(restored_fpath):
        line_1 = 'Something went wrong decrypting {0}'.format(restore_file)
        line_2 = 'Please ask Shared Technologies Team to investigate'
        logging.info('{0}\n{1}'.format(line_1, line_2))
        send_mail('{0}\n{1}'.format(line_1, line_2), ARGS.email, SUBJ)
    del os.environ['PASSPHRASE']
    random_dir = unpredictable_url(restored_fpath, ARGS.email, SUBJ)
    random_base_dir = os.path.basename(random_dir)
    at_command = '/bin/echo /bin/rm -rf {0} {1} | /usr/bin/at now + 4 hours > /dev/null 2>&1'.format(restored_fpath, random_dir)
    subprocess.call(at_command, shell=True)

    # everything went fine: let's send the notification
    sftp_username = config.get(ARGS.platform, 'sftp_username')
    restored_fname = os.path.basename(restored_fpath)
    rsync_cmd_html = 'rsync -avx --progress -e \'ssh -i &#60;YOUR_SSH_KEY_ID_HERE&#62;\' <a name="fake">{0}_encryptonator@encryptonator.ecg.so</a>::{1}_decrypt/{2} &#60;/YOUR/RESTORE/PATH/HERE/&#62;'.format(sftp_username, ARGS.platform, restored_fname)
    rsync_cmd_text = 'rsync -avx --progress -e \'ssh -i <YOUR_SSH_KEY_ID_HERE>\' {0}_encryptonator@encryptonator.ecg.so::{1}_decrypt/{2} </YOUR/RESTORE/PATH/HERE/>'.format(sftp_username, ARGS.platform, restored_fname)

    text = """Restore completed!
You can use rsync from your server:
{0}
or use the link: https://encryptonator.ecg.so/volatile/{1}/{2}

Note that the file will automatically be removed from the system in 4 hours.
    """.format(rsync_cmd_text, random_base_dir, restored_fname)

    html = """
        <html>
          <head></head>
            <body>
              <p>
                <span style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: left; font-size: 14px; color: #151515">
                  <b>Restore completed!</b><br>
                  <br><br>
                  You can use rsync from your server:<br>
                </span>
                  <pre>{0}</pre>
                <span style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: left; font-size: 14px; color: #151515">
                  or use this temporary random <a href="https://encryptonator.ecg.so/volatile/{1}/{2}">Link</a><br>
                  <br><br>
                  Note that the file will automatically be removed from the system in 4 hours.<br>
                </span>
              </p>
            </body>
          </html>""".format(rsync_cmd_html, random_base_dir, restored_fname)

    logging.info('File decrypted. Email sent to {}'.format(ARGS.email))
    send_mail(text, ARGS.email, SUBJ, html)
