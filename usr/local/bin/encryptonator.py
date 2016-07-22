#!/usr/bin/env python
"""
  encryptonator daemon: starts thread triggered by rabbitMQ
"""
import ConfigParser
from datetime import datetime
from time import sleep
import fnmatch
import hashlib
import logging
import socket
import os
import subprocess as sp
import struct
import shutil
from threading import Thread
from Crypto.Cipher import AES
import gnupg
import paramiko
import pika
import rsa


def encrypt(platform, platform_rsync_pid, platform_path, in_filename):
    """ encrypt file """
    logging.info('[{0}] ENC: Encrypting {1}'.format(
        platform_rsync_pid, os.path.basename(in_filename)))
    # upload a file to detron
    # the file name is prepended byt the date and time (hour and minute)
    now = datetime.now()
    now_format = now.strftime("%Y%m%d%H%M%S")

    filename = '{0}/encrypt/{1}_{2}'.format(platform_path, now_format,
                                            os.path.basename(in_filename))
    out_filename = filename.replace(platform_rsync_pid, 'enc')

    # check if we have enough space on detron for this file
    filesize = os.path.getsize(in_filename)
    check_detron = check_size(filesize, in_filename, platform)

    if check_detron:
        os.remove(in_filename)
    else:
        # create random aes key, encrypt it using gpg with a platform
        # specific rsa 2048 key and store it
        gpg = gnupg.GPG(gnupghome='/home/encryptonator/.gnupg')
        all_public_keys = gpg.list_keys()
        all_public_keys_names = []
        for public_key in all_public_keys:
            key_uid = public_key['uids'][0]
            all_public_keys_names.append(key_uid)
        if not any(public_key_name.startswith(platform) for public_key_name in all_public_keys_names):
            logging.info("[{0}] ENC: No rsa key found for platform {1} in gpg. Stopping encryption.".format(platform_rsync_pid, platform))
            return

        aes_key = str(rsa.randnum.read_random_bits(256))
        aes_key_file_name = filename.replace(platform_rsync_pid, 'aes')
        gpg_aes_key_file_name = '{}.gpg'.format(aes_key_file_name)
        # temporarily store the encrypted aes key
        with open(aes_key_file_name, 'wb') as aes_key_file:
            aes_key_file.write(aes_key)
        # encrypt aes key file. gpg recipient name must be equal to platform name
        with open(gpg_aes_key_file_name, 'wb') as gpg_file, open(aes_key_file_name, 'rb') as aes_file:
            gpg.encrypt_file(aes_file, recipients=platform,
                             output=gpg_aes_key_file_name)
        # remove the temporary aes file
        os.remove(aes_key_file_name)

        # create the md5sum of the enrypted aes key and store it
        gpg_aes_key_file_md5 = get_md5sum(gpg_aes_key_file_name)
        gpg_aes_file_md5 = '{}.md5'.format(gpg_aes_key_file_name)
        detron_md5_file_format = '{0}  {1}'.format(
            gpg_aes_key_file_md5, os.path.basename(gpg_aes_key_file_name))
        with open(gpg_aes_file_md5, 'wb') as md5_out:
            md5_out.write(detron_md5_file_format)
        logging.info("[{0}] ENC: Stored AES key in {1}".format(
            platform_rsync_pid, os.path.basename(gpg_aes_key_file_name)))

        # encrypt the input file using the generated aes key
        # taken from http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
        iv = rsa.randnum.read_random_bits(128)
        mode = AES.MODE_CBC
        encryptor = AES.new(aes_key, mode, iv)

        chunksize = 64*1024

        with open(in_filename, 'rb') as in_file, open(out_filename, 'wb') as out_file:
            out_file.write(struct.pack('<Q', filesize))
            out_file.write(iv)
            while True:
                chunk = in_file.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)
                out_file.write(encryptor.encrypt(chunk))

        # create the md5sum of the encrypted file and store it
        out_filename_md5 = get_md5sum(out_filename)
        out_file_md5 = '{}.md5'.format(out_filename)
        detron_md5_file_format = '{0}  {1}'.format(
            out_filename_md5, os.path.basename(out_filename))
        with open(out_file_md5, 'wb') as md5_out:
            md5_out.write(detron_md5_file_format)
        logging.info("[{0}] ENC: Finished encrypting {1}".format(
            platform_rsync_pid, os.path.basename(in_filename)))

        # we first upload the md5sum (as requeste by detron)
        # then we upload the gpg key and then we send the real file to MQ
        for item_file in gpg_aes_file_md5, out_file_md5, gpg_aes_key_file_name:
            upload_file(platform_rsync_pid, platform, item_file)
        upload_file(platform_rsync_pid, platform, out_filename, mq=True)


def upload_file(platform_rsync_pid, platform, up_file, mq=None):
    """ upload file to detron """
    remote_file = os.path.basename(up_file)
    now = datetime.now()
    dir_now_format = now.strftime("%Y%m%d")

    # get configuration from the encryptonator configuration
    config = ConfigParser.RawConfigParser()
    config.readfp(open('/etc/encryptonator/encryptonator.conf'))
    host = config.get('sftp', 'host')
    port = config.get('sftp', 'port')
    proxy_host = config.get('sftp', 'proxy_host')
    proxy_port = config.get('sftp', 'proxy_port')
    sftp_username = config.get(platform, 'sftp_username')
    platform_ssh_key = "/home/encryptonator/.ssh/{}".format(platform)

    # use the proxy server to connect to the detron sftp server
    proxy_command = '/usr/bin/connect -H {0}:{1} {2} {3}'.format(
        proxy_host, proxy_port, host, port)

    # create sftp handler
    connected = True
    try:
        ssh_key = paramiko.RSAKey.from_private_key_file(platform_ssh_key)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        sock = paramiko.ProxyCommand(proxy_command)
        client.connect(
            hostname=host,
            port=int(port),
            username=sftp_username,
            pkey=ssh_key,
            sock=sock
            )
        sftp = client.open_sftp()
    except Exception, e:
        logging.info("[{0}] ENC: Could not connect {1} to Detron: {2}".format(
            platform_rsync_pid, platform, e))
        sftp.close()
        client.close()
        connected = False

    # check if directory exists or create it (if there is an sftp handler)
    if connected:
        dir_now_path = os.path.join('/home', platform, dir_now_format)
        try:
            sftp.stat(dir_now_path)
        except Exception:
            logging.info("[{0}] ENC: creating {1})".format(
                platform_rsync_pid, dir_now_format))
            absent = True
        else:
            absent = False
        if absent:
            try:
                sftp.mkdir(dir_now_path, mode=0700)
                # we agreed with Detron to let incron assign permissions 700
                sftp.chmod(dir_now_path, 0700)
                sleep(3)
            except Exception, e:
                logging.error(
                    "[{0}] ENC: Failed creating directory {1} ({2})".format(
                        platform_rsync_pid, dir_now_format, e))
                connected = False
                sftp.close()
                client.close()

    # upload file or send message to MQ (if there is an sftp handler)
    if connected:
        if mq:
            sftp.close()
            client.close()
            message = '{0},{1},{2},{3}'.format(
                platform_rsync_pid, platform, dir_now_format, up_file)
            logging.info(
                '[{0}] ENC: Publishing message for platform {1} to upload to Detron {0}'.format(
                    platform_rsync_pid, platform))
            try:
                connection_det = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
                channel_det = connection_det.channel()
                channel_det.queue_declare(queue='detron', durable=True)
            except Exception, e:
                msg = '[rsync]: ERROR: Failed to create queue: {0}'.format(e)
                logging.error(msg)
            try:
                channel_det.basic_publish(exchange='',
                                          routing_key='detron',
                                          body=message,
                                          properties=pika.BasicProperties(
                                              delivery_mode=2,))
                connection_det.close()
            except Exception, e:
                msg_det = '[{0}] ENC: Failed to publish message for platform {1} to upload to Detron {0}: {2} '.format(platform_rsync_pid, platform, e)
                logging.error(msg_det)
        else:
            try:
                logging.info("[{0}] ENC: Putting {1} to remote location {2}".format(
                    platform_rsync_pid, up_file,
                    os.path.join(dir_now_format, remote_file)))
                sftp.put(up_file, os.path.join(dir_now_format, remote_file))
                logging.info(
                    "[{0}] ENC: Successfully uploaded {1} for platform {2}".format(
                        platform_rsync_pid, up_file, platform))
            except Exception, e:
                err = "[{0}] ENC: Failed to upload {1} for platform {2}, {3}".format(
                    platform_rsync_pid, up_file, platform, e)
                logging.error(err)
                notify_nagios(err)
            else:
                os.remove(up_file)
                logging.info("[{0}] ENC: Removed {1} from /encrypt".format(
                    platform_rsync_pid, os.path.basename(up_file)))
            finally:
                sftp.close()
                client.close()
    else:
        err = "[{0}] ENC: Failed to upload {1} for platform {2}, {3}".format(
            platform_rsync_pid, up_file, platform, e)
        logging.error(err)
        notify_nagios(err)
        sftp.close()
        client.close()


def get_md5sum(md5_file):
    """ return the md5 of a file """
    md5_hash = hashlib.md5()
    with open(md5_file, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()


def encryption_thread(platform, platform_rsync_pid, platform_path, file_path):
    """ move the file to the in_progress directory """
    file_path_in_progress = os.path.join(platform_path, 'in_progress',
                                         os.path.basename(file_path))
    shutil.move(file_path, file_path_in_progress)
    logging.info("[{0}] ENC: Moved {1} to /in_progress".format(
        platform_rsync_pid, os.path.basename(file_path)))
    # start the file encryption
    encrypt(platform, platform_rsync_pid, platform_path, file_path_in_progress)
    # remove the file from the in_progress directory
    os.remove(file_path_in_progress)
    logging.info("[{0}] ENC: Removed {1} from /in_progress".format(
        platform_rsync_pid, os.path.basename(file_path_in_progress)))


def callback(ch, method, properties, body):
    """ start thread for each MQ message """
    # mq message is split
    platform, platform_rsync_pid, platform_path = body.split(',')
    # platform path reported by rsync in /mnt/platformname/incoming. Fixed here
    platform_path = platform_path.replace('/incoming', '')
    logging.info("[{0}] ENC: Received message for platform {1}".format(
        platform_rsync_pid, platform))

    # new files are stored in the /mnt/platformname/queued directory.
    # Files have the pid of their rsync program appended
    platform_path_queued = os.path.join(platform_path, 'queued')
    file_match_pattern = '*.{}'.format(platform_rsync_pid)

    # for each queued file start an encryption thread
    for queued_file in os.listdir(platform_path_queued):
        if fnmatch.fnmatch(queued_file, file_match_pattern):
            file_path = os.path.join(platform_path_queued, queued_file)
            logging.info("[{0}] ENC: Starting thread for file {1}".format(
                platform_rsync_pid, queued_file))
            try:
                enc_thread = Thread(target=encryption_thread, args=(
                    platform, platform_rsync_pid, platform_path, file_path))
                enc_thread.start()
            except Exception, e:
                queue_err = ("[{0}] ENC: Something broke running an encryption thread for platform {1} and file {2}: {3}".format(platform_rsync_pid, platform, file_path, e))
                logging.error(queue_err)
                notify_nagios(queue_err)

    ch.basic_ack(delivery_tag=method.delivery_tag)


def check_size(file_size, file_name, platform):
    """ compare file size with available size on detron """
    ssh_key = '/home/encryptonator/.ssh/{}'.format(platform)
    df_batch = '/home/encryptonator/df'
    if 'ix5' in socket.getfqdn():
        squid = 'proxy001.ix5.ops.prod.st.ecg.so'
    elif 'esh' in socket.getfqdn():
        squid = 'proxy001.esh.ops.prod.st.ecg.so'
    with open(df_batch, 'w') as df_file:
        df_file.write('df')
    df_file.close()
    sftp_cmd = "/usr/bin/sftp -b {0} -i {1} -o ProxyCommand='/bin/nc -X connect -x {2}:3128 %h %p' {3}@88.211.136.242".format(df_batch, ssh_key, squid, platform)
    proc_sftp = sp.Popen(sftp_cmd, shell=True, stdout=sp.PIPE, stderr=sp.STDOUT)
    proc_out = proc_sftp.communicate()[0]
    retcode = proc_sftp.returncode
    if retcode is not 0:
        notify_nagios('Team {} cannot connect to Detron'.format(platform))
        return 'noconnection'
    else:
        proc_out = proc_out.split('\n')[-2]  # take last but one row
        disk_avail = int(proc_out.split()[-3].replace('%', ''))

        if file_size >= disk_avail:
            mb_file_size = file_size / 1024
            mb_disk_avail = disk_avail / 1024
            notify_nagios('The file size to backup ({0} MB) exceeds the space available ({1} MB) on Detron'.format(mb_file_size, mb_disk_avail))
            notify_nagios('The file {} will be removed'.format(file_name))
            return 'nospace'


def notify_nagios(nagios_msg):
    """ write a message that will be read by nagios """
    timestamp = datetime.now()
    nagios_msg += '\n\n Check /var/log/encryptonator.log for the full log: '
    with open('/var/log/encryptonator_nagios.log', 'a') as nagios:
        nagios.write("ERROR - {0} - {1}".format(timestamp, nagios_msg))

    nagios.close()


if __name__ == "__main__":
    log_file = '/var/log/encryptonator/encryptonator.log'
    log_format = '%(asctime)-15s %(levelname)s %(message)s'
    logging.basicConfig(
        filename=log_file,
        level=logging.DEBUG,
        format=log_format)

    logging.getLogger("paramiko").setLevel(logging.INFO)
    logging.getLogger("gnupg").setLevel(logging.INFO)

    pika_logger = logging.getLogger('pika')
    pika_logger.setLevel(logging.CRITICAL)

    # ack_new_file posts messages on the 'encryptonator' queue for each new
    # rsync operation
    # an rsync operation might include multiple files
    # the mq message contains the platform name, rsync_pid and platform path
    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
        channel = connection.channel()
        channel.queue_declare(queue='encryptonator', durable=True)
        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(callback, queue='encryptonator')
    except Exception, e:
        msg = "ENC: Failed to create queue: {0}".format(e)
        logging.error(msg)
        notify_nagios(msg)
        os.sys.exit(1)

    logging.info("ENC: Starting consuming from the encryptonator queue.")
    channel.start_consuming()
