#!/usr/bin/env python
"""
  sftpsite-uploader daemon: starts thread triggered by rabbitMQ
"""
import os
import logging
from datetime import datetime
from threading import Thread
import ConfigParser
import paramiko
import pika


def callback(ch, method, properties, body):
    """ start sftp thread and ack rabbitMQ message """
    platform_rsync_pid, platform, dir_now_format, up_file = body.split(',')
    try:
        sftp_thread = Thread(target=sftpsite_thread, args=(
            platform_rsync_pid, platform, dir_now_format, up_file))
        sftp_thread.start()
    except Exception, e:
        thread_err = (
            "[{0}] SFTP: Something broke in the upload thread for platform {1} and file {2}: {3}".format(
                platform_rsync_pid, platform, up_file, e))
        logging.error(thread_err)
        notify_nagios(thread_err)

    ch.basic_ack(delivery_tag=method.delivery_tag)


def sftpsite_thread(platform_rsync_pid, platform, dir_now_format, up_file):
    """ upload file to sftpsite """
    logging.info(
        ("[{0}] SFTP: Started new upload thread for platform {1} and file {2}".format(
            platform_rsync_pid, platform, up_file)))
    remote_file = os.path.basename(up_file)
    config = ConfigParser.RawConfigParser()
    config.readfp(open('/etc/encryptonator/encryptonator.conf'))
    host = config.get('sftp', 'host')
    port = config.get('sftp', 'port')
    proxy_host = config.get('sftp', 'proxy_host')
    proxy_port = config.get('sftp', 'proxy_port')
    sftp_username = config.get(platform, 'sftp_username')
    platform_ssh_key = "/home/encryptonator/.ssh/{}".format(platform)

    # use the proxy server to connect to the sftpsite sftp server
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
        logging.info("[{0}] SFTP: Could not connect {1} to Sftp Site: {2}".format(
            platform_rsync_pid, platform, e))
        connected = False
        sftp.close()
        client.close()


    # upload file (if there is an sftp handler)
    if connected:
        try:
            logging.info("[{0}] SFTP: Putting {1} to remote location {2}".format(
                platform_rsync_pid,
                up_file,
                os.path.join(dir_now_format, remote_file)))
            sftp.put(up_file, os.path.join(dir_now_format, remote_file))
            logging.info(
                "[{0}] SFTP: Successfully uploaded {1} for platform {2}".format(
                    platform_rsync_pid, up_file, platform))
        except Exception, e:
            err = "[{0}] SFTP: Failed to upload {1} for platform {2}, {3}".format(
                platform_rsync_pid, up_file, platform, e)
            logging.error(err)
            notify_nagios(err)
        else:
            os.remove(up_file)
            logging.info("[{0}] SFTP: Removed {1} from /encrypt".format(
                platform_rsync_pid, os.path.basename(up_file)))
        finally:
            sftp.close()
            client.close()
    else:
        err = "[{0}] SFTP: Failed to upload {1} for platform {2}, {3}".format(
            platform_rsync_pid, up_file, platform, e)
        logging.error(err)
        notify_nagios(err)
        sftp.close()
        client.close()


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

    # encryptonator posts messages on the 'sftpsite' queue for each sftp transfer
    try:
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host='localhost'))
        channel = connection.channel()
        channel.queue_declare(queue='sftpsite', durable=True)
        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(callback, queue='sftpsite')
    except Exception, e:
        msg = "SFTP: Failed to create queue: {0}".format(e)
        logging.error(msg)
        notify_nagios(msg)
        os.sys.exit(1)

    logging.info("SFTP: Starting consuming from the sftpsite queue.")
    channel.start_consuming()
