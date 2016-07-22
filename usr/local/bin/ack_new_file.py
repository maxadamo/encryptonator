#!/usr/bin/env python
""" This script runs as post-xfer exec of rsyncd. It:
      1. moves new files to the ${platform_path}/queued folder
      2. sends a message to the encryptonator rabbit mq queue
"""
import fnmatch
import logging
import os
import shutil
import pika


def loghandler(log_message, error=None, sysexit=None):
    """ handle logging """
    if error:
        logging.error(log_message)
        exit_status = 1
    else:
        logging.info(log_message)
        exit_status = 0
    if sysexit:
        os.sys.exit(exit_status)


if __name__ == "__main__":

    log_file = '/var/log/encryptonator/encryptonator.log'
    log_format = '%(asctime)-15s %(levelname)s %(message)s'
    logging.basicConfig(filename=log_file, level=logging.DEBUG, format=log_format)

    pika_logger = logging.getLogger('pika')
    pika_logger.setLevel(logging.CRITICAL)

    platform = os.environ['RSYNC_MODULE_NAME']
    platform_path = os.environ['RSYNC_MODULE_PATH']
    platform_rsync_pid = os.environ['RSYNC_PID']
    rsync_exit_status = int(os.environ['RSYNC_EXIT_STATUS'])
    platform_path_up = os.path.dirname(platform_path)
    message = '{0},{1},{2}'.format(platform, platform_rsync_pid, platform_path)

    # check if it's a download instead of upload
    if '_decrypt' in platform:
        platform = platform.replace('_decrypt', '')
        msg = '[rsync] ANF: Platform {} is downloading a file'.format(platform)
        loghandler(msg, sysexit=True)

    # check rsync exit status
    if rsync_exit_status > 0:
        msg = '[{0}] ANF: ERROR: rsync exited with status {1} on platform {2} with rsync id {0}'.format(platform_rsync_pid, rsync_exit_status, platform)
        loghandler(msg, error=True, sysexit=True)

    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        channel = connection.channel()
        channel.queue_declare(queue='encryptonator', durable=True)
    except Exception, e:
        msg = '[rsync]: ERROR: Failed to create queue: {0}'.format(e)
        loghandler(msg, error=True, sysexit=True)

    try:
        for (dirpath, dirnames, filenames) in os.walk(platform_path):
            break
        for file_item in filenames:
            # make sure to not move the rsync .lock file
            if not fnmatch.fnmatch(file_item, '.*'):
                msg = '[{0}] ANF: Moving file {1} of platform {2} to /queued'.format(platform_rsync_pid, file_item, platform)
                loghandler(msg)
                file_path = os.path.join(platform_path, file_item)
                file_path_queued = '{0}/queued/{1}.{2}'.format(platform_path_up, file_item, platform_rsync_pid)
                shutil.move(file_path, file_path_queued)
    except Exception, e:
        msg = '[{0}] ANF: ERROR: Failed to move file {1} of platform {2} to /queued: {3}'.format(platform_rsync_pid, file_item, platform, e)
        loghandler(msg, error=True, sysexit=True)

    try:
        msg = '[{0}] ANF: Publishing message for platform {1} with rsync id {0}'.format(platform_rsync_pid, platform)
        loghandler(msg)
        channel.basic_publish(exchange='',
                              routing_key='encryptonator',
                              body=message,
                              properties=pika.BasicProperties(delivery_mode=2,))
        connection.close()
    except Exception, e:
        msg = '[{0}] ANF: ERROR: Failed to publish message for platform {1} with rsync id {0}: {2} '.format(platform_rsync_pid, platform, e)
        loghandler(msg, error=True, sysexit=True)
