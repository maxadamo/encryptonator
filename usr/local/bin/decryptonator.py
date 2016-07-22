#!/usr/bin/python
"""
  decrypts and downloads a file from Detron
"""
from optparse import OptionParser
import ConfigParser
import getpass
import os
import re
import struct
import subprocess
import socket
from Crypto.Cipher import AES
import gnupg
import paramiko


def get_detron_dirlist(platform):
    """ get file list from detron """
    config = ConfigParser.RawConfigParser()
    config.readfp(open('/etc/encryptonator/encryptonator.conf'))
    host = config.get('sftp', 'host')
    port = config.get('sftp', 'port')
    proxy_host = config.get('sftp', 'proxy_host')
    proxy_port = config.get('sftp', 'proxy_port')
    sftp_username = config.get(platform, 'sftp_username')
    platform_ssh_key = '/home/encryptonator/.ssh/{0}'.format(platform)

    proxy_command = '/usr/bin/connect -H {0}:{1} {2} {3}'.format(proxy_host, proxy_port, host, port)

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
            sock=sock,
            )
        sftp = client.open_sftp()
        dirlist = sftp.listdir('.')
        return dirlist
    except Exception, e:
        print "Failed to get listing from detron: {0}".format(e)
        quit(1)


def get_detron_file(sftp_file):
    """ Get file from detron """
    config = ConfigParser.RawConfigParser()
    config.readfp(open('/etc/encryptonator/encryptonator.conf'))
    host = config.get('sftp', 'host')
    port = config.get('sftp', 'port')
    proxy_host = config.get('sftp', 'proxy_host')
    proxy_port = config.get('sftp', 'proxy_port')
    sftp_username = config.get(platform, 'sftp_username')
    platform_ssh_key = "/home/encryptonator/.ssh/{0}".format(platform)

    proxy_command = '/usr/bin/connect -H {0}:{1} {2} {3}'.format(
        proxy_host, proxy_port, host, port)

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
            sock=sock,
            )
        sftp = client.open_sftp()
        sftp.get(os.path.basename(sftp_file), sftp_file)
    except Exception, e:
        print 'Failed to get file from detron: {0}'.format(e)
        quit(1)


def decrypt_file(encrypted_file, gpg_file):
    """ Decrypt file """
    pass_phrase = getpass.getpass(prompt='Please enter the passphrase: ')
    aes_file = os.path.join(
        os.path.dirname(gpg_file),
        os.path.basename(gpg_file).replace('.aes.gpg', '.aes')
        )
    gpg = gnupg.GPG(gnupghome='/home/encryptonator/.gnupg')
    with open(gpg_file, 'rb') as gpg_in_file:
        gpg.decrypt_file(gpg_in_file, passphrase=pass_phrase, output=aes_file)
    os.remove(gpg_file)
    with open(aes_file, 'rb') as aes_in_file:
        aes_key = aes_in_file.read()

    out_filename = os.path.join(
        os.path.dirname(encrypted_file),
        os.path.basename(encrypted_file).replace('.enc', '')
        )
    chunksize = 24*1024

    with open(encrypted_file, 'rb') as in_file:
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
    for remove_file in aes_file, encrypted_file:
        os.remove(remove_file)


if __name__ == "__main__":
    usage = "Usage: %prog -p platform"
    parser = OptionParser(usage)
    parser.add_option("-p", dest="platform",
                      help="Platform to restore a download and decrypt for.")
    (options, args) = parser.parse_args()

    if not options.platform:
        print "Please specify a platform"
        quit(1)
    else:
        platform = options.platform

    # check if the specified platform exists
    config = ConfigParser.RawConfigParser()
    config.readfp(open('/etc/encryptonator/encryptonator.conf'))
    platforms = config.sections()
    platforms.remove('sftp')

    if platform not in platforms:
        print "Unrecognized platform. Check /etc/encryptonator/encryptonator.conf for options."
        quit(1)

    # get file listing from detron and exclude md5 and gpg files
    filelist = []
    remove_list = []
    filelist = get_detron_dirlist(platform)
    md5_regex = re.compile('^.*\.(md5|gpg)$')
    for file_item in filelist:
        if md5_regex.match(file_item):
            remove_list.append(file_item)
    for remove_file in remove_list:
        filelist.remove(remove_file)
    filedict = dict(enumerate(sorted(filelist)))

    print 'Available backup files:'
    print "%5s - %s" % ('id', 'filename')
    for index, filename in filedict.items():
        print "%5i - %s" % (index, filename)

    print ''
    id_to_restore = int(raw_input('Please enter the id of the file to restore: '))

    restore_path = '/mnt/' + platform + '/decrypt/'
    restore_file = restore_path + filedict[id_to_restore]
    gpg_file = restore_file.replace('.enc', '.aes.gpg')

    for download_file in restore_file, gpg_file:
        get_detron_file(download_file)

    decrypt_file(restore_file, gpg_file)

    sftp_username = config.get(platform, 'sftp_username')
    host_name = socket.getfqdn()
    stripped_restore_file = os.path.basename(restore_file).replace('.enc', '')
    example_rsync_command = 'rsync -avx --progress -e \'ssh\' {0}_encryptonator@{1}::{2}_decrypt/{3} .'.format(sftp_username, host_name, platform, stripped_restore_file)
    print 'Restore completed to this rsync location:\n{0}_encryptonator@{1}::{2}_decrypt/{3}'.format(sftp_username, host_name, platform, stripped_restore_file)
    print '\nRun this command on the backup server of your platform to rsync the file:\n{0}'.format(example_rsync_command)
    print '\n\nNote that the file will automatically be removed from the system in 2 hours.'

    # setup an at command to remove the restored file 2 hours from now
    at_command = '/bin/echo /bin/rm {0} | /usr/bin/at now + 2 hours > /dev/null 2>&1'.format(restore_file.replace('.enc', ''))
    subprocess.call(at_command, shell=True)

    quit(0)
