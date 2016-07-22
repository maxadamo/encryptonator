#!/usr/bin/python
""" Spans all users, based on the private key stored inside
    /home/encryptonator/.ssh/ and run df onto Sftp Site server
"""
from glob import glob
import subprocess as sp
import argparse
import socket
import os


def parse():
    """ pass arguments to the script """
    parser = argparse.ArgumentParser(description="check Sftp Site disk usage")
    parser.add_argument('-w', '--warn', help='Warning limit', default=80, type=int)
    parser.add_argument('-c', '--crit', help='Critical limit', default=95, type=int)
    return parser.parse_args()


def nagios_exit(state, msg):
    """ this was meant to run as nagios check but we are
        now using it to throw the output to a log file
    """
    # states = {'OK': 0, 'WARNING': 1, 'CRITICAL': 2, 'UNKNOWN': 3}
    # print '{0}: {1}'.format(state, msg)
    # os.sys.exit(states[state])
    msg_content = '{0}: {1}'.format(state, msg)
    with open('/home/encryptonator/sftpsite_space.log', 'w') as sftpsite_log:
        sftpsite_log.write(msg_content)
    os.sys.exit(0)


def loop_users(proxy, warn=80, crit=90, err_msg=''):
    """ spans all user and run df on sftpsite """
    home_dir = '/home/encryptonator'
    os.chdir('/home/encryptonator/.ssh')
    pubkeys = glob('*.pub')
    with open('/home/encryptonator/df', 'w') as df_file:
        df_file.write('df')
    df_file.close()
    if 'encryptonator.pub' in pubkeys:
        pubkeys.remove('encryptonator.pub')

    privkeys = [s.replace('.pub', '') for s in pubkeys]

    for privkey in privkeys:
        team_name = privkey.upper()
        sftp_cmd = "/usr/bin/sftp -b {0}/df -i {0}/.ssh/{1} -o ProxyCommand='/bin/nc -X connect -x {2}:3128 %h %p' {1}@88.211.136.242".format(home_dir, privkey, proxy)
        proc_sftp = sp.Popen(sftp_cmd, shell=True, stdout=sp.PIPE, stderr=sp.STDOUT)
        proc_out = proc_sftp.communicate()[0]
        retcode = proc_sftp.returncode
        if retcode is not 0:
            disk_usage = -1
            err_msg += 'CRITICAL: Team {} cannot connect to Sftp Site, '.format(team_name)
        else:
            proc_out = proc_out.split('\n')[-2]  # take last but one row
            disk_usage = int(proc_out.split()[-1].replace('%', ''))

        if disk_usage > crit:
            err_msg += 'CRITICAL: Team {0} is using {1}% of space, '.format(team_name, disk_usage)
        elif disk_usage > warn and disk_usage <= crit:
            err_msg += 'WARNING: Team {0} is using {1}% of space, '.format(team_name, disk_usage)

    return err_msg


if __name__ == "__main__":

    ARGS = parse()
    if 'ix5' in socket.getfqdn():
        squid = 'proxy001.ix5.ops.prod.st.ecg.so'
    elif 'esh' in socket.getfqdn():
        squid = 'proxy001.esh.ops.prod.st.ecg.so'

    status_msg = loop_users(squid, ARGS.warn, ARGS.crit)

    if status_msg:
        exit_code = 'ERROR'
    else:
        exit_code = 'OK'
        status_msg = 'disk usage is below limits'

    nagios_exit(exit_code, status_msg)
