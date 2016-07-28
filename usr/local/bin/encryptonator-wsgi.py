#!/usr/bin/env python
""" starts CherryPy web server
      features:
        - span groups on ldap and grant access to specific platform
        - list files on the remote Sftp site for the chosen platform
        - browse remote directories on the remote Sftp site
        - download a specific file from the remote Sftp site
        - decrypt the file
        - send job notification thru email
        - serve the file over http
        - allows user to reset platform GPG passphrase
    author: "Massimiliano Adamo<madamo@ebay.com>"
"""
from __future__ import division
from stat import S_ISDIR
import ConfigParser
import subprocess as sp
import argparse
import os
import re
import ldap
import gnupg
import paramiko
import cherrypy
from cherrypy.process.plugins import Daemonizer, PIDFile


def parse():
    """ pass arguments to the script """
    ssl_dir = '/etc/encryptonator/ssl/'
    parser = argparse.ArgumentParser(description="My server daemon")
    parser.add_argument('-d', '--daemon', help='Run the server daemon using traditional double fork', action='store_true')
    parser.add_argument('-a', '--bind-address', help='Network interface to bind to', default='127.0.0.1')
    parser.add_argument('-p', '--port', help='Port to bind to', default=4443, type=int)
    parser.add_argument('-c', '--ssl-cert', help='Fulle path to SSL certificate', default=ssl_dir + 'certs/wildcard.ecg.so.crt')
    parser.add_argument('-k', '--ssl-key', help='Fulle path to SSL key file', default=ssl_dir + 'private/wildcard.ecg.so.key')
    parser.add_argument('--pidfile', help='process id file', type=str)

    return parser.parse_args()


class Root(object):
    """ Root class: serve index """
    @cherrypy.expose
    def index(self):
        """ Serve index page """
        if 'count' not in cherrypy.session:
            cherrypy.session['count'] = 0
        cherrypy.session['count'] += 1

        username = cherrypy.request.headers.get("ldapuser")

        try:
            platform_group
        except NameError:
            platform_group = check_ldap_group(username)
            config = ConfigParser.RawConfigParser()
            config.readfp(open('/etc/encryptonator/encryptonator.conf'))
            platforms = config.sections()

            if not platform_group:
                return ops_page
            else:
                platform_groups = set(platforms) & set(platform_group)
                if not platform_groups:
                    return ops_page
                else:
                    platform_groups = sorted(platform_groups)
                    platform_set = ['<option value="' + s + '">' + s + '</option>' for s in platform_groups]
                    joined_platform_set = '\n'.join(platform_set)
                    platforms_page = """{0}
                          <body>
                            <table align="center" width="100%" border="0" class="Table" id="table1">
                              <tr>
                                <div  style="text-align: center;">
                                <td bgcolor="#282828" colspan="1" width="100%" style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: center; font-size: 36px; color: #697476">
                                  <br>Encryptonator (self-service page)<br></br>
                                </td>
                              </tr>
                              <tr>
                                <div  style="text-align: center;">
                                <td colspan="1" width="100%" height="30" style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: center; font-size: 18px; color: #282828">
                                  <br>Choose your platform:</br>
                                </td>
                              </tr>
                              <tr>
                                <td colspan="1" width="100%" height="30" style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: center; font-size: 14px; color: #282828">
                                  <form  name="Choose_Team">
                                    <div  style="text-align: center;"><br>
                                      <select required  name="example" size="1">
                                        {1}
                                      </select>
                                    </div><br>
                                      <script  type="text/javascript">
                                        <!--
                                          function go(){{
                                          location=document.Choose_Team.example.
                                          options[document.Choose_Team.example.selectedIndex].value
                                          }}
                                        //-->
                                      </script>
                                    <div  style="text-align: center;"><input name="test" value="Go to platform!" onclick="go()" type="button"></div>
                                  </form>
                                </td>
                              </tr>
                            </table>
                          </body>
                        </html>""".format(html_head, joined_platform_set)
                    return platforms_page


class App(object):
    """ App class: serves pages """
    def __init__(self, platform, directory_level=None):
        self.platform = os.path.basename(platform)
        self.directory_level = directory_level

    @cherrypy.expose
    def index(self, platform=None, directory_level=None):
        """ Serve platform index page """
        if 'count' not in cherrypy.session:
            cherrypy.session['count'] = 0
        cherrypy.session['count'] += 1

        username = cherrypy.request.headers.get("ldapuser")

        try:
            platform_group
        except NameError:
            platform_group = check_ldap_group(username)
            config = ConfigParser.RawConfigParser()
            config.readfp(open('/etc/encryptonator/encryptonator.conf'))
            platforms = config.sections()

            if not platform_group:
                return ops_page
            else:
                all_groups = set([self.platform]) & set(platform_group)
                if not all_groups:
                    return ops_page

        return get_sftpsite_dirlist(self.platform, self.directory_level)

    @cherrypy.expose
    def get_and_decrypt(self, myfile='filename', sftp_path=None):
        """ runs the specified command """
        # the user must belong to one of the XX-encryptonator groups
        # and its name should not end with -apiaccess
        logged_user = cherrypy.request.headers.get("ldapuser")
        platform_group = check_ldap_group(logged_user)
        all_groups = set([self.platform]) & set(platform_group)
        if str.endswith(logged_user, '-apiaccess') or not all_groups:
            return ops_page

        email_tip = check_ldap_email(logged_user)
        name_of_file = re.sub(r'^.*\t ', '', myfile)
        kind_of_file = re.sub(r'\].*', '', myfile).replace('[', '')
        if not sftp_path:
            sftp_path = os.path.join('/home', self.platform)
        if kind_of_file != 'file':
            if name_of_file == 'Upper Directory':
                my_dir = os.path.dirname(sftp_path)
                print my_dir
            elif name_of_file == 'Home Directory':
                my_dir = os.path.join('/home', self.platform)
            else:
                my_dir = os.path.join(sftp_path, name_of_file)
            return get_sftpsite_dirlist(self.platform, my_dir)
        else:
            full_name = os.path.join(sftp_path, name_of_file)
            stripped_name = '/'.join(full_name.split('/')[-2:])
            html_page = """{0}
                  <body>
                    <table width="100%" border="0" class="Table" id="table1">
                      <tr>
                        <div  style="text-align: center;">
                        <td bgcolor="#282828" colspan="1" width="100%" height="30" style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: center; font-size: 20px; color: #697476">
                        <br><br>You have chosen the file: {1}<br><br><br></br>
                        </td>
                      </tr>
                    </table>
                    <table align="center" width="1024" border="0" class="Table" id="table1">
                      <form method="POST" action="start_processing">
                        <tr>
                          <td colspan="1" width="300" style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; font-size: 14px; color: #282828">
                          <div class="title">Platform name</div></td>
                          <td colspan="1" height="25" style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; font-size: 14px; color: #282828">
                          <input type="hidden" name="platform" value="{2}">
                          <div class="title">{2}</div></td>
                        </tr>
                        <tr>
                          <td colspan="1" width="300"  style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; font-size: 14px; color: #282828">
                          <div class="title">File name</div></td>
                          <td colspan="1" height="25" style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; font-size: 14px; color: #282828">
                          <input type="hidden" name="name_of_file" value="{3}">
                          <div class="title">{3}</div></td>
                        </tr>
                        <tr>
                          <td colspan="1" width="300" style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; font-size: 14px; color: #282828">
                          <div class="title">E-Mail (to receive a job notification)</div></td>
                          <td colspan="1" height="25"><input type="text" name="mymail" value="{4}" required /> <br />
                        </tr>
                        <tr>
                          <td colspan="1" width="300"style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; font-size: 14px; color: #282828">
                          <div class="title">Passphrase (to decrypt the AES public key)</div></td>
                          <td colspan="1" height="25"><input type="password" name="mypass" required /> <br />
                        </tr>
                        <tr>
                          <td colspan="1" width="300"style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; font-size: 14px; color: #282828">
                          <a href="/{2}/">Cancel (Go back)</a>
                          <td colspan="2" style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; font-size: 14px; color: #282828">
                          <div class="title"><br><button type="submit">Get the file!</button></td>
                        </tr>
                      </form>
                    </table>
                  </body>
                </html>""".format(html_head, name_of_file, self.platform,
                                  stripped_name, email_tip)
            return html_page

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def api(self, my_path='filename'):
        """ runs the specified command """
        my_dir = os.path.join('/home', self.platform, my_path)
        return get_sftpsite_json(self.platform, my_dir)


    @cherrypy.expose
    def start_processing(self, platform, name_of_file, mymail, mypass):
        """ get file list from the remote sftp site """
        devnull = open(os.devnull, 'w')
        decrypt_cmd = 'export PASSPHRASE={0}; /usr/local/bin/decryptonator-wsgi.py -f {1} -p {2} -e {3} &'.format(mypass, name_of_file, self.platform, mymail)
        sp.Popen(decrypt_cmd, shell=True, stdout=devnull, stderr=sp.STDOUT)
        html_page = """{0}
              <body>
                <span style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: left; font-size: 36px; color: #4F4F4F">
                  <p>Job submitted!</p> </span>
                <span style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: left; font-size: 18px; color: #4F4F4F">
                  <p>The file {1} will be retrieved and an e-mail will be sent to {2} upon completion.</p>
                </span>
                <span style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: left; font-size: 14px; color: #FFFFFF">
                  <p><a href="/{3}/">Go back and submit a new job</a></p>
                </span>
                </br></br>
              </body>
            </html>""".format(html_head, name_of_file, mymail, self.platform)
        return html_page

    @cherrypy.expose
    def reset_passphrase(self, platform):
        """ reset passphrase page """
        # the user must belong to one of the XX-encryptonator groups
        # and its name should not end with -apiaccess
        logged_user = cherrypy.request.headers.get("ldapuser")
        platform_group = check_ldap_group(logged_user)
        all_groups = set([self.platform]) & set(platform_group)
        if str.endswith(logged_user, '-apiaccess') or not all_groups:
            return ops_page

        PLATFORM = platform.upper()
        years_set = \
            ['<option value="{0}">{0}</option>'.format(s) for s in range(1, 2)]
        joined_years_set = '\n'.join(years_set)
        html_page = """{0}
              <body>
                <table width="100%" border="0" class="Table" id="table1">
                  <tr>
                    <div  style="text-align: center;">
                    <td bgcolor="#282828" colspan="1" width="100%" height="30" style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: center; font-size: 20px; color: #697476">
                    <br><br>Passphrase reset tool (platform: {2})<br><br><br></br>
                    </td>
                  </tr>
                </table>
                <br>
                <table align="center" width="1024" border="0" class="Table" id="table1">
                    <tr>
                      <td colspan="1" width="50" valign="middle" style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: left; font-size: 14px; color: #282828">
                        <div class="title" style="font-size: 16px"><img src="/alert_48.png" alt="Alert">
                      </td>
                      <td colspan="1" style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: left; font-size: 14px; color: #282828">
                        <div class="title" style="font-size: 16px"><b>warning</b>: in order to restore older backups you'll need to use your old passphrase.</div>
                        <div class="title">In such case you need to:</div>
                        <div class="title"> - access this tool again</div>
                        <div class="title"> - temporarily revert to your old passphrase</div>
                      </td>
                    </tr>
                </table>
                <br><br>
                <table align="center" width="1024" border="0" class="Table" id="table1">
                  <form method="POST" action="change_pass">
                    <tr>
                      <td colspan="1" width="300" style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; font-size: 14px; color: #282828">
                      <div class="title">Platform name</div></td>
                      <td colspan="1" height="25" style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; font-size: 14px; color: #282828">
                      <input type="hidden" name="platform" value="{1}">
                      <div class="title">{2}</div></td>
                    </tr>
                    <tr>
                      <td colspan="1" width="300"style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; font-size: 14px; color: #282828">
                      <div class="title">Expiration from now (years number)</div></td>
                      <td>
                      <form name="years">
                        <select required name="years" size="1">
                          {3}
                        </select>
                      </td>
                    </tr>
                    <tr>
                      <td colspan="1" width="300"style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; font-size: 14px; color: #282828">
                      <div class="title">Old Passphrase</div></td>
                      <td colspan="1" height="25"><input type="password" pattern=".{{40,}}"  required title="40 characters minimum" size="35" name="oldsecret" required /> <br />
                    </tr>
                    <tr>
                      <td colspan="1" width="300"style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; font-size: 14px; color: #282828">
                      <div class="title">New Passphrase (40-charachters minum)</div></td>
                      <td colspan="1" height="25"><input type="password" pattern=".{{40,}}"  required title="40 characters minimum" size="35" name="newsecret" required /> <br />
                    </tr>
                    <tr>
                      <td colspan="1" width="300"style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; font-size: 14px; color: #282828">
                      <div class="title">New Passphrase (verification)</div></td>
                      <td colspan="1" height="25"><input type="password" pattern=".{{40,}}" required title="40 characters minimum" size="35" name="confirmsecret" required /> <br />
                    </tr>
                    <tr>
                      <td colspan="1" width="300"style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; font-size: 14px; color: #282828">
                      <a href="/{1}/">Cancel (Go back)</a>
                      <td colspan="2" style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; font-size: 14px; color: #282828">
                      <div class="title"><br><button type="submit">Change Passphrase!</button></td>
                    </tr>
                  </form>
                </table>
              </body>
            </html>""".format(html_head, self.platform,
                              PLATFORM, joined_years_set)
        return html_page

    @cherrypy.expose
    def change_pass(self, platform, oldsecret, newsecret, confirmsecret, years):
        """ run the code to change the passphrase """
        config = ConfigParser.RawConfigParser()
        config.readfp(open('/etc/encryptonator/encryptonator.conf'))
        key_mail = config.get('main', 'distribution_list')
        PLATFORM = platform.upper()
        if newsecret != confirmsecret:
            err_msg = 'Passphrase and Passphrase verification did not match.'
            got_error = True
        elif oldsecret == newsecret:
            err_msg = 'Old passphrase and New Passphrase canno be the same.'
            got_error = True
        else:
            got_error = None

        if got_error:
            return """{0}
                  <body>
                    <span style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: left; font-size: 36px; color: #4F4F4F">
                      <p>Failed!</p>
                    </span>
                    <span style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: left; font-size: 18px; color: #4F4F4F">
                      <p>{1} Please try again</p>
                    </span>
                    <span style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: left; font-size: 14px; color: #FFFFFF">
                      <p><a href="/{2}/">Go back</a></p>
                    </span>
                    </br></br>
                  </body>
                </html>""".format(html_head, err_msg, platform)

        os.environ['USERNAME'] = 'encryptonator'
        os.environ['HOME'] = '/home/encryptonator'
        passwd_file = os.path.join(os.environ['HOME'], 'passwd_file')
        expire_file = os.path.join(os.environ['HOME'], 'expire_file')
        gpg = gnupg.GPG(gnupghome='/home/encryptonator/.gnupg')
        all_keys = gpg.list_keys()
        with open(passwd_file, 'w') as spool_file:
            spool_file.write('PASSWD\n{0}\n{1}\nSAVE\n'.format(oldsecret, newsecret))
        with open(expire_file, 'w') as exp_file:
            exp_file.write(newsecret)
        spool_file.close()
        exp_file.close()

        try:
            for my_key in all_keys:
                if my_key['uids'][0] == '{0} <{1}>'.format(platform, key_mail):
                    keyid = my_key['keyid']
                    expire_cmd = '/usr/bin/printf "EXPIRE\n{0}y\nSAVE\n" | /usr/bin/gpg --batch --passphrase-fd 3 --command-fd 0  --no-tty --status-fd 2 --verbose --edit-key {1} 3<{2}'.format(years, keyid, expire_file)
                    passwd_cmd = '/usr/bin/gpg --command-fd 0 --no-tty --passphrase-repeat 0 --status-fd 2 --verbose --edit-key {0} < {1}'.format(keyid, passwd_file)
                    proc_pwd = sp.Popen(passwd_cmd, shell=True,
                                        stdout=sp.PIPE, stderr=sp.STDOUT)
                    proc_pw_out = '<br>'.join(proc_pwd.stdout.readlines())
                    if 'Invalid passphrase' in proc_pw_out:
                        raise ValueError(proc_pw_out)
                    proc_exp = sp.Popen(expire_cmd, shell=True,
                                        stdout=sp.PIPE, stderr=sp.STDOUT)
                    proc_exp_out = '<br>'.join(proc_exp.stdout.readlines())
                    if 'bad passphrase' in proc_exp_out:
                        raise ValueError(proc_exp_out)
        except Exception, e:
            html_page = """{0}
                  <body>
                    <span style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: left; font-size: 36px; color: #4F4F4F">
                      <p>Failed!</p>
                    </span>
                    <span style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: left; font-size: 18px; color: #4F4F4F">
                      <p>Failed to change the passphrase: </p>
                    </span>
                    <span style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: left; font-size: 14px; color: #4F4F4F">
                      <p>{1}</p>
                    <span style="font-family: color: #FFFFFF">
                      <p><a href="/{2}/">Go back</a></p>
                    </span>
                    </br></br>
                  </body>
                </html>""".format(html_head, e, platform)
        else:
            key_cmd = 'gpg --list-keys {}'.format(keyid)
            proc_key = sp.Popen(key_cmd, shell=True, stdout=sp.PIPE, stderr=sp.STDOUT)
            proc_out = proc_key.stdout.readlines()
            stripped_out = [x for x in proc_out if x.startswith("pub") or x.startswith("uid")]
            proc_key_out = '<br>'.join(stripped_out)
            html_page = """{0}
                  <body>
                    <span style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: left; font-size: 36px; color: #4F4F4F">
                      <p>Passphrase updated!</p>
                    </span>
                    <span style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: left; font-size: 18px; color: #4F4F4F">
                      <p>The passphrase/expiration for the platform {1} has been updated:</p>
                    </span>
                    <span style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: left; font-size: 16px; color: #4F4F4F">
                      <p>{2}</p>
                    <span style="font-family: color: #FFFFFF">
                      <p><a href="/{3}/">Go back</a></p>
                    </span>
                    </br></br>
                  </body>
                </html>""".format(html_head, PLATFORM, proc_key_out, platform)
        finally:
            try:
                finalize_gpg(passwd_file, expire_file)
            except OSError:
                pass

        return html_page


def finalize_gpg(file1, file2, script1='/home/encryptonator/bin/gpg_sync.sh'):
    """ - remove stale files
        - synchronizes gpg keys across servers and write sync command output
          to a log file. Nagios will check the log for errors
    """
    for stale_file in [file1, file2]:
        try:
            os.remove(stale_file)
        except:
            pass

    proc_rsync = sp.Popen(script1, shell=True, stdout=sp.PIPE, stderr=sp.STDOUT)
    proc_rsync_out = proc_rsync.communicate()[0]
    proc_rsync_out = ''.join(proc_rsync_out)
    retcode = proc_rsync.returncode
    if retcode is not 0:
        proc_rsync_out = 'ERROR\n' + proc_rsync_out

    with open('/home/encryptonator/gpgsync.log', 'w') as log_file:
        log_file.write(proc_rsync_out)
    log_file.close()


def get_sftpsite_dirlist(platform, sftpsite_dir=None):
    """ get a list of files and directories from sftpsite """
    # the user must belong to one of the XX-encryptonator groups
    # and its name should not end with -apiaccess
    logged_user = cherrypy.request.headers.get("ldapuser")
    platform_group = check_ldap_group(logged_user)
    all_groups = set([platform]) & set(platform_group)
    if str.endswith(logged_user, '-apiaccess') or not all_groups:
        return ops_page

    # get configuration from encryptonator config file
    config = ConfigParser.RawConfigParser()
    config.readfp(open('/etc/encryptonator/encryptonator.conf'))
    host = config.get('sftp', 'host')
    port = config.get('sftp', 'port')
    proxy_host = config.get('sftp', 'proxy_host')
    proxy_port = config.get('sftp', 'proxy_port')
    sftp_username = config.get(platform, 'sftp_username')
    platform_ssh_key = os.path.join('/home/encryptonator/.ssh', platform)

    # use the proxy server to connect to the sftpsite sftp server
    proxy_command = '/usr/bin/connect -H {0}:{1} {2} {3}'.format(
        proxy_host,
        proxy_port,
        host,
        port)

    try:
        ssh_key = paramiko.RSAKey.from_private_key_file(platform_ssh_key)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        sock = paramiko.ProxyCommand(proxy_command)
        client.connect(
            hostname=host,
            port=int(port),
            username=platform,
            pkey=ssh_key,
            sock=sock)
        sftp = client.open_sftp()
    except Exception, e:
        return "Failed to connect to sftpsite: {0}".format(e)

    if not sftpsite_dir:
        sftpsite_dir = os.path.join('/home', platform)

    sftp.chdir(sftpsite_dir)
    sftp_cwd = sftp.getcwd()
    dir_list = sftp.listdir('.')

    # get rid of gpg, md5 files
    md5_regex = re.compile('^.*\.(md5|gpg)$')
    remove_list = []
    for item in dir_list:
        if md5_regex.match(item):
            remove_list.append(item)
    for remove_file in remove_list:
        dir_list.remove(remove_file)

    sorted_list = sorted([isdir(sftp, s) for s in dir_list])
    sftp.close()
    sorted_list.insert(0, '[..] &#9;&#9; Upper Directory')
    sorted_list.insert(0, '[{}] &#9;&#9; Home Directory'.format(platform))

    modified_list = ['<input type="radio" name="myfile" value="{0}" required> {0}'.format(s) for s in sorted_list]
    joined_list = '\n'.join(modified_list)
    gpg_expiration = re.sub(r'\s$', '', check_gpg(platform))
    html_page = """{0}
          <body>
            <table align="center" width="100%" border="0" class="Table" id="table1">
              <tr>
                <div  style="text-align: center;">
                  <td bgcolor="#282828" colspan="0" height="80" valign="middle" style="font-family: 'Trebuchet MS', Vesans-serif; font-size: 18px; color: #697476">
                    <p style="text-align:left;">&nbsp;<&nbsp;[<a href="/">Home Page</a>]
                      <span style="float:right;font-size: 16px;">
                        [{1}]&nbsp;&nbsp;
                      </span>
                    </p>
                  </td>
                  <td bgcolor="#282828" colspan="0" width="310" height="80" valign="middle" style="font-family: 'Trebuchet MS', Vesans-serif; text-align: center; font-size: 18px; color: #697476">
                    <form method="POST" action="reset_passphrase">
                      <input type="hidden" name="platform" value="{2}"/>
                      <button type="submit">Reset passphrase / Renew GPG key</button>
                    </form>
                  </td>
                </div>
              </tr>
            </table>
            <span style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; font-size: 12px; color: #282828">
              <form method="POST" action="get_and_decrypt"><pre>{3}
                <br /></pre>
                <input type="hidden" name="sftp_path" value="{4}"/>
                <button type="submit">Change Directory or Get file</button>
              </form>
            </span>
          </body>
        </html>""".format(html_head, gpg_expiration, platform,
                          joined_list, sftp_cwd)
    return html_page


def get_sftpsite_json(platform, sftpsite_dir=None, count=0):
    """ get a list of files and directories from sftpsite """
    # get configuration from encryptonator config file
    config = ConfigParser.RawConfigParser()
    config.readfp(open('/etc/encryptonator/encryptonator.conf'))
    host = config.get('sftp', 'host')
    port = config.get('sftp', 'port')
    proxy_host = config.get('sftp', 'proxy_host')
    proxy_port = config.get('sftp', 'proxy_port')
    sftp_username = config.get(platform, 'sftp_username')
    platform_ssh_key = os.path.join('/home/encryptonator/.ssh', platform)

    # use the proxy server to connect to the sftpsite sftp server
    proxy_command = '/usr/bin/connect -H {0}:{1} {2} {3}'.format(
        proxy_host,
        proxy_port,
        host,
        port)

    try:
        ssh_key = paramiko.RSAKey.from_private_key_file(platform_ssh_key)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        sock = paramiko.ProxyCommand(proxy_command)
        client.connect(
            hostname=host,
            port=int(port),
            username=platform,
            pkey=ssh_key,
            sock=sock)
        sftp = client.open_sftp()
    except Exception, err:
        err_msg = {'ERROR': 'Failed to connect to sftpsite: {0}'.format(e)}
        return err_msg

    if not sftpsite_dir:
        sftpsite_dir = os.path.join('/home', platform)

    try:
        sftp.chdir(sftpsite_dir)
    except Exception, err:
        err_msg = {'ERROR': '{0} not a directory or does not exist: {1}'.format(
            sftpsite_dir, err)}
        return err_msg

    sftp_cwd = sftp.getcwd()
    dir_list = sftp.listdir('.')

    # get rid of gpg, md5 files
    md5_regex = re.compile('^.*\.(md5|gpg)$')
    remove_list = []
    for item in dir_list:
        if md5_regex.match(item):
            remove_list.append(item)
    for remove_file in remove_list:
        dir_list.remove(remove_file)

    sorted_list = sorted([isdir_json(sftp, s) for s in dir_list])
    sftp.close()
    json_list = {}
    for item in sorted_list:
        json_list[count+1] = {
            'type': sorted_list[count][0],
            'size': sorted_list[count][1],
            'name': sorted_list[count][2]
            }
        count += 1
    if not json_list:
        json_list = {
            'ERROR': '{} does not contain any file'.format(sftpsite_dir)}

    return json_list


def check_gpg(platform):
    """ check the status of the GPG key """
    config = ConfigParser.RawConfigParser()
    config.readfp(open('/etc/encryptonator/encryptonator.conf'))
    key_mail = config.get('main', 'distribution_list')
    PLATFORM = platform.upper()
    os.environ['USERNAME'] = 'encryptonator'
    os.environ['HOME'] = '/home/encryptonator'
    gpg = gnupg.GPG(gnupghome='/home/encryptonator/.gnupg')
    all_keys = gpg.list_keys()

    for my_key in all_keys:
        if my_key['uids'][0] == '{0} <{1}>'.format(platform, key_mail):
            keyid = my_key['keyid']

    key_cmd = 'gpg --list-keys {}'.format(keyid)
    proc_key = sp.Popen(key_cmd, shell=True, stdout=sp.PIPE, stderr=sp.STDOUT)
    proc_out = proc_key.stdout.readlines()
    for line_out in proc_out:
        if line_out.startswith("pub"):
            break

    expiration = line_out.split(' ')[-1].replace(']', '')
    check_gpg_out = 'GPG key for platform {0} expires on: {1}'.format(
        PLATFORM,
        expiration)
    # creation = line_out.split(' ')[4]
    # signature = line_out.split(' ')[3].split('/')[1]
    return check_gpg_out


def isdir(sftp, path):
    """ check wether is a dir or a file on an SFTP server
        and return type, size and name
    """
    if S_ISDIR(sftp.stat(path).st_mode):
        isdir_string = '[directory]&#9;&#9; {0}'.format(path)
    else:
        byte_syze = sftp.stat(path).st_size
        if byte_syze > 1024**4:
            path_size = '{0} T'.format(round(byte_syze/(1024**4), 2))
        elif byte_syze > 1024**3:
            path_size = '{0} G'.format(round(byte_syze/(1024**3), 2))
        elif byte_syze > 1024**2:
            path_size = '{0} M'.format(round(byte_syze/(1024**2), 2))
        elif byte_syze > 1024:
            path_size = '{0} K'.format(round(byte_syze/1024, 2))
        else:
            path_size = '{0} B'.format(round(byte_syze, 2))
        isdir_string = '[file] {0} &#9; {1}'.format(path_size, path)
    return isdir_string


def isdir_json(sftp, path):
    """ check wether is a dir or a file on an SFTP server
        and return type, size and name
    """
    if S_ISDIR(sftp.stat(path).st_mode):
        isdir_string = ['directory', '0', path]
    else:
        byte_syze = sftp.stat(path).st_size
        isdir_string = ['file', byte_syze, path]
    return isdir_string


def check_ldap_group(uid):
    """ Browse groups for the specified user """
    config = ConfigParser.RawConfigParser()
    config.readfp(open('/etc/encryptonator/encryptonator.conf'))
    LDAP_BASE = config.get('ldap', 'ldap_base')
    LDAP_SERVER = config.get('ldap', 'ldap_server')
    GROUP_BASE = config.get('ldap', 'group_base')
    GROUP_SUFFIX = config.get('ldap', 'group_suffix')
    l = ldap.initialize(LDAP_SERVER)
    l_filter = '(|(&(objectClass=*)(member=uid={0},{1})))'.format(uid, LDAP_BASE)

    try:
        results = l.search_s(GROUP_BASE, ldap.SCOPE_SUBTREE, l_filter, ['cn'])
    except Exception:
        return None

    for ldapgroup in results:
        if GROUP_SUFFIX in ldapgroup[1]['cn'][0]:
            try:
                encgroup
            except NameError:
                encgroup = []
            encgroup.append(ldapgroup[1]['cn'][0].replace(GROUP_SUFFIX, ''))

    try:
        encgroup
    except NameError:
        return None
    else:
        return encgroup


def check_ldap_email(uid):
    """ get the email for the specified user """
    config = ConfigParser.RawConfigParser()
    config.readfp(open('/etc/encryptonator/encryptonator.conf'))
    LDAP_SERVER = config.get('ldap', 'ldap_server')
    LDAP_BASE = config.get('ldap', 'ldap_base')
    l = ldap.initialize(LDAP_SERVER)
    l_filter = '(|(&(objectClass=*)(uid={0})))'.format(uid)

    try:
        result = l.search_s(LDAP_BASE, ldap.SCOPE_SUBTREE,
                            l_filter, ['mail'])[0][1]['mail'][0]
    except Exception:
        return 'insert_your_user@ebay.com'

    return result


if __name__ == '__main__':

    global ops_page, html_head
    ARGS = parse()
    CONF_DIR = "/etc/encryptonator/wsgi"

    html_head = """<!DOCTYPE html>
    <html>
      <head>
        <meta content="text/html; charset=utf-8" http-equiv="content-type">
        <link rel="stylesheet" type="text/css" href="/main.css" />
        <title>Encryptonator</title>
      </head>"""

    ops_page = """{0}
      <body>
        <span style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: left; font-size: 36px; color: #4F4F4F">
          <p>Ops!</p> </span>
        <span style="font-family: 'Trebuchet MS', Verdana, Arial, sans-serif; text-align: left; font-size: 18px; color: #4F4F4F">
          <p>You are either unauthorized or this path does not exist</p>
        </span>
        <br>
        <a HREF="javascript:javascript:history.go(-1)">Go back</a>
        </br>
      </body>
    </html>""".format(html_head)

    cherrypy.config.update({
        'server.socket_host': ARGS.bind_address,
        'server.socket_port': ARGS.port,
        'server.ssl_module': 'builtin',
        'server.ssl_certificate': ARGS.ssl_cert,
        'server.ssl_private_key': ARGS.ssl_key,
        'log.screen': True,
        'tools.sessions.on': True,
        'tools.sessions.storage_type': 'file',
        'tools.sessions.storage_path': '/home/encryptonator/sessions',
        'tools.sessions.timeout': 60,
        'autoreload.on': False,
        })

    execfile(os.path.join(CONF_DIR, 'server_list.conf'))

    cherrypy.tree.mount(Root(), '/', os.path.join(CONF_DIR, 'root.conf'))

    for webpath in server_list:
        conf = '{0}{1}.app.conf'.format(CONF_DIR, webpath)
        cherrypy.tree.mount(App(webpath), webpath, config=conf)

    if ARGS.daemon:
        Daemonizer(cherrypy.engine).subscribe()

    if ARGS.pidfile:
        PIDFile(cherrypy.engine, ARGS.pidfile).subscribe()

    cherrypy.engine.signal_handler.subscribe()
    cherrypy.engine.start()
    cherrypy.engine.block()
