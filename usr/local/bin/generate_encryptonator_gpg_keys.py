#!/usr/bin/python
"""
 Generate encryptonator GPG key
"""
from optparse import OptionParser
import ConfigParser
import getpass
import gnupg


if __name__ == "__main__":
    usage = "Usage: %prog -p platform"
    parser = OptionParser(usage)
    parser.add_option("-p", dest="platform", help="Platform name")
    (options, args) = parser.parse_args()

if options.platform:
    platform = options.platform
else:
    print 'Please specify a platform'
    quit(1)

# check for valid platforms in the encryptonator config
config = ConfigParser.RawConfigParser()
config.readfp(open('/etc/encryptonator/encryptonator.conf'))
platforms = config.sections()
platforms.remove('sftp')

if platform in platforms:
    try:
        gpg = gnupg.GPG(gnupghome='/home/encryptonator/.gnupg')
        pass_phrase = getpass.getpass(prompt='Please enter a passphrase: ')
        key_input = gpg.gen_key_input(
            key_type='RSA',
            key_length='2048',
            name_real=platform,
            name_email='email@domain.com',
            expire_date='1y',
            passphrase=pass_phrase)
        key_data = gpg.gen_key(key_input)
        import_key = gpg.import_keys(str(key_data))
    except Exception, e:
        print 'Failed to generate key: {0}'.format(e)
else:
    print 'Unrecognized platform. Check /etc/encryptonator/encryptonator.conf for options.'
    quit(1)
