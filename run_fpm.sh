#!/bin/bash
set -x
set -e

package_version=`cat VERSION`

rm -f *.deb

fpm -t deb \
    -s dir \
    --architecture all \
    --version ${package_version} \
    --before-install pre-install.sh \
    --after-install post-install.sh \
    --maintainer 'Jenkins Blahblah <blahblah@domain.com>' \
    --deb-user root \
    --deb-group root \
    --description 'encryptonator' \
    --verbose \
    -C . \
    -x pre-install.sh \
    -x post-install.sh \
    -x README.md \
    -x run_fpm.sh \
    -x VERSION \
    -x .git \
    -x *.deb \
    --deb-pre-depends python-pika \
    --deb-pre-depends python-rsa \
    --deb-pre-depends python-crypto \
    --deb-pre-depends python-paramiko \
    --deb-pre-depends python-gnupg \
    --deb-pre-depends python-cherrypy3 \
    --deb-pre-depends python-ldap \
    --name encryptonator \
    .
