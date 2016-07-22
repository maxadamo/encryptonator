#!/bin/bash
getent group encryptonator >/dev/null 2>&1 || groupadd -g 999 encryptonator
getent passwd encryptonator >/dev/null 2>&1 || useradd -r -s /bin/bash -d /home/encryptonator -g 999 -u 999 -m -c 'encryptonator service' encryptonator
