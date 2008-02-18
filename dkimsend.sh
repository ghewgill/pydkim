#!/bin/sh

/usr/local/bin/python2.5 /home/greg/src/pydkim/dkimsign.py greg hewgill.com /home/greg/.domainkeys/rsa.private | /usr/sbin/sendmail $*
