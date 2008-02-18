#!/bin/sh

/usr/local/bin/python2.5 /home/greg/src/pydkim/dkimsign.py | /usr/sbin/sendmail $*
