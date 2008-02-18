#!/usr/local/bin/python2.5

import sys

import dkim

message = sys.stdin.read()
try:
    sig = dkim.sign(message, "greg", "hewgill.com", open("/home/greg/.domainkeys/rsa.private", "r").read())
    sys.stdout.write(sig)
    sys.stdout.write(message)
except Exception, e:
    print >>sys.stderr, e
    sys.stdout.write(message)
