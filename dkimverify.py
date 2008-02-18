#!/usr/local/bin/python2.5

import sys

import dkim

message = sys.stdin.read()
if not dkim.verify(message):
    print "signature verification failed"
    sys.exit(1)
print "signature ok"
