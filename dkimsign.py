#!/usr/local/bin/python2.5

import sys

import dkim

if len(sys.argv) < 4 or len(sys.argv) > 5:
    print >>sys.stderr, "Usage: dkimsign.py selector domain privatekeyfile [identity]"
    sys.exit(1)

selector = sys.argv[1]
domain = sys.argv[2]
privatekeyfile = sys.argv[3]
identity = len(sys.argv) >= 5 and sys.argv[4]

message = sys.stdin.read()
try:
    sig = dkim.sign(message, selector, domain, open(privatekeyfile, "r").read(), identity = identity)
    sys.stdout.write(sig)
    sys.stdout.write(message)
except Exception, e:
    print >>sys.stderr, e
    sys.stdout.write(message)
