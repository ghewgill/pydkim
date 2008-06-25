#!/usr/local/bin/python2.5

# This software is provided 'as-is', without any express or implied
# warranty.  In no event will the author be held liable for any damages
# arising from the use of this software.
# 
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
# 
# 1. The origin of this software must not be misrepresented; you must not
#    claim that you wrote the original software. If you use this software
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
# 2. Altered source versions must be plainly marked as such, and must not be
#    misrepresented as being the original software.
# 3. This notice may not be removed or altered from any source distribution.
# 
# Copyright (c) 2008 Greg Hewgill http://hewgill.com

import sys

import dkim

if len(sys.argv) < 4 or len(sys.argv) > 5:
    print >>sys.stderr, "Usage: dkimsign.py selector domain privatekeyfile [identity]"
    sys.exit(1)

selector = sys.argv[1]
domain = sys.argv[2]
privatekeyfile = sys.argv[3]
if len(sys.argv) > 5:
    identity = sys.argv[4]
else:
    identity = None

message = sys.stdin.read()
try:
    sig = dkim.sign(message, selector, domain, open(privatekeyfile, "r").read(), identity = identity)
    sys.stdout.write(sig)
    sys.stdout.write(message)
except Exception, e:
    print >>sys.stderr, e
    sys.stdout.write(message)
