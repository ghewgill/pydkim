import base64
import hashlib
import re
import time

import dns.resolver

__all__ = [
    "Simple",
    "Relaxed",
    "FormatError",
    "ParameterError",
    "sign",
    "verify",
]

class Simple:
    """Class that represents the "simple" canonicalization algorithm."""

    name = "simple"

    @staticmethod
    def canonicalize_headers(headers):
        return headers

    @staticmethod
    def canonicalize_body(body):
        return re.sub("(\r\n)*$", "\r\n", body)

class Relaxed:
    """Class that represents the "relaxed" canonicalization algorithm."""

    name = "relaxed"

    @staticmethod
    def canonicalize_headers(headers):
        return [(x[0].lower(), (re.sub(r"\s+", " ", re.sub("\r\n", "", x[1]))).strip()+"\r\n") for x in headers]

    @staticmethod
    def canonicalize_body(body):
        return re.sub("(\r\n)*$", "\r\n", re.sub(r"[\x09\x20]+", " ", re.sub("[\\x09\\x20]+\r\n", "\r\n", body)))

class DKIMException(Exception):
    """Base class for DKIM errors."""
    pass

class FormatError(DKIMException):
    pass

class ParameterError(DKIMException):
    pass

def _remove(s, t):
    i = s.find(t)
    assert i >= 0
    return s[:i] + s[i+len(t):]

INTEGER = 0x02
BIT_STRING = 0x03
OCTET_STRING = 0x04
NULL = 0x05
OBJECT_IDENTIFIER = 0x06
SEQUENCE = 0x30

ASN1_Object = [
    (SEQUENCE, [
        (SEQUENCE, [
            (OBJECT_IDENTIFIER,),
            (NULL,),
        ]),
        (BIT_STRING,),
    ])
]

ASN1_RSAPublicKey = [
    (SEQUENCE, [
        (INTEGER,),
        (INTEGER,),
    ])
]

ASN1_RSAPrivateKey = [
    (SEQUENCE, [
        (INTEGER,),
        (INTEGER,),
        (INTEGER,),
        (INTEGER,),
        (INTEGER,),
        (INTEGER,),
        (INTEGER,),
        (INTEGER,),
        (INTEGER,),
    ])
]

def asn1_parse(template, data):
    r = []
    i = 0
    for t in template:
        tag = ord(data[i])
        i += 1
        if tag == t[0]:
            length = ord(data[i])
            i += 1
            if length & 0x80:
                n = length & 0x7f
                length = 0
                for j in range(n):
                    length = (length << 8) | ord(data[i])
                    i += 1
            if tag == INTEGER:
                n = 0
                for j in range(length):
                    n = (n << 8) | ord(data[i])
                    i += 1
                r.append(n)
            elif tag == BIT_STRING:
                r.append(data[i:i+length])
                i += length
            elif tag == NULL:
                assert length == 0
                r.append(None)
            elif tag == OBJECT_IDENTIFIER:
                r.append(data[i:i+length])
                i += length
            elif tag == SEQUENCE:
                r.append(asn1_parse(t[1], data[i:i+length]))
                i += length
            else:
                print "we should not be here"
        else:
            print "unexpected tag (%02x, expecting %02x)" % (tag, t[0])
    return r

def asn1_length(n):
    if n < 0x7f:
        return chr(n)
    print "fail"

def asn1_build(node):
    if node[0] == OCTET_STRING:
        return chr(OCTET_STRING) + asn1_length(len(node[1])) + node[1]
    if node[0] == NULL:
        assert node[1] is None
        return chr(NULL) + asn1_length(0)
    elif node[0] == OBJECT_IDENTIFIER:
        return chr(OBJECT_IDENTIFIER) + asn1_length(len(node[1])) + node[1]
    elif node[0] == SEQUENCE:
        r = ""
        for x in node[1]:
            r += asn1_build(x)
        return chr(SEQUENCE) + asn1_length(len(r)) + r
    else:
        print "unexpected tag"

def str2int(s):
    r = 0
    for c in s:
        r = (r << 8) | ord(c)
    return r

def int2str(n, length = -1):
    assert n >= 0
    r = []
    while length < 0 or len(r) < length:
        r.append(chr(n & 0xff))
        n >>= 8
        if length < 0 and n == 0: break
    r.reverse()
    assert length < 0 or len(r) == length
    return r

def rfc822_parse(message):
    headers = []
    lines = re.split("\r?\n", message)
    i = 0
    while i < len(lines):
        if len(lines[i]) == 0:
            i += 1
            break
        if re.match(r"[\x09\x20]", lines[i][0]):
            headers[-1][1] += lines[i]+"\r\n"
        else:
            m = re.match(r"([\x21-\x7e]+?):", lines[i])
            if m is not None:
                headers.append([m.group(1), lines[i][m.end(0):]+"\r\n"])
            elif lines[i].startswith("From "):
                pass
            else:
                raise FormatError()
        i += 1
    return (headers, "\r\n".join(lines[i:]))

def dnstxt(name):
    a = dns.resolver.query(name, dns.rdatatype.TXT)
    for r in a.response.answer:
        if r.rdtype == dns.rdatatype.TXT:
            return "".join(r[0].strings)
    return None

def sign(message, selector, domain, privkey, identity=None, canonicalize=(Simple, Simple), include_headers=None, length=-1, debuglog=None):
    """Sign an RFC822 message and return the DKIM-Signature header line.

    @param message: an RFC822 formatted message (with either \\n or \\r\\n line endings)
    @param selector: the DKIM selector value for the signature
    @param domain: the DKIM domain value for the signature
    @param privkey: a PKCS#1 private key in base64-encoded text form
    @param identity: the DKIM identity value for the signature (default "@"+domain)
    @param canonicalize: the canonicalization algorithms to use (default (Simple, Simple))
    @param include_headers: a list of strings indicating which headers are to be signed (default all headers)
    @param length: the length of the body to include in the signature
    @param debuglog: a file-like object to which debug info will be written (default None)

    """

    pkdata = base64.b64decode(re.search("--\n(.*?)\n--", privkey, re.DOTALL).group(1))
    if debuglog is not None:
        print >>debuglog, " ".join("%02x" % ord(x) for x in pkdata)
    pka = asn1_parse(ASN1_RSAPrivateKey, pkdata)
    pk = {
        'version': pka[0][0],
        'modulus': pka[0][1],
        'publicExponent': pka[0][2],
        'privateExponent': pka[0][3],
        'prime1': pka[0][4],
        'prime2': pka[0][5],
        'exponent1': pka[0][6],
        'exponent2': pka[0][7],
        'coefficient': pka[0][8],
    }
    modlen = len(int2str(pk['modulus']))

    (headers, body) = rfc822_parse(message)

    headers = canonicalize[0].canonicalize_headers(headers)

    if include_headers is None:
        include_headers = [x[0] for x in headers]
    sign_headers = [x for x in headers if x[0] in include_headers]

    body = canonicalize[1].canonicalize_body(body)

    h = hashlib.sha256()
    h.update(body)
    bodyhash = base64.b64encode(h.digest())

    sigfields = [
        ('v', "1"),
        ('a', "rsa-sha256"),
        ('c', "%s/%s" % (canonicalize[0].name, canonicalize[1].name)),
        ('d', domain),
        ('i', identity or "@"+domain),
        ('q', "dns/txt"),
        ('s', selector),
        ('t', "%d" % time.time()),
        ('h', " : ".join(x[0] for x in sign_headers)),
        ('bh', bodyhash),
        ('b', ""),
    ]
    sig = "DKIM-Signature: " + "; ".join("%s=%s" % x for x in sigfields)

    if debuglog is not None:
        print >>debuglog, "sign headers:", sign_headers + [("DKIM-Signature", " "+"; ".join("%s=%s" % x for x in sigfields))]
    h = hashlib.sha256()
    for x in sign_headers:
        h.update(x[0])
        h.update(":")
        h.update(x[1])
    h.update(sig)
    d = h.digest()
    if debuglog is not None:
        print >>debuglog, "sign digest:", " ".join("%02x" % ord(x) for x in d)

    dinfo = asn1_build(
        (SEQUENCE, [
            (SEQUENCE, [
                (OBJECT_IDENTIFIER, "\x60\x86\x48\x01\x65\x03\x04\x02\x01"), # sha256
                (NULL, None),
            ]),
            (OCTET_STRING, d),
        ])
    )
    sig2 = int2str(pow(str2int("\x00\x01"+"\xff"*(modlen-len(dinfo)-3)+"\x00"+dinfo), pk['privateExponent'], pk['modulus']), modlen)
    sig += base64.b64encode(''.join(sig2))

    return sig + "\r\n"

def verify(message, debuglog=None):
    """Verify a DKIM signature on an RFC822 formatted message.

    @param message: an RFC822 formatted message (with either \\n or \\r\\n line endings)
    @param debuglog: a file-like object to which debug info will be written (default None)

    """

    (headers, body) = rfc822_parse(message)

    sigheaders = [x for x in headers if x[0].lower() == "dkim-signature"]
    if len(sigheaders) != 1:
        return None

    a = re.split(r"\s*;\s*", sigheaders[0][1].strip())
    if debuglog is not None:
        print >>debuglog, "a:", a
    sig = dict((x.group(1), x.group(2)) for x in [re.match(r"(\w+)=(.*)", y, re.DOTALL) for y in a if y])
    if debuglog is not None:
        print >>debuglog, "sig:", sig

    m = re.match("(\w+)/(\w+)$", sig['c'])
    can_headers = m.group(1)
    can_body = m.group(2)

    if can_headers == "simple":
        canonicalize_headers = Simple
    elif can_headers == "relaxed":
        canonicalize_headers = Relaxed
    else:
        raise ParameterError()

    headers = canonicalize_headers.canonicalize_headers(headers)

    if can_body == "simple":
        body = Simple.canonicalize_body(body)
    elif can_body == "relaxed":
        body = Relaxed.canonicalize_body(body)
    else:
        raise ParameterError()

    if sig['a'] == "rsa-sha1":
        hasher = hashlib.sha1
    elif sig['a'] == "rsa-sha256":
        hasher = hashlib.sha256
    else:
        raise ParameterError()

    h = hasher()
    h.update(body)
    if debuglog is not None:
        print >>debuglog, "bh:", base64.b64encode(h.digest())

    s = dnstxt(sig['s']+"._domainkey."+sig['d']+".")
    if not s:
        return False
    a = re.split(r";\s*", s)
    pub = {}
    for f in a:
        m = re.match(r"(.)=(.*)", f)
        if m:
            pub[m.group(1)] = m.group(2)
    x = asn1_parse(ASN1_Object, base64.b64decode(pub['p']))
    pkd = asn1_parse(ASN1_RSAPublicKey, x[0][1][1:])
    pk = {
        'modulus': pkd[0][0],
        'publicExponent': pkd[0][1],
    }
    modlen = len(int2str(pk['modulus']))
    if debuglog is not None:
        print >>debuglog, "modlen:", modlen

    #pemkey = "-----BEGIN PUBLIC KEY-----\n"
    #p = pub['p']
    #while len(p):
    #    pemkey += p[0:64]+"\n"
    #    p = p[64:]
    #pemkey += "-----END PUBLIC KEY-----\n"
    #pubkey = POW.pemRead(POW.RSA_PUBLIC_KEY, pemkey)

    include_headers = re.split(r"\s*:\s*", sig['h'])
    if debuglog is not None:
        print >>debuglog, "include_headers:", include_headers
    sign_headers = []
    lastindex = {}
    for h in include_headers:
        i = lastindex.get(h, len(headers))
        while i > 0:
            i -= 1
            if h.lower() == headers[i][0].lower():
                sign_headers.append(headers[i])
                break
        lastindex[h] = i
    sign_headers += [(x[0], x[1].rstrip()) for x in canonicalize_headers.canonicalize_headers([(sigheaders[0][0], _remove(sigheaders[0][1], sig['b']))])]
    if debuglog is not None:
        print >>debuglog, "verify headers:", sign_headers

    h = hasher()
    for x in sign_headers:
        h.update(x[0])
        h.update(":")
        h.update(x[1])
    d = h.digest()
    if debuglog is not None:
        print >>debuglog, "verify digest:", " ".join("%02x" % ord(x) for x in d)

    dinfo = asn1_build(
        (SEQUENCE, [
            (SEQUENCE, [
                #(OBJECT_IDENTIFIER, "\x2b\x0e\x03\x02\x1a"), # sha1
                (OBJECT_IDENTIFIER, "\x60\x86\x48\x01\x65\x03\x04\x02\x01"), # sha256
                (NULL, None),
            ]),
            (OCTET_STRING, d),
        ])
    )
    if debuglog is not None:
        print >>debuglog, "dinfo:", " ".join("%02x" % ord(x) for x in dinfo)
    sig2 = "\x00\x01"+"\xff"*(modlen-len(dinfo)-3)+"\x00"+dinfo
    if debuglog is not None:
        print >>debuglog, "sig2:", " ".join("%02x" % ord(x) for x in sig2)
        print >>debuglog, sig['b']
        print >>debuglog, re.sub(r"\s+", "", sig['b'])
    v = int2str(pow(str2int(base64.b64decode(re.sub(r"\s+", "", sig['b']))), pk['publicExponent'], pk['modulus']), modlen)
    if debuglog is not None:
        print >>debuglog, "v:", " ".join("%02x" % ord(x) for x in v)
    assert len(v) == len(sig2)
    return not [1 for x in zip(v, sig2) if x[0] != x[1]]

if __name__ == "__main__":
    message = """From: greg@hewgill.com\r\nSubject: test\r\n message\r\n\r\nHi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe.\r\n"""
    print rfc822_parse(message)
    sig = sign(message, "greg", "hewgill.com", open("/home/greg/.domainkeys/rsa.private").read())
    print sig
    print verify(sig+message)
    #print sign(open("/home/greg/tmp/message").read(), "greg", "hewgill.com", open("/home/greg/.domainkeys/rsa.private").read())
