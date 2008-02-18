#!/usr/bin/env python

from distutils.core import setup

setup(
    name = "pydkim",
    version = "0.1",
    description = "DKIM (DomainKeys Identified Mail)",
    author = "Greg Hewgill",
    author_email = "greg@hewgill.com",
    url = "http://hewgill.com/software/pydkim/",
    py_modules = ["dkim"],
    scripts = ["dkimsign.py", "dkimverify.py", "dkimsend.sh"],
)
