#!/bin/sh -e

VERSION=`grep version setup.py | cut -d\" -f2`
echo $VERSION
python2.5 setup.py sdist --formats gztar,zip
MD5_GZTAR=`md5 dist/pydkim-$VERSION.tar.gz | cut -d' ' -f4`
MD5_ZIP=`md5 dist/pydkim-$VERSION.zip | cut -d' ' -f4`
echo $MD5_GZTAR $MD5_ZIP
