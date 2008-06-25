#!/bin/sh -e

VERSION=`grep ^version setup.py | cut -d\" -f2`
echo $VERSION
if [ -f dist/pydkim-$VERSION.tar.gz ]; then
    echo "version already exists"
    exit 1
fi
perl -pi -e "s/pydkim [0-9.]+/pydkim $VERSION./g" README
epydoc dkim
python2.5 setup.py sdist --formats gztar
MD5_GZTAR=`md5 dist/pydkim-$VERSION.tar.gz | cut -d' ' -f4`
echo $MD5_GZTAR
perl -pi -e "s/pydkim-[0-9.]+/pydkim-$VERSION./g; s/= [0-9a-f]+/= $MD5_GZTAR/" ~/www.hewgill.com/pydkim/index.html
cp -Rv html ~/www.hewgill.com/pydkim/
cp -v dist/pydkim-$VERSION.tar.gz ~/www.hewgill.com/pydkim/
echo "Version $VERSION successful"
echo
echo "NEXT STEPS:"
echo "- svn cp trunk tags/release-$VERSION"
echo "- python setup.py register"
