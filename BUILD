#! /bin/sh

##  Script to build a simple PKI.
umask 2

##  If you change the the value of "dir" also edit $OPENSSL_CONF
OPENSSL_CONF=pki.conf ; export OPENSSL_CONF
dir=data

ME=`basename $0`

##  Basic sanity check
if [ ! -f ${OPENSSL_CONF} ] ; then
    echo ${ME}: ${OPENSSL_CONF} not found. 2>&1
    exit 1
fi

if [ "x$1" = "x--clean" ]  ; then
    echo ''
    echo '**'
    echo '**  REMOVING PREVIOUS CONFIGURATION'
    echo '**'
    rm -rf ${dir} pki.tgz cert.der cert.pem
    exit 0
fi

if [ "x$1" != "x" ] ; then
    echo ${ME}: Bad flag. 2>&1
    exit 1
fi

##  Create home for CA and items within it.
##  See ${OPENSSL_CONF} for what needs to be created.
test -d ${dir} || mkdir ${dir} || exit 1
test -f ${dir}/serial || echo '01' > ${dir}/serial
test -f ${dir}/crlnumber || echo '01' > ${dir}/crlnumber
touch ${dir}/index.txt
test -d ${dir}/certs || mkdir ${dir}/certs
touch ${dir}/.rand
find ${dir} -exec chmod g+w,a+w '{}' ';'

cat <<\EOF >${dir}/.htaccess
<FilesMatch ".">
    Deny from all
</FilesMatch>
EOF

##  Create keypair, cert request, and self-sign the certificate
DNTYPE=cadn_req openssl req \
        -newkey rsa:2048 -nodes -batch \
        -out ${dir}/certreq.pem -keyout ${dir}/key.pem
[ $? -eq 0 ] || exit 1
openssl x509 -extensions cacert_ext \
        -req -signkey ${dir}/key.pem \
        -sha1 -days 1800 \
        -in ${dir}/certreq.pem -out temp.pem
[ $? -eq 0 ] || exit 1

##  Get full-text and DER of the certificate
openssl x509 -text -in temp.pem -out ${dir}/cert.pem
[ $? -eq 0 ] || exit 1
cp ${dir}/cert.pem .
openssl x509 -outform der -in temp.pem -out cert.der
[ $? -eq 0 ] || exit 1
rm -f temp.pem

##  Create distro for download
HERE=`/bin/pwd`
D=`basename $HERE`
cd ..
rm -f ${P}/pki.tgz
tar zcf ${D}/pki.tgz ${D}/README.txt ${D}/BUILD \
        ${D}/makecert.cgi ${D}/enroll.txt \
        ${D}/pki-conf.txt ${D}/index-html.txt ${D}/style.css \
        ${D}/win-instr

echo ''
echo '**'
echo '**  DONE'
echo '**'
