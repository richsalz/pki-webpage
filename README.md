PKI-Webpage


A very simple PKI in a web page.  It creates a root CA which then creates
SSL server certificates; it also generates the keypair for each client.

It should not be too hard to edit pki.conf to create other types.
Perhaps add a (hidden) parameter to the form in index.html and use that
in makecert.

This was only ever tested with Apache on Ubuntu but (famous last words)
I tried to make it generic to any Apache/Unix-like system.  I'd be curious
to see portability enhancements to make it work on other such systems;
I'm not interested in maintaining a Windows port.

The data directory holds all the OpenSSL configuration, including the
CA's private key.  The makecert script needs full read/write access to
that directory.  The BUILD script does this brute-force by giving global
write permission and setting an .htaccess file to prevent remote access
to that data.  This is not great; putting the data directory outside the
URL space and/or using setgid perl is better.  If you do that, please
let me know.

To install:

        cp index-html.txt index.html
        ${EDITOR} index.html (look for XXX or xxx)
        cp pki-conf.txt pki.conf
        ${EDITOR} pki.conf (look for XXX or xxx)
        sh ./BUILD

To scrub:

        sh ./BUILD --clean

If you are worried about race conditions with the CA command and serial
numbers, look at the lockfile and lockit variables in makecert.cgi .  I'm not
worried, so that is definiteily untested code.

-Rich Salz
 Originally written: September, 2009

Adding CRL support might be useful.  Notes on what to do:
1.  In index.html, add a link to fetch the current CRL.
2.  In index.html, add a revocation section including name/password
    (decide if this is for real use or only audit purposes) and then
    either the serial# or a place to upload the PEM cert file.
3.  In makecert, if revocation, get cert from serial# or parse/print PEM
    file.  Authorize request -- e.g., username must be in subjectAltName.
4.  To revoke a cert and generate a CRL:
        openssl ca -revoke data/certs/{SERIAL#}.pem  -name pki_ca
        openssl ca -gencrl -name pki_ca | openssl crl -text >crl.pem
        openssl crl -outform der <crl.pem >crl.crl
