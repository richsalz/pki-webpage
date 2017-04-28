#! /usr/bin/perl -TW

##
##  SSL PKI in a script
##

##  Imports.
use strict;
use CGI qw/:standard/;
use CGI::Carp qw/fatalsToBrowser set_message/;
use Net::LDAP;
use Fcntl ':flock';

# Look for "$IBM" for places to change.
my $IBM = 1;

$ENV{"PATH"} = "/bin:/usr/bin/:/usr/local/bin";
$ENV{"OPENSSL_CONF"} = "pki.conf";

my $reqfile = "/tmp/req$$.pem";
my $keyfile = "/tmp/key$$.pem";
my $certfile = "/tmp/cert$$.pem";
my $lockit = 0;
my $lockfile = "/var/run/makecert.lock";
my $status;
my $extsect;
my @args;


##  Send error page to browser and exit.
sub Bye
{
    my $reason = pop();
    set_message("Please press BACK and try again.");
    die "Bad request: $reason\n";
    exit 1;
}


##  Authenticate or die trying.
sub
Authenticate
{
    my ($name, $pass) = @_;

    if ( $IBM ) {
        # Bind to server.
        my $ldap = new Net::LDAP("bluepages.ibm.com");
        my $result = $ldap->bind();
        Bye("Can't connect to BluePages -- $result->error") if $result->code;

        # Find user with that email address
        $result = $ldap->search(
            base   => "o=ibm.com",
            filter => "(&(mail=$req::name)(objectclass=person))",
            attrs  => ["dn"]);
        Bye("BluePages error $result->error") if $result->code;
        Bye("No such user") if $result->count == 0;

        # Try to bind as that user with the password they gave
        my $dn = $result->shift_entry->dn;
        $result = $ldap->bind($dn, password => $req::pass);
        Bye("Authentication failure") if $result->code;
    }
    else {
        Bye("No authentication provided");
    }
}


##  Send a file's contents to stdout
sub
cat
{
    my $name = pop();
    open(FH, $name) || Bye("Can't open $name, $!");
    print while (<FH>);
    close(FH);
}


# Using SSL?  This warning is too late, but hopefully educational.
Bye("You should use SSL to protect your password over the network")
    if $IBM
        and $ENV{"SERVER_SOFTWARE"} =~ /Apache/
        and not defined $ENV{"SSL_SESSION_ID"};

##  Get the form/request data and validate it.
Bye("No data available") unless param();
import_names("req");
Bye("Either server name or IP address must be provided")
    if $req::hostname eq "" and $req::ipaddr eq "";
Bye("Bad IP address given (e.g., not in internal IBM network)")
    if $IBM
        and $req::ipaddr ne ""
        and $req::ipaddr !~ /^9\.[0-9]{1,3}\.[0-9]{1,3}.[0-9]{1,3}$/;
Bye("Bad results type (must be screen or PKCS12)")
    if $req::results ne "p12" and $req::results ne "scr";
Bye("No login name provided") if $req::name eq "";
Bye("No password provided") if $req::pass eq "";
Authenticate($req::name, $req::pass);

##  Set up values for OpenSSL commands.
$req::hostname .= ".ibm.com"
    if $IBM
        and $req::hostname ne ""
        and $req::suffix eq "yes";
$ENV{"CN"} = $req::hostname ne "" ? $req::hostname : $req::ipaddr;
$ENV{"EMAILADDR"} = $req::name;
$ENV{"IPADDR"} = $req::ipaddr if $req::ipaddr ne "";
$extsect =  $req::ipaddr eq "" ? "cert_ext" : "cert_ipaddr_ext";

##  Generate keypair and cert request.
@args = ( "openssl", "req", "-batch",
    "-newkey", "rsa:1024", "-nodes",
    "-out", $reqfile, "-keyout", $keyfile );
$status = (system @args) >> 8;
Bye("Cert request failed") if $status != 0;

##  Sign the request, making a certificate.
if ( $lockit ) {
    open(LH, ">$lockfile") || Bye("cannot open lockfile $lockfile");
    flock(LH, LOCK_EX) || Bye("Cannot lock lockfile $lockfile");
}
@args = ( "openssl", "ca", "-batch",
    "-name", "pki_ca", "-extensions", $extsect,
    "-in", $reqfile, "-out", $certfile );
if ( $lockit ) {
    flock(LH, LOCK_UN);
    close(LH);
}
$status = (system @args) >> 8;
Bye("Cert generation failed") if $status != 0;

##  Generate the desired output.
if ( $req::results eq "scr" ) {
    my $t = "Certificate and Key";
    print header, start_html($t), h1($t), "\n<pre>\n";
    cat($certfile);
    print "\n";
    cat($keyfile);
    print "</pre>\n";
}
else {
    @args = ( "openssl", "pkcs12", "-export",
        "-nodes", "-password", "pass:",
        "-in", $certfile, "-inkey", $keyfile, "-out", $reqfile );
    $status = (system @args) >> 8;
    Bye("Generating PKCS12 file failed") if $status != 0;
    open(FH, $reqfile) || Bye("Can't open $reqfile, $!");
    binmode FH;
    my $buffer;
    read(FH, $buffer, 64 * 1024);
    close(FH);
    print "Content-Type: application/octet-stream\n",
         "Content-Disposition: inline; filename=\"ssl.p12\"\n",
         "\n",
         $buffer;
}

##  Cleanup and leave.
unlink $reqfile, $keyfile, $certfile;
exit 0;


##  Lint fluff.
$req::suffix = $req::suffix if 0;
