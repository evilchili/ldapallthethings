#!/usr/bin/env perl
#
# an example LDAP client script that authenticates
# a username and password using ldapallthethings.
#
use strict;
use Authen::Simple::LDAP;
use Term::ReadKey;

# list of DNs to search; must have matching 
# providers defined in ldaphuntress.pm
my $dn = join ';', qw(
	DC=foo,DC=bar,DC=org
	DC=legacy,DC=baz,DC=com
);

# where is ldapallthethings running?
my $host   = '127.0.0.1';
my $port   = 52323;
my $binddn = 'proxyuser';
my $bindpw = 'proxypass';

# get the username and password from the user
my $user = '';
my $pass = '';
print "Username: ";
chomp( $user = <STDIN> );
print 'Password: ';
ReadMode('noecho');
chomp( $pass = ReadLine(0) );
ReadMode('restore');
print "\n";

# give 'er
my $ldap = Authen::Simple::LDAP->new( 
	host    => $host,
	basedn  => $dn,
	port    => $port,
	binddn  => $binddn,
	bindpw  => $bindpw,
	filter  => '(uid=%s)'
);
$ldap->authenticate( $user, $pass )
	or die "Could not authenticate as $user on any provider.\n";

print "Success!\n";
exit 0;
