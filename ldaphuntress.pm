package LDAPHuntress;
#
# A simple LDAP server that proxies bind requests 
# across multiple LDAP providers.  
#
use strict;
use Net::LDAP;
use Data::Dumper;
use base 'Net::LDAP::Server';

# hashref containing LDAP host definitions keyed by DN.
my $providers = { 

	# an AD server running on localhost
	'dc=foo,dc=bar,dc=org' => {
		host	       => '127.0.0.1',
		search_port	   => 3268,
		modify_port    => 389,
		version        => 3,
		binddn         => 'foo_user@foo.bar.org',
		bindpw         => 'foo_pass',
		filter         => '(&(objectClass=organizationalPerson)(objectClass=user)(%s))',
		uid_field      => 'sAMAccountName',
	},

	# legacy domain with two AD servers
	'dc=legacy,dc=baz,=dc=com' => {
		host	       => 'ad1.legacy.baz.com,ad2.legacy.baz.com',
		search_port	   => 3268,
		modify_port    => 389,
		version        => 3,
		binddn         => 'legacy_user@legacy.baz.com',
		bindpw         => 'legacy_pass',
		filter         => '(&(objectClass=organizationalPerson)(objectClass=user)(%s))',
		uid_field      => 'sAMAccountName',
	},

	# OpenLDAP server for customers that authenticates with email addresses. 
	'dc=customers,dc=legacy,dc=baz,=dc=com' => {
		host	       => 'ext1.legacy.baz.com',
		search_port	   => 389,
		modify_port    => 389,
		version        => 3,
		binddn         => 'legacy_user@customer.baz.com',
		bindpw         => 'legacy_pass',
		filter         => '(&(objectclass=Customer)(%s))',
		uid_field      => 'mail',
	},
};

# set up some LDAP query return value constants
use constant RESULT_MISSING => {
	'matchedDN' => '',
	'errorMessage' => '',
	'resultCode' => Net::LDAP::Constant::LDAP_NO_SUCH_OBJECT
};
use constant RESULT_INVALID => {
	'matchedDN' => '',
	'errorMessage' => '',
	'resultCode' => Net::LDAP::Constant::LDAP_INVALID_CREDENTIALS
};
use constant RESULT_OK => {
	'matchedDN' => '',
	'errorMessage' => '',
	'resultCode' => Net::LDAP::Constant::LDAP_SUCCESS
};


sub bind {
	# Handle bind requests by iterating over every provider, 
	# and every host for every provider, and trying to find 
	# the specified user.
	#
	# We return success if we are able to bind using the 
	# specified user and password against any provider.
	
	my $self = shift;
	my $req  = shift;

	# TODO: support something other than simple auth
	my $user = $req->{'name'};
	my $pass = $req->{'authentication'}->{'simple'};

	# $user will either be a login or an LDAP object.  
	# If the latter, strip everything after the CN so we 
	# can search multiple directories without assuming a 
	# consistent organizational structure.
	$user =~ s/(CN=[^,]+).*/$1/i;

	# step through each LDAP provider and look for the user
	foreach my $key ( keys %$providers ) {
		my $conf = $providers->{ $key };	

		# Step through the comma-separated list of hosts for 
		# this provider definition, and try to connect. We 
		# stop as soon as we successfully connect to any host.
		my $con;
		foreach my $host ( split /\s*,\s*/, $conf->{'host'} ) {
			$con = Net::LDAP->new( $host,
				port    => $conf->{'search_port'}, 
				version => $conf->{'version'},
			);
			if ( ! defined( $con ) ) {
				print "$!\n";
				next;
			} else {
				print "Connected to ", $con->host(), "\n";
				last;
			}
		}

		# no connection? cannot search this provider.
		next unless $con;

		# bind to the ldap provider so we can search.
		my $res = $con->bind( $conf->{'binddn'}, password => $conf->{'bindpw'} );
		if ( $res->is_error ) {
			print "Could not bind as $conf->{'binddn'}: $res->error\n";
			return { 'error' => $res->error };
		}
	
		# search for the user we're trying to authenticate by preparing 
		# filter string.  If the user was specified as an LDAP object, 
		# we search for the CN.  Otherwise, we search only for objects 
		# where the provider's uid_field matches the username.
		my $filter;
		if ( $user =~ /^cn=/i ) {
			$filter = sprintf( $conf->{'filter'}, $user );
		} else {
			$filter = sprintf( $conf->{'filter'}, join( '=', $conf->{'uid_field'}, $user ) );
		}

		# Do the search.
		#print "base: $key, filter: $filter\n";
		$res = $con->search(
			base   => $key,
			filter => $filter,
			attrs  => [ '1.1' ],
		);
		if ( $res->is_error ) {
			print "Could not locate $user in $key: ", $res->error, "\n";
			next;
		} elsif ( $res->count == 0 ) {
			print "Could not locate $user in $key (no results).\n";
			next;
		}	

		# We found the user. Yay!  Now try to bind authenticate.
		my $entry = $res->entry(0);
		if ( exists $entry->{'asn'} ) {
			my $obj = $entry->{'asn'}->{'objectName'};
			print "Located $user in $key: ", $obj," ...";

			# try to bind as the object
			$res = $con->bind( $obj, password => $pass );
			if ( $res->is_error ) {
				print "Failed to bind as $user on ", $con->host(), ":", $res->error,"\n";

				# many Active Directory servers have an account lockout policy for 
				# multiple consecutive failed authentication attempts.  We don't want 
				# to lock an account in another AD because the user might be sending 
				# valid creds for another AD, so we force the lockoutTime back to 0.
				#
				my $unlockcon = Net::LDAP->new( $con->host(),
					port    => $conf->{'modify_port'},
					version => $conf->{'version'},
				);
				$res = $unlockcon->bind( $conf->{'binddn'}, password => $conf->{'bindpw'} );
				$res = $unlockcon->modify( $obj, replace => { lockoutTime => 0 } );	
				if ( $res->is_error ) {
					print "Failed to set lockoutTime=0 for $user: ", $res->error, "\n";
				}
				$unlockcon->unbind;
				next;

			} else {
				print "Authenticated!\n";
				return RESULT_OK;
			}
		} else {
			print "Couldn't parse entry: ", Dumper( $entry );
			next;
		}
	}
	print "BIND: Could not bind as $user on any ldap host.\n";
	return RESULT_INVALID;
	
}
sub search {
	# This routine only provides the most basic of search functions, 
	# enough to get by with LDAP clients that search for a user 
	# before trying to authenticate.  It is *not* a generic search 
	# proxy function.
	#
	# We treat every serach as a search for a username.
	#
	
	my $self = shift;
	my $req  = shift;

	my $res;

	# we only process equality searches
	my $username = $req->{'filter'}->{'equalityMatch'}->{'assertionValue'};
	return RESULT_OK, { error => "Invalid query" }
		unless $username;

	# Our search base DN is a semicolon-separated list of DNs.
	my @entries;
	foreach my $basedn ( map { lc } split /;/, $req->{'baseObject'} ) {
	
		print "Searching for $username in $basedn...";
	
		# the specified base DN must be one of our providers.
		if ( ! exists $providers->{ $basedn } ) {
			print "Invalid DN ($basedn); rejecting query.\n";
			return RESULT_OK, { denied => 1 };
		}
	
		my $conf = $providers->{ $basedn };
	
		# bind to the provider using the first host we  can connect to.
		my $con;
		foreach my $host ( split /\s*,\s*/, $conf->{'host'} ) {
			$con = Net::LDAP->new( $host,
				port => $conf->{'search_port'}, 
				version => $conf->{'version'},
			);
			if ( ! defined( $con ) ) {
				print "$!\n";
				next;
			} else {
				print "Connected to ", $con->host(), "\n";
				last;
			}
		}
		next unless $con;
		$res = $con->bind( $conf->{'binddn'}, password => $conf->{'bindpw'} );
		if ( $res->is_error ) {
			print "Could not bind as $conf->{'binddn'}: $res->error\n";
			return { 'error' => $res->error };
		}
	
		# build a search query from the query the client sent us.
		# Since we assume every search is a username search, we build a 
		# filter using the provider's uid_field .
		my $search = $con->search( 
			base	=> $basedn,
			scope	=> $req->{'scope'},
			filter  => sprintf( $conf->{'filter'}, join( '=', $conf->{'uid_field'}, $username ) ), 
			attrs	=> $req->{'attributes'},
		);
		if ( $search->is_error ) {
			print $search->error, "\n";

		} elsif ( $search->count == 0 ) {
			print "No results\n";

		} else {
			print "Found!\n";
			push @entries, $search->entries;
		}
	}

	return RESULT_MISSING unless @entries;

	# return *all* matching objects from all providers
	print "Returning ", scalar @entries, " matches.\n";
	return RESULT_OK, @entries;
}

1;
