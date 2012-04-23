package LDAPHuntress;
#
# A simple LDAP server that proxies bind requests 
# across multiple LDAP providers.  
#
use strict;
use Net::LDAP;
use Data::Dumper;
use base 'Net::LDAP::Server';
use base 'providers';

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
	foreach my $key ( keys %$providers::dn ) {
		my $conf = $providers::dn->{ $key };	

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
			print "Could not bind as $conf->{'binddn'}: ", $res->error, "\n";
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

				next unless $conf->{'unlock'};

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

	# some LDAP clients will construct an equality match with multiple 
	# (empty) assertions.  We step through them and look for the uid. 
	# Note that this has the effect of *ignoring* other assertions!
	#
	# Works for apache's mod_auth_ldap thus:
	#
	# AuthLDAPURL "ldap://127.0.0.1:52323/DC=foo,DC=org;DC=bar,DC=org?uid" NONE
	#
	if ( ! $username && exists $req->{'filter'}->{'and'} ) {
		foreach my $clause ( @{ $req->{'filter'}->{'and'} } ) {
			if ( exists $clause->{'equalityMatch'} && $clause->{'equalityMatch'}->{'attributeDesc'} eq 'uid' ) {
				$username = $clause->{'equalityMatch'}->{'assertionValue'};
				last;
			}
		}
	}
	return RESULT_INVALID
		unless $username;

	# Our search base DN is a semicolon-separated list of DNs.
	my @entries;
	foreach my $basedn ( map { lc } split /;/, $req->{'baseObject'} ) {
	
		print "Searching for $username in $basedn...";
	
		# the specified base DN must be one of our providers.
		if ( ! exists $providers::dn->{ $basedn } ) {
			print "Invalid DN ($basedn); rejecting query.\n";
			return RESULT_OK, { denied => 1 };
		}
	
		my $conf = $providers::dn->{ $basedn };
	
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

	# We should return *all* matching objects from all providers,
	# but this will generate a "user is not unique!" error in apache's
	# mod_auth_ldap, so we only return the first one.
	print "Returning ", scalar @entries, " matches.\n";
	return RESULT_OK, $entries[0];
}

1;
