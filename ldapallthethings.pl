#!/usr/bin/perl

use strict;
use Data::Dumper;
use FindBin;
use lib "$FindBin::Bin";
require ldaphuntress;

my $port = 52323;
  
# set up a daemon that will handle incoming LDAP queries
package listener;
use Net::Daemon;
use base 'Net::Daemon';
sub Run {
	my $self = shift;
	my $handler = LDAPHuntress->new( $self->{'socket'} );
	while (1) {
		my $finished = $handler->handle;
		if ($finished) {
			$self->{'socket'}->close;
			return;
		}
	}
}

# start listening
package main;

my $server = listener->new({
	localaddr => '127.0.0.1',
	localport => $port,
	pidfile   => 'none',
	mode      => 'fork',
}, \@ARGV);
$server->Bind;

1;
