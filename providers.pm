package providers;
use strict;

our $dn = { 

    # an AD server running on localhost
    'dc=foo,dc=bar,dc=org' => {
            host           => '127.0.0.1',
            search_port    => 3268,
            modify_port    => 389,
            version        => 3,
            binddn         => 'foo_user@foo.bar.org',
            bindpw         => 'foo_pass',
            filter         => '(&(objectClass=organizationalPerson)(objectClass=user)(%s))',
            uid_field      => 'sAMAccountName',
            unlock         => 1,
    },

    # legacy domain with two AD servers
    'dc=legacy,dc=baz,=dc=com' => {
            host           => 'ad1.legacy.baz.com,ad2.legacy.baz.com',
            search_port    => 3268,
            modify_port    => 389,
            version        => 3,
            binddn         => 'legacy_user@legacy.baz.com',
            bindpw         => 'legacy_pass',
            filter         => '(&(objectClass=organizationalPerson)(objectClass=user)(%s))',
            uid_field      => 'sAMAccountName',
            unlock         => 1,
    },

    # OpenLDAP server for customers that authenticates with email addresses. 
    'dc=customers,dc=legacy,dc=baz,=dc=com' => {
            host           => 'ext1.legacy.baz.com',
            search_port    => 389,
            version        => 3,
            binddn         => 'legacy_user@customer.baz.com',
            bindpw         => 'legacy_pass',
            filter         => '(&(objectclass=Customer)(%s))',
            uid_field      => 'mail',
            unlock         => 0, # do not try to unlock accounts
    },
};


1;
