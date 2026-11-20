#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;
use Cwd;
use File::Temp qw(tempdir);

# Interop tests: TLS listeners + SASL authentication, and their
# compatibility with the existing ascii and binary protocols.

if (!enabled_tls_testing()) {
    plan skip_all => 'SSL testing is not enabled';
    exit 0;
}

if (!supports_sasl()) {
    plan skip_all => 'SASL is not enabled';
    exit 0;
}

# Part 1: ascii protocol authentication (-Y authfile) over TLS and
# plaintext listeners of the same server.

my $plain_port = free_port();
my $ssl_port = free_port();

my $server = new_memcached("-Y $Bin/authfile -U 0 -l notls:127.0.0.1:$plain_port,127.0.0.1:$ssl_port", $ssl_port);
my $ssl_sock = $server->sock;
isa_ok($ssl_sock, 'IO::Socket::SSL', 'ascii: connected over TLS');

# Unauthenticated requests are rejected over TLS.
print $ssl_sock "get akey\r\n";
like(scalar <$ssl_sock>, qr/CLIENT_ERROR/, 'ascii/tls: get before auth is rejected');

# Authenticate over TLS using the authfile credentials.
print $ssl_sock "set foo 0 0 7\r\nfoo bar\r\n";
like(scalar <$ssl_sock>, qr/STORED/, 'ascii/tls: authenticated');

print $ssl_sock "set akey 0 0 5\r\nvalue\r\n";
like(scalar <$ssl_sock>, qr/STORED/, 'ascii/tls: set after auth');
mem_get_is($ssl_sock, 'akey', 'value', 'ascii/tls: get after auth');

# The plaintext listener speaks the same protocol: authenticate and
# read back the data written over TLS.
my $plain_sock = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$plain_port");
ok($plain_sock, 'ascii: connected to plaintext listener');

print $plain_sock "get akey\r\n";
like(scalar <$plain_sock>, qr/CLIENT_ERROR/, 'ascii/plain: get before auth is rejected');

print $plain_sock "set foo 0 0 7\r\nfoo bar\r\n";
like(scalar <$plain_sock>, qr/STORED/, 'ascii/plain: authenticated');
mem_get_is($plain_sock, 'akey', 'value', 'ascii/plain: reads data written over TLS');

print $plain_sock "set pkey 0 0 5\r\nplain\r\n";
like(scalar <$plain_sock>, qr/STORED/, 'ascii/plain: set after auth');
mem_get_is($ssl_sock, 'pkey', 'plain', 'ascii/tls: reads data written over plaintext');

# Part 2: binary protocol SASL (-S) over TLS and plaintext listeners.

my $saslpasswd_path;
for my $dir (split(/:/, $ENV{PATH}),
             "/usr/bin",
             "/usr/sbin",
             "/usr/local/bin",
             "/usr/local/sbin",
    ) {
    my $exe = $dir . '/saslpasswd2';
    if (-x $exe) {
        $saslpasswd_path = $exe;
        last;
    }
}

SKIP: {
    skip 'saslpasswd2 not available', 12 unless $saslpasswd_path;

    # Private SASL config/db so we can run in parallel with binary-sasl.t
    my $confdir = tempdir(CLEANUP => 1);
    my $sasldb = "$confdir/test.sasldb";
    open(my $fh, '>', "$confdir/memcached.conf") or die $!;
    print $fh "mech_list: plain\nlog_level: 5\nsasldb_path: $sasldb\n";
    close($fh);
    $ENV{'SASL_CONF_PATH'} = $confdir;

    my $sasl_realm = 'memcached.realm';
    system("echo testpass | $saslpasswd_path -a memcached -u $sasl_realm -c -p -f $sasldb testuser");

    my $bplain_port = free_port();
    my $bssl_port = free_port();

    my $bserver = new_memcached("-B binary -U 0 -S -l notls:127.0.0.1:$bplain_port,127.0.0.1:$bssl_port", $bssl_port);
    ok($bserver, 'binary: started TLS+SASL server');

    # Send a binary command, return (status, value) with extras stripped.
    my $bin_cmd = sub {
        my ($sock, $cmd, $key, $val, $extra) = @_;
        $extra ||= '';
        my $body = $extra . $key . $val;
        print $sock pack("CCnCCnNNNN", 0x80, $cmd, length($key),
                         length($extra), 0, 0, length($body), 0, 0) . $body;
        my $hdr;
        return unless read($sock, $hdr, 24) == 24;
        my @f = unpack("CCnCCnNNNN", $hdr);
        my $rlen = $f[6];
        my $rbody = '';
        while (length($rbody) < $rlen) {
            my $n = read($sock, my $buf, $rlen - length($rbody));
            last unless $n;
            $rbody .= $buf;
        }
        return ($f[5], substr($rbody, $f[3]));
    };

    my $sasl_auth = sub {
        my ($sock, $pass) = @_;
        my $msg = sprintf("%c%s@%s%c%s", 0, 'testuser', $sasl_realm, 0, $pass);
        my ($status) = $bin_cmd->($sock, 0x21, 'PLAIN', $msg);
        return $status;
    };

    my $bsock = $bserver->new_sock;
    isa_ok($bsock, 'IO::Socket::SSL', 'binary: connected over TLS');

    my ($status, $val) = $bin_cmd->($bsock, 0x20, '', '');
    is($status, 0, 'binary/tls: list mechs succeeds');
    like($val, qr/PLAIN/, 'binary/tls: PLAIN mech is listed');

    # Unauthenticated commands are rejected over TLS.
    ($status, $val) = $bin_cmd->($bsock, 0x01, 'bkey', 'bvalue', pack("NN", 0, 0));
    is($status, 0x20, 'binary/tls: set before auth is rejected');

    # Wrong password is rejected.
    $bsock = $bserver->new_sock;
    $status = $sasl_auth->($bsock, 'wrongpass');
    is($status, 0x20, 'binary/tls: bad password is rejected');
    $bsock = $bserver->new_sock;
    $status = $sasl_auth->($bsock, 'testpass');
    is($status, 0, 'binary/tls: authenticated');

    ($status, $val) = $bin_cmd->($bsock, 0x01, 'bkey', 'bvalue', pack("NN", 0, 0));
    is($status, 0, 'binary/tls: set after auth');

    # The plaintext binary listener speaks the same protocol: auth and
    # read back the data written over TLS.
    my $bpsock = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$bplain_port");
    ok($bpsock, 'binary: connected to plaintext listener');
    $status = $sasl_auth->($bpsock, 'testpass');
    is($status, 0, 'binary/plain: authenticated');
    ($status, $val) = $bin_cmd->($bpsock, 0x00, 'bkey', '');
    is($status, 0, 'binary/plain: get succeeds');
    is($val, 'bvalue', 'binary/plain: reads data written over TLS');
}

done_testing();
