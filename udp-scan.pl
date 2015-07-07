#!/usr/bin/perl

#
# http://korenofer.blogspot.ru/2009/02/simple-udp-port-scanner-in-perl-icmp_14.html
#

use Net::Ping;
use IO::Select;
use IO::Socket::INET;

# IP address to scan
my $ip = $ARGV[0] || '10.0.0.1';
my ( $first_port, $last_port ) = split( /-/, $ARGV[1] || '1-65535', 2 );

# First we will send a ping to make sure the scanned host is exist
my $p = Net::Ping->new( "icmp", 1, 64 );

if ( $p->ping($ip) ) {
  print "$ip ping-pong finished successfully\n";
} else {
  print "$ip did not answer ping\n";
  exit 5;
}

# Time  to wait for the "destination unreachable" package.
my $icmp_timeout = 2;

# Create the icmp socket for the "destination unreachable" packages  
$icmp_sock = IO::Socket::INET->new( Proto => "icmp" );
$read_set = IO::Select->new();
$read_set->add( $icmp_sock );

# Buffer to send via UDP
my $hello = "Hello\n";

# Scan all the ports .....
for ( $i = $first_port ; $i <= ( $last_port || $first_port ) ; $i++ ) {      # Create UDP socket to the remote  host and port
    my $udp = IO::Socket::INET->new
      (
        PeerAddr => $ip,
        PeerPort => $i,
        Proto    => "udp"
      )
    ;

    # Send the buffer and close the UDP socket.
    $udp->send( $hello );

    # Set the arrival flag.
    my $icmp_arrived = 0;

    # For every socket we had received packets (In our case only one - icmp_socket)
    my @done = $read_set->can_read( $icmp_timeout );

    for my $socket ( @done ) {
      # If we have captured an icmp packages, Its probably "destination unreachable"
      if ( $socket == $icmp_sock ) {
        # Set the flag and clean the socket buffers
        $icmp_arrived = 1;
        $icmp_sock->recv( $buffer, 50, 0 );
        last;
      }
    }

    if ( $icmp_arrived == 0 ) {
      printf "\t%-5d opened\n", $i;
    }

    $udp->close();
}

# Close the icmp sock
$icmp_sock->close();
exit 0;

