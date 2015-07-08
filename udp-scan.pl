#!/usr/bin/perl -w

#
# Credits:
#   http://korenofer.blogspot.ru/2009/02/simple-udp-port-scanner-in-perl-icmp_14.html
#

use strict;
use Net::Ping;
use IO::Select;
use IO::Socket::INET;
use NetPacket::IP;
use NetPacket::ICMP;


# IP address to scan
my $host = $ARGV[0] || '127.0.0.1';
my ( $first_port, $last_port ) = split( /-/, $ARGV[1] || '1-65535', 2 );

# Time to wait for the "destination unreachable" package.
my $timeout = int( $ARGV[2] || 2 );

# Buffer to send via UDP
my $hello = "Hello\n";


# First we will send a ping to make sure the scanned host is exist
my $ping = Net::Ping->new( "icmp", 1, 64 );

if ( defined $ping and $ping->ping( $host ) ) {
  print STDERR "$host recieved ICMP echo response, start scanning...\n";
} else {
  print STDERR "$host did not sent a response via ICMP\n";
  exit 1;
}

for my $port (int( $first_port) .. int( $last_port || $first_port ) ) {
  &check_udp( $host, $port )
    and printf "\t%-5d opened\n", $port;
}

exit 0;


sub check_udp($$) {
  my ( $host, $port ) = @_;
  

  # Create the icmp socket for the "destination unreachable" packages  
  my $icmp = IO::Socket::INET->new( Proto => "icmp" );

  # Create UDP socket to the remote  host and port
  my $udp = IO::Socket::INET->new
    (
      PeerAddr => $host,
      PeerPort => $port,
      Proto    => "udp",
    ) or die "Could not create UDP socket: $!";

  # Send the buffer and close the UDP socket.
  $udp->send( $hello );
  
  my $select = IO::Select->new();
  $select->add( $icmp );
  $select->add( $udp );

  # Set the arrival flag.
  my $icmp_arrived = 0;

  # For every socket we had received packets 
  # (In our case only one - icmp_socket)
  my $i = 1;
  do {
    # wait for packets
    sleep $timeout;

    my @done = $select->can_read( 0 );

    for my $socket ( @done ) {
      # If we have captured an icmp packages,
      # Its probably "destination unreachable"
      if ( $socket == $icmp ) {
        # Set the flag and clean the socket buffers

        $icmp->recv( my $packet, 64, 0 );
      
        my $p = NetPacket::ICMP->decode( &NetPacket::IP::strip( $packet ) );
        my ( $type, $code ) = @$p{ qw( type code ) };

        if ( $type == NetPacket::ICMP::ICMP_UNREACH
          && $code == NetPacket::ICMP::ICMP_UNREACH_PORT )
        {
          $icmp_arrived = 1;
        }
      }
    }
  } while ( $i-- >= 0 );

  close( $icmp );
  close( $udp );

  return $icmp_arrived ? 0 : 1;
}
