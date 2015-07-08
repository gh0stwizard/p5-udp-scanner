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


# IP address and UDP port to scan
my $host = $ARGV[0] || '127.0.0.1';
my $port = $ARGV[1] || 53;

# Time to wait for the "destination unreachable" packet.
my $timeout = int( $ARGV[2] || 2 );

# String to send via UDP
my $hello = $ARGV[3] || "Hello\n";


&check_udp( $host, $port ) ? exit 0 : exit 1;


# ---------------------------------------------------------------------


sub check_udp($$) {
  my ( $host, $port ) = @_;
  

  # Create the icmp socket for the "destination unreachable" packages  
  my $icmp = IO::Socket::INET->new( Proto => "icmp" )
    or print( STDERR "ICMP socket: $!\n" ), exit 2;

  # Create UDP socket to the remote  host and port
  my $udp = IO::Socket::INET->new
    (
      PeerAddr => $host,
      PeerPort => $port,
      Proto    => "udp",
    ) or print( STDERR "UDP socket: $!\n" ), exit 2;

  # Send the buffer and close the UDP socket.
  $udp->send( $hello );
  
  my $select = IO::Select->new();
  $select->add( $icmp );
  $select->add( $udp );

  # Set the arrival flag.
  my $icmp_arrived = 0;

  # For every socket we had received packets 
  # (In our case only one - icmp_socket)
  
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
        last;
      }
    }
  }

  close( $icmp );
  close( $udp );

  return $icmp_arrived ? 0 : 1;
}
