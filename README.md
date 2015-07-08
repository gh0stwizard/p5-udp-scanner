# Perl UDP Port Scanner #

This is a fork of the original Perl UDP Port Scanner written by 
[Ofer Koren](http://korenofer.blogspot.ru/2009/02/simple-udp-port-scanner-in-perl-icmp_14.html).


## Usage ##

```
Usage: udp-scan.pl [[ host ] [ port ] [timeout] [greetings]]
```

For instance, to scan a host example.com, UDP port 123:

```
shell> perl udp-scan.pl example.com 123 && echo "opened" || echo "closed"
```

## Return codes ##

* <code>0</code> - port opened
* <code>1</code> - port closed
* <code>2</code> - probably permissions error

## Dependencies ##

* Net::Ping
* IO::Select
* NetPacket::IP
* NetPacket::ICMP
