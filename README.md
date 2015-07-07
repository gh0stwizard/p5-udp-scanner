# Perl UDP Port Scanner #

This is a fork of the original Perl UDP Port Scanner written by 
[Ofer Koren](http://korenofer.blogspot.ru/2009/02/simple-udp-port-scanner-in-perl-icmp_14.html).


## Usage ##

```
Usage: udp-scan.pl [[ host ] [ port | start_port-end_port ] [timeout]]
```

For instance, to scan the port range from 1 to 1024 on example.com host:

```
shell> perl udp-scan.pl example.com 1-1024
```
