# pytrace

A networking tool to perform route tracing.

```text
usage: pytrace [-h] [-s src_addr] [-f first_ttl] [-m max_ttl] [-p port] [-q nqueries]
               [-w waittime] [-z pausemsecs]
               host [packet_length]

positional arguments:
  host
  packet_length

options:
  -h, --help     show this help message and exit
  -s src_addr    Use the following IP address (which must be given as an IP number, not a
                 hostname) as the source address in outgoing probe packets. On hosts with
                 more than one IP address, this option can be used to force the source
                 address to be something other than the IP address of the interface the
                 probe packet is sent on. If the IP address is not one of this machine's
                 interface addresses, an error is returned and nothing is sent.
  -f first_ttl   Set the initial time-to-live used in the first outgoing probe packet. The
                 default is 1, .i.e., start with the first hop.
  -m max_ttl     Set the max time-to-live (max number of hops) used in outgoing probe
                 packets. The default is 64 hops.
  -p port        Sets the base port used in probes (default is 33434).
  -q nqueries    Set the number of queries per 'ttl' to nqueries (default is 3 probes)
  -w waittime    Set the time (in seconds) to wait for a response to a probe (default 5
                 sec.).
  -z pausemsecs  Set the time (in milliseconds) to pause between probes (default 0). Some
                 systems such as Solaris and routers such as Ciscos rate limit ICMP
                 messages. A good value to use with this is 500 (e.g. 1/2 second).
```
