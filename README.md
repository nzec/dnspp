# dnspp

Following [Implement DNS in a weekend](https://implement-dns.wizardzines.com/) in C++

Uses [ASIO](https://think-async.com/) for sending and receiving UDP packets.

## Running

```
$ git clone https://github.com/nzec/dnspp && cd dnspp
$ cmake -S . -B build
$ cmake --build build/
$ ./build/dnspp x.com
Querying 198.41.0.4 for x.com
Querying 192.41.162.30 for x.com
Querying 198.41.0.4 for a.u10.twtrdns.net.
Querying 192.55.83.30 for a.u10.twtrdns.net.
Querying 205.251.195.207 for a.u10.twtrdns.net.
Querying 204.74.66.101 for x.com
IPv4 Address found: 104.244.42.1
```
