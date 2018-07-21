aidentd
=======

A somewhat anachronistic Ident daemon for Linux with support for forwarding
queries (including originating IP address) to hosts behind NAT.

The [Ident protocol](https://en.wikipedia.org/wiki/Ident_protocol) allows
a remote host to ask for the user id associated with another TCP connection
to that host from the Ident server. While this is generally considered
harmful nowadays, it is of some use in the case of IRC connections, since
most IRC servers still use Ident. As a general rule, if you don't know why
you would want this, you almost certainly don't, and should avoid installing
this software (or any like it).

NAT (i.e., multiple hosts on a LAN masquerading behind one public IP) causes
problems with Ident, since the request coming to the public IP needs to be
forwarded to the correct local IP. If there is only one "shell machine" on
the LAN, one might be tempted to forward the port (`113`) to its `identd`, but
also the source port (needed to identify the connection) may differ due to
NAT.

There are some other implementations that offer to solve this problem, but the
ones that I found were either massively bloated (e.g., per-user/network
configuration etc.) or oversimplified (using only the pair of ports to identify
connections, potentially leading to - mostly theoretical, but easily
reproducible - ambiguities). Furthermore, most of them use outdated approaches
for identifying connections, leading to incompatibilites with current Linux
kernels. In short, there wasn't an existing one that I both could and would
run on my EdgeRouter, so I decided to write my own.

~ [Kimmo Kulovesi](http://arkku.com/), 2018-07-21

Protocol Extension
==================

I've added a non-standard protocol extension: sending the original IP address
along with forwarded connections. This allows the forwarding target to more
accurately match the exact connection, but technically makes the query
incompatible with other implementations. In practice I believe most other
implementations will simply ignore it, and having it off is no worse than the
typical forwarding `identd`.

The extension is _off by default_, and enabled with the options `-A` (sending
IP when forwarding) and `-a` (accepting IP in incoming requests). Note that
running without this extension enabled means having to match requests behind
NAT based only on the pair of ports, which is what other implementations seem
to be doing. This also means that if an invalid IP address is sent to `aidentd`
with this extension enabled, it will still at most match the same connection
that would have been matched by the port pair alone. (That being said, the
scenario seems to imply that the malicious requests would come from the same
LAN, or they would be caught by the router.)

Example Flow
------------

An Ident request from the IRC server at `203.0.113.1` arrives to the `aidentd`
running on the router:

    12345,6667

The router determines that the requested connection originates from the
local computer with a LAN IP of `192.168.1.2`, from its port `56789`
which is masquareded as coming from the router's public IP and port `12345`.
The router connects to the host `192.168.1.2` on over the LAN from its
local IP `192.168.1.1` and sends a modified query:

    56789,6667 : 203.0.113.1

Note that the port has changed to account for the change, and the original
request's IP is sent in addition to the port-pair. Without the protocol
extension the `identd` at `192.168.1.2` would either incorrectly try to match
the connection with the router's LAN IP (`192.168.1.1`) and find no such
connection, or ignore the IP altogether and only match by the port pair.

Now, the other `aidentd` running on `192.168.1.2` can correctly match the
connection from its port `56789` to port `6667` on `203.0.113.1` and identify
the matching user to the router:

    56789,6667:USERID:UNIX:arkku

The router simply changes the ports to match those of the original query,
and replies to `203.0.113.1` with:

    12345,6667:USERID:UNIX:arkku

From the IRC server's point of view, both the query and response are exactly
the same as if the connection had actually come from a single host directly
connected to the internet.

Requirements
============

Currently (and probably forever) `aidentd` is only intended for relatively
modern Linux systems. However, other machines on the LAN can still run
other forwarding-compatible (or fixed-response) Ident servers with the
router running `aidentd`.

Beyond Linux, the required tools and libraries are:

* `inetd` (e.g., `openbsd-inetd`)
* `conntrack` (only for forwarding)
* `libcap` (and `libcap-dev` for compiling)

Installing requirements on Debian:

    sudo apt-get install build-essential libcap-dev conntrack openbsd-inetd

You may also use another `inetd` if you wish.

Building
========

It is recommended to compile with either GCC or clang, simply by running `make`.
You can also run `make install` to install the binary at `/usr/local/sbin/`. The
only build requirement beyond the standard libraries is `libcap-dev`.

Building on Debian:

    make
    sudo make install

Installation
============

For sake of simplicity and security, `aidentd` runs from `inetd` rather than
a daemon in itself. This allows using the chosen `inetd` for things like rate
limiting and access control. 

Forwarding requires using `conntrack`, which needs `CAP_NET_ADMIN`. For this
reason `aidentd` should normally be started as `root`, but it will drop all
other capabilities and switch to running as `nobody` _before reading input_.
Alternatively, one can set the capability `CAP_NET_ADMIN` on `aidentd` and
`conntrack` binaries with `setcap` beforehand, but this is largely the same
as just letting `aidentd` do it when run as `root`.

If forwarding is not used (option '-l'), it is also possible to run directly
as an unprivileged user.

Assuming a traditional-style `inetd`, add this service to `/etc/inetd.conf`:

    ident   stream  tcp     nowait  root /usr/local/sbin/aidentd aidentd

With some `inetd` versions you may also specify `tcp4` and `tcp6` to have
separate IPv4 and IPv6 configurations, respectively. IPv6 is supported by
`aidentd`.

Add any command-line arguments at the end of the line, e.g., `aidentd -Ai`.

The most relevant options are:

* `-l` – Local results only, i.e., disable forwarding. Use this option on
  everything that is _not_ a router with masquerading/NAT.
* `-f foo` – Reply to any non-forwarded queries with a fixed response.
  Use this option on routers that are _only_ expected to do forwarding,
  or hosts where you only even want to give a single response. (As
  a special case, specifying the response `?` causes the error
  `HIDDEN-USER` to be sent, which is better for multi-user than a
  single made-up username.)
* `-i` – IP on the connection must match that of the host asking. Enable
  this option only if all incoming queries come either without NAT,
  or you also specify the option `-a` and all forwarded NAT queries
  come from an `aidentd` also having the option `-a` or `-A`.
* `-A` — Enable the protocol extension of sending the original IP
  address when forwarding the request to a host behind NAT. This is
  non-standard and may cause problems when forwarding to other
  `identd` implementations behind NAT, but in practice many of them
  seem to just ignore the extra field and behave normally. This option
  should be enabled on hosts that forward requests to other `aidentd`
  (or compatible) instances behind NAT.
* `-a` – Enable receiving the original IP address in incoming queries.
  This is the recipient counterpart to `-A` described above, but has
  no compatibility implications on its own, since the reply format is
  unchanged. Without this option hosts behind NAT can not validate
  the IP address (and have to run without `-i`).

I also recommend using a firewall to limit access to the service,
only allowing the specific IRC and/or mail servers that you presumably
had in mind when deciding to install this in the first place. Any random
Ident queries these days are likely to be unwanted flood and scans...
If there are untrusted computers on the LAN, recipients of forwards could
also limit Ident access to the router sending the forwards, assuming Indent
isn't used inside the LAN (and it probably shouldn't be in such a case).

Example Configuration
---------------------

An example `/etc/inetd.conf` on a NAT router that receives the incoming
Ident queries from the internet, matches connections using their IP (`-i`),
has no local users and replies with the error `HIDDEN-USER` to any
queries that do not get a forwarded response (`-f ?`), and forwards the
original IP address to any masqueraded hosts without accepting one
in incoming queries (`-A`):

    ident   stream  tcp4    nowait  root /usr/local/sbin/aidentd aidentd -Aif ?

Note that since NAT is generally done only for IPv4, `tcp4` is used above to
specifically not listen on IPv6 – other hosts can receive their incoming
IPv6 connections directly and the router shouldn't have local IRC clients.

Another example of configuration on a machine behind NAT that receives
queries from the router configured as above with the original IP address
forwarded (`-a`), but does not forward queries itself (`-l`). The same
machine can also receive direct IPv6 connections (`tcp6`), for which it
matches connections using the direct IP address (`-i`).

    ident   stream  tcp4    nowait  nobody /usr/local/sbin/aidentd aidentd -al
    ident   stream  tcp6    nowait  nobody /usr/local/sbin/aidentd aidentd -il

Note that in this configuration `aidentd` can run as an unprivileged user
(`nobody`), since no forwarding is being done (`-l`). Starting it as `root`
isn't a problem, though, since the default is to drop from `root` to
`nobody` before even reading any input, so the only real difference is whether
it is done by `inetd` or `aidentd`.

Logging
=======

Since `inetd` typically also forwards `stderr` to the remote connection,
logging is done to the daemon syslog (often `/var/log/daemon.log` or
`/var/log/messages`). The default log level produces 1-3 lines per query,
and can be made considerable verbose by adding one or two `-v` options,
or more quiet by adding one or two `-q` options. With `-qq` only errors
are logged, and with `-vv` even debug info is logged with higher priority
to reduce the likelihood of it being filtered out by `syslogd`.

If there seems to be a problem that you can't see in the syslog even with
`-vv`, you can also try running `aidentd` directly with logging on
`stderr` (option `-e`), e.g.:

   echo '12345,6667' | sudo ./aidentd -evva

You can use `conntrack -L -p tcp` to find connections to test with.

Further Configuration
=====================

In addition to the primary options described earlier, there are some
others. They won't all be documented here – instead run `aidentd --help` to
see the up-to-date list from the program itself.

Some of the potentially more useful ones include:

* `-q` – log less information (can be repeated)
* `-v` – log more information (can be repeated)
* `-u user` and `-g group` – specify which user and group to drop to
  when started as `root`.
* `-c /path/to/conntrack` – required if your `conntrack` is not at
  the default `/usr/sbin/conntrack` location.
* `-t seconds` – sets the timeout in seconds for forwarded queries, etc.
  The default is 5 seconds, which is usually plenty with modern LAN
  and computer speeds, but if your forwards are slow then you may wish
  to increase this on the router (e.g., `-t 10`).

Future Development
==================

There are no planned future developments to bloat either the set of features
or configurability. In particular, no per-user or per-host custom responses
are forthcoming: not only do they significantly complicate the software,
but they also undermine what little usefulness there is left to Ident.

Returning hashed or otherwise obscured responses for all users could be
worth considering, but given that the primary use case of `aidentd` is to
get your proper username on IRC without the `~`, and most users of `identd`
probably have their Linux username as their IRC nick, the advantages of
that might be limited.

Anyway, I doubt there is much of an audience for a new `identd` in 2018
and beyond, but I will try to maintain this as needed for the latest stable
Debian and EdgeOS releases.
