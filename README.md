# Simple DTLS-to-UDP proxy for your IoT cloud

This repo contains a simple proxy server (using `pion-dtls`) that accepts
DTLS-encrypted connections and relays the data to a plain-text UDP connection.

[Pion](https://github.com/pion/) was chosen due to

1. Being a pretty great library all-in-all, and
2. Having support for **DTLS Connection ID** which is a killer feature we
   outline briefly in a section below.


## Why is this useful?

For IoT projects, "we'll deal with security later" is a pretty common sentiment.
It's somewhat understandable - you wanna start hacking on the stuff you can demo
ASAP, because that's what impresses investors and managers. Rigorous security
isn't as demo-friendly as real-time data visualization or whatever.

In many cases, it ends up never happening because it turns out that duct taping
security onto an existing system is harder than one might suspect. For example,
you might realize too late that a particular feature you REALLY want isn't
supported by the DTLS library you intended to use. Are you going to rewrite your
server in another language, just to get access to the right DTLS library?

This is the problem this simple proxy server tries to solve - you can keep your
hacky plain-text server and simply add a sprinkling of DTLS to it by going

```
./dtls_proxy --bind 0.0.0.0:12345 --connect $ADDR:$PORT --psk-csv keys.csv
```

Where `$ADDR` and `$PORT` points to your plain-text server (clearly the
communication between the proxy and the plain-text server needs to be secured,
which is most easily solved by running them on the same machine).

In other words, you actually *can* duct-tape security onto your existing
architecture! The barrier of entry has never been lower! Yay!


## Key management integration

Iteration 1 of the proxy only supported the simplest KMS integration possible:
feeding the id/key pairs via a CSV file.

Experimental REST support is also available:

```
./dtls_proxy ... --psk-rest http://$KMS_SRV:$KMS_PORT/keys
```

The KMS service needs to expect a query parameter of the form
`pskId=SOME_STRING`. If it requires additional query parameters (such as API
key), you can piggyback that onto the URL like this:

```
--psk-rest http://$KMS_SRV:$KMS_PORT/keys?apiKey=7ad2d94771c9f11f26a51223cb0d0608
```

or whatever -- the final request will include both the `pskId=SOME_STRING` part
and the `apiKey=7ad2d94771c9f11f26a51223cb0d0608` part. The PSK should be
returned in the body as raw binary data (no content-type checking or anything
like that is done by the DTLS proxy).

### Best and simplest KMS integration method

```
./dtls_proxy ... --shell-kms-cmd /path/to/your/lookup/binary
```

Your lookup binary will be launched with the PSK ID as string arg and is
expected to return the corresponding PSK key in plain ASCII hex.

This binary can do whatever it wants, including random `curl` calls etc, so this
method actually contains REST lookup as a subset. This is the recommended
method.

## DTLS Connection ID

Network Address Translation (NAT) has been a HUGE blocker for cellular IoT for
many years now. This is because, traditionally, DTLS has used the client IP/port
to uniquely identify sessions which becomes problematic if your client wants to
sleep for any significant amount of time between transmissions.

Sleeping for more than a minute or so will cause NAT caches along the route
between client and server to get flushed due to inactivity. This means the
client IP/port suddenly changes from the server's perspective, which means the
established DTLS session suddenly becomes invalid, which means each device
uplink requires a new handshake... which means even a 50-byte message will incur
a mandatory overhead of up to 1500 bytes!

[RFC 9146](https://datatracker.ietf.org/doc/rfc9146/) solves this by using an
arbitrary but unique byte string to identify the session (negotiated with the
client during the handshake).

A simple concept, but rather ground-breaking in its practical implications for
cellular IoT, where data costs are measured in milli-cents and power consumption
is measured in micro-amps.


## Elektronikutvecklingsbyrån EUB AB

> Elektronikutvecklingsbyrån is a small team of experienced embedded developers
> who help idea holders in all stages of product development, from architecture,
> systemization and planning to circuit board design and firmware hacking.

We deeply feel that the large-scale collaboration enabled by open source is
transforming the way we do embedded. Our PCB:s are designed using KiCad, our
firmwares are running Zephyr RTOS or Linux and our development environments are
fetched using `apt`.

We try to upstream as much of our work as we possibly can, including this repo.
We hope you find it useful!

If you want to learn more of what we do and who we are, check out
[www.eub.se](https://www.eub.se/en).
