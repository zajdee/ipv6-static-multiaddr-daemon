## RA-assisted IPv6 static address deprecation daemon

Have you ever wondered how to:

1. deploy IPv6 on a LAN
2. deploy independent prefixes from two or more ISPs on a shared LAN
3. use statically assigned IPv6 addresses on a server, one or more address per each ISP
4. allow incoming traffic to all the assigned addresses
5. select one of the ISPs to be *active* and the other(s) to act as *stand-by* ISP(s)
5. automagically control which ISP is used for outbound traffic originated on the server with the static assignments
6. **all of the above together?**

Wonder no more! Here's *the* solution to this problem.

### What's the ideal network set-up for the script to run?

The script's ideal environment is when it runs on a host in the multihomed infrastructure similar to [RFC 7157, Section 3.1, Scenario 2](https://datatracker.ietf.org/doc/html/rfc7157#section-3.1). This time, we view the 

```
                                           ___________
                     +-----+ DelegatedA   /           \
                     |     | - - - - - - /   network   \
          PfxA       |     | port1       \      1      /
+-------+ PrefLft==0 |     |              \___________/
|       |            |     |
| hosts |------------| GW  |
|       | PfxB       | rtr |
+-------+ PrefLft>0  |     |               ___________
                     |     | port2        /           \
                     |     | ============/   network   \
                     +-----+ DelegatedB  \      2      /
                                          \___________/
```

The gateway router in the example:

- has two IPv6 uplinks with two delegated prefixes (`DelegatedA` and `DelegatedB`)
- builds `PfxA` from the `DelegatedA`, e.g. picks a /64 from the delegated `/56`
- builds `PfxB` from the `DelegatedB`, e.g. picks a /64 from the delegated `/48`
- has a shared LAN segment to which end hosts connect
- selects one of the uplinks and prefixes (here: `PfxB`) as *active*, the other one (here: `PfxA`) as *stand-by*
- sets the *active* prefix' (here: `PfxB`) `PreferredLifetime` in the Router Advertisement Prefix information to a **value greater than zero (`0`)**; the router should follow the rule defined in [RFC 9096, Section 3, requirement L-15](https://datatracker.ietf.org/doc/html/rfc9096#section-3).
- sets the *inactive* prefix' (here: `PfxA`) `PreferredLifetime` in the Router Advertisement Prefix information to a **value equal to zero (`0`)**
- includes all the relevant (prefixes), in this case `PfxA` and `PfxB` in all Router Advertisements

You **need to advertise all prefixes from all the ISPs** for this to work as expected. The preferred (active) ISP is then used for outgoing connections on  hosts using SLAAC (as the prefix with `PreferredLifetime` set to zero causes SLAAC address deprecation and deprecated addresses are not used for outgoing traffic), but there wasn't a good solution for the statically addressed hosts - until now.

### What can you find here and how does it work

We proudly present the *RA-assisted IPv6 static address deprecation daemon* for GNU/Linux.

What does it do? Well, it listens for incoming router advertisements (you don't need to have SLAAC enabled on the machine) and based on the `PreferredLifetime` of each of the prefixes in the RA it then either:

- *deprecates* a static IPv6 address (sets the `preferred lifetime` of such address to zero), if the `PreferredLifetime` of the prefix in the RA equals to zero, or
- sets the `preferred lifetime` of a static IPv6 address to *forever*, if the `PreferredLifetime` of the prefix in the RA equals to a non-zero value

In both cases, the **valid lifetime** values of static addresses are set to `forever`.

### How to run the script

You need Python 3 (which is assumed), and `scapy`. Install the dependencies using:

```
pip3 install -r requirements.txt
```

The interface needs to be specified as a script argument, e.g. for `eth0` use:

```
python3 static-multiaddr-daemon.py -i eth0
```
