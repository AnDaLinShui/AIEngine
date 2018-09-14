AIEngine (Artificial Intelligent Engine)
==========================
AIEngine is a next generation interactive/programmable Python/Ruby/Java/Lua and Go network intrusion detection system engine with capabilities of learning without any human intervention, DNS domain classification, Spam detection, network collector, network forensics and many others.

AIEngine also helps network/security professionals to identify traffic and develop signatures for use them on NIDS, Firewalls, Traffic classifiers and so on.

Main Functionalities
==========
 - Write MORE Tests
 - Add Night Mode
 - Support for interacting/programing with the user while the engine is running.
 - Support for PCRE JIT for regex matching.
 - Support for regex graphs (complex detection patterns).
 - Support six types of NetworkStacks (lan, mobile, lan6, virtual, oflow and mobile6).
 - Support Sets and Bloom filters for IP searches.
 - Supports x86_64, ARM and MIPS architecture over operating systems such as Linux, FreeBSD and MacOS.
 - Support for HTTP, DNS and SSL Domains matching.
 - Support for banned domains and hosts for HTTP, DNS, SMTP and SSL.
 - Frequency analysis for unknown traffic and auto-regex generation.
 - Generation of Yara signatures.
 - Easy integration with databases (MySQL, Redis, Cassandra, Hadoop, etc...) for data correlation.
 - Easy integration with other packet engines (Netfilter).
 - Support memory clean caches for refresh stored memory information.
 - Support for detect DDoS at network/application layer.
 - Support for rejecting TCP/UDP connections.
 - Support for network forensics on real time.
 - Supports protocols such as Bitcoin, CoAP, DHCPv4/DHCPv6, DNS, GPRS, GRE, HTTP, ICMPv4/ICMPv6, IMAP, IPv4/v6, Modbus, MPLS, MQTT, Netbios, NTP, OpenFlow, PPPoE, POP, Quic, RTP, SIP, SMB, SMTP, SSDP, SSH, SSL, TCP, UDP, VLAN, VXLAN.


How to use
==========
To use AIEngine(reduce version) just execute the binary aiengine or use the python/ruby/java/lua binding.

```
luis@luis-xps:~/c++/aiengine/src$ ./aiengine -h
aiengine 1.9.0
Mandatory arguments:
  -I [ --input ] arg                Sets the network interface ,pcap file or
                                    directory with pcap files.

Link Layer optional arguments:
  -q [ --tag ] arg      Selects the tag type of the ethernet layer (vlan,mpls).

TCP optional arguments:
  -t [ --tcp-flows ] arg (=32768) Sets the number of TCP flows on the pool.

UDP optional arguments:
  -u [ --udp-flows ] arg (=16384) Sets the number of UDP flows on the pool.

Regex optional arguments:
  -R [ --enable-signatures ]     Enables the Signature engine.
  -r [ --regex ] arg (=.*)       Sets the regex for evaluate agains the flows.
  -c [ --flow-class ] arg (=all) Uses tcp, udp or all for matches the signature
                 on the flows.
  -m [ --matched-flows ]         Shows the flows that matchs with the regex.
  -M [ --matched-packet ]        Shows the packet payload that matchs with
                                 the regex.
  -C [ --continue ]              Continue evaluating the regex with the
                                 next packets of the Flow.
  -j [ --reject-flows ]          Rejects the flows that matchs with the
                                     regex.
  -w [ --evidence ]              Generates a pcap file with the matching
                                     regex for forensic analysis.

Frequencies optional arguments:
  -F [ --enable-frequencies ]       Enables the Frequency engine.
  -g [ --group-by ] arg (=dst-port) Groups frequencies by src-ip,dst-ip,src-por
                    t and dst-port.
  -f [ --flow-type ] arg (=tcp)     Uses tcp or udp flows.
  -L [ --enable-learner ]           Enables the Learner engine.
  -k [ --key-learner ] arg (=80)    Sets the key for the Learner engine.
  -b [ --buffer-size ] arg (=64)    Sets the size of the internal buffer for
                                    generate the regex.
      -Q [ --byte-quality ] arg (=80)   Sets the minimum quality for the bytes of
                                        the generated regex.
  -y [ --enable-yara ]              Generates a yara signature.

Optional arguments:
  -n [ --stack ] arg (=lan)    Sets the network stack (lan,mobile,lan6,virtual,
                   oflow).
  -d [ --dumpflows ]           Dump the flows to stdout.
  -s [ --statistics ] arg (=0) Show statistics of the network stack (5 levels).
  -T [ --timeout ] arg (=180)  Sets the flows timeout.
  -P [ --protocol ] arg        Show statistics of a specific protocol of the
                                   network stack.
  -e [ --release ]             Release the caches.
  -l [ --release-cache ] arg   Release a specific cache.
  -p [ --pstatistics ]         Show statistics of the process.
      -o [ --summary ]             Show protocol summmary statistics
                                   (bytes,packets,% bytes,cache miss,memory).
  -h [ --help ]                Show help.
  -v [ --version ]             Show version string.
```

### NetworkStack types

AIEngine supports six types of Network stacks depending on the network topology.

* StackLan (lan) Local Area Network based on IPv4.

* StackLanIPv6 (lan6) Local Area Network with IPv6 support.

* StackMobile (mobile) Network Mobile (Gn interface) for IPv4.

* StackVirtual (virtual) Stack for virtual/cloud environments with VxLan and GRE Transparent.

* StackOpenFlow (oflow) Stack for openflow environments.

* StackMobileIPv6 (mobile6) Network Mobile (Gn interface) for IPv6.

### Integrating/Program AIEngine with other systems
AIEngine is a python/ruby/java/lua module also that allows to be more flexible in terms of integration with other systems and functionalities. The main objects that the python module provide export are the following ones.
```
BitcoinInfo
CoAPInfo
DCERPCInfo
DHCPInfo
DHCPv6Info
DNSInfo
DatabaseAdaptor (Abstract class)
DomainName
DomainNameManager
Flow
FlowManager
Frequencies
FrequencyGroup
HTTPInfo
HTTPUriSet
IMAPInfo
IPAbstractSet (Abstract class)
    IPSet
IPSetManager
LearnerEngine
MQTTInfo
NetbiosInfo
NetworkStack (Abstract class)
    StackLan
    StackLanIPv6
    StackMobile
    StackOpenFlow
    StackVirtual
    StackMobileIPv6
POPInfo
PacketDispatcher
PacketFrequencies
Regex
RegexManager
SIPInfo
SMBInfo
SMTPInfo
SSDPInfo
SSLInfo
```
For a complete description of the class methods in Python

```
import pyaiengine
help(pyaiengine)
```

Check the directory examples in order to have useful use cases, and check /docs for documentation


## Compile AIEngine binary
You should have installed pcre-devel, libpcap-devel and boost-devel in your system as minimun.
```
$ git clone https://github.com/ryadpasha/ai-engine
$ ./autogen.sh
$ ./configure
$ make
```

## Optional features
The system provides the following enable/disable functionalities depending your requirements.

* enable-tcpqos Enable TCP QoS Metrics support for measure the QoS of connections.
* enable-bloomfilter Enable bloom filter support for IP lookups. This option should have the correct libraries.
* enable-reject Enable TCP/UDP reject connection support for break establish connections on StackLans and StackLanIPv6 objects.
* enable-pythongil Enable Python Gil support for multithreading applications.
* enable-static-memory Enable static/fixed memory support for systems with low memory requirements (256 Bytes slot).
* enable-code-coverage Enable code coverage support (develop).
* enable-sanatizer Enable sanatizer tests support (develop).
This options only can be enable/disable on compilation time on the configure script.

## Compile AIEngine Python library
For compile the Python library is also recomended boost-python3-devel or boost-python-devel and python-devel.

The first option for compile the library is using O3 compile optimization, this will generate a small library

```
$ git clone https://github.com/ryadpasha/ai-engine
$ ./autogen.sh
$ ./configure
$ cd src
$ make python
$ python pyai_test.py
```

The second option will compile the library by using the standard pythonic way by using setup.py, this will generate a bigger library size if compare with the previous one.

```
$ git clone https://github.com/ryadpasha/ai-engine
$ ./autogen.sh
$ ./configure
$ cd src
$ python setup.py build_ext -i
$ python pyai_test.py
$ python3.6 setup.py build_ext -i
$ python3.6 pyai_test.py
```

The python lib contains all the functionality that the engine provides.

## Contributing to AIEngine
AIEngine is develop with c++11/14 standard and is under the terms of GPLv2.

Check out the AIEngine source with

```
$ git clone https://github.com/ryadpasha/ai-engine
```

If you are interested in a specific functionality, promote the project or just need some help just drop me an email. Contributions are always helpful.

## Develop new functionality
AIEngine have been develop using test driven development. So in order to maintain the same life cycle, the new functionatly should have unit test on the directory created of the new functionality and for integrate with all the system, later integrate with the main tests.cc file on the /src directory

## Discussion
If you have questions or problems with installation or usage [create an Issue](https://github.com/ryadpasha/aiengine).

For any queries contact me at: **me@ryadpasha.com**
