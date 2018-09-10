Injecting code on the engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

One of the cool features of the engine is the ability to change the behavior while is executing. This means that you can reprogram the behavior
of the engine and inject on them new code with new intelligence that allows you to deal with new types of attacks with no reloads and restarts of the engine.
The best way to understand this feature is by having a proper example.
We load the library and create a StackLan object with some memory requirements.

.. code:: python

  import pyaiengine

  s = pyaiengine.StackLan()

  s.tcp_flows = 32768
  s.udp_flows = 56384

Just for the example we are going to create 3 DNS rules for handling queries.

.. code:: python

  d1 = pyaiengine.DomainName("Generic net queries",".net")
  d2 = pyaiengine.DomainName("Generic com queries",".com")
  d3 = pyaiengine.DomainName("Generic org queries",".org")

  dm = pyaiengine.DomainManager()

  """ Add the DomainName objects to the manager """
  dm.add_domain_name(d1)
  dm.add_domain_name(d2)
  dm.add_domain_name(d3)

  st.set_domain_name_manager(dm,"DNSProtocol")

Now we open a new context of a PacketDispatcher and enable the shell for interacting with the engine.

.. code:: python

  with pyaiengine.PacketDispatcher("enp0s25") as pd:
      pd.stack = st
      """ We enable the shell for interact with the engine """
      pd.enable_shell = True
      pd.run()

If we execute this code we will see the following messages.

.. code:: bash

  [luis@localhost ai]$ python example.py
  [09/30/16 21:48:41] Lan network stack ready.
  AIEngine 1.6 shell
  [09/30/16 21:48:41] Processing packets from device enp0s25
  [09/30/16 21:48:41] Stack 'Lan network stack' using 51 MBytes of memory

  >>>

Now we are under control of the internal shell of the engine and we can access to the different
components.

.. code:: bash

  >>> print(dm)
  DomainNameManager (Generic Domain Name Manager)
          Name:Generic net queries      Domain:.net     Matchs:10
          Name:Generic org queries      Domain:.org     Matchs:0
          Name:Generic com queries      Domain:.com     Matchs:21

  >>>

And now we inject a callback function for one of the given domains.

.. code:: bash

  >>> def my_callback(flow):
  ...   d = flow.dns_info
  ...   if (d):
  ...     print(str(d))
  ...
  >>> d3.callback = my_callback
  >>>


And wait for domains that ends on .org

.. code:: bash

  >>>  Domain:www.gnu.org

also verify the rest of the components

.. code:: bash

  >>> print(d2)
  Name:Generic org queries      Domain:.org     Matchs:1        Callback:<function my_callback 0x023ffeea378>
  >>> dm.show()
  DomainNameManager (Generic Domain Name Manager)
          Name:Generic net queries      Domain:.net     Matchs:14
          Name:Generic org queries      Domain:.org     Matchs:1        Callback:<function my_callback 0x023ffeea378>
          Name:Generic com queries      Domain:.com     Matchs:21

Check the global status by executing the method show_protocol_statisitics

.. code:: bash

  >>> st.show_protocol_statistics()
  Protocol statistics summary
	Protocol       Bytes      Packets  % Bytes  CacheMiss  Memory      UseMemory    CacheMemory   Dynamic  Events
	Ethernet       3030778    11681    100      0          192 Bytes   192 Bytes    0 Bytes       no       0
	VLan           0          0        0        0          192 Bytes   192 Bytes    0 Bytes       no       0
	MPLS           0          0        0        0          192 Bytes   192 Bytes    0 Bytes       no       0
	IP             2642875    9356     87       0          216 Bytes   216 Bytes    0 Bytes       no       0
	TCP            1388303    5224     45       210        9 KBytes    44 KBytes    0 Bytes       yes      0
	UDP            977364     4112     32       436        312 Bytes   116 KBytes   0 Bytes       yes      12
	ICMP           0          17       0        0          224 Bytes   224 Bytes    0 Bytes       no       0
	HTTP           0          0        0        0          800 Bytes   800 Bytes    0 Bytes       yes      0
	SSL            1012883    1779     33       0          12 KBytes   8 KBytes     1 KBytes      yes      0
	SMTP           0          0        0        0          440 Bytes   440 Bytes    0 Bytes       yes      0
	IMAP           0          0        0        0          376 Bytes   376 Bytes    0 Bytes       yes      0
	POP            0          0        0        0          376 Bytes   376 Bytes    0 Bytes       yes      0
	Bitcoin        0          0        0        0          240 Bytes   240 Bytes    0 Bytes       yes      0
	Modbus         0          0        0        0          232 Bytes   232 Bytes    0 Bytes       no       0
	MQTT           0          0        0        0          344 Bytes   344 Bytes    0 Bytes       yes      0
	TCPGeneric     173981     491      5        0          216 Bytes   216 Bytes    0 Bytes       no       0
	TCPFrequency   0          0        0        0          248 Bytes   248 Bytes    0 Bytes       yes      0
	DNS            174666     748      5        0          24 KBytes   20 KBytes    3 KBytes      yes      3
	SIP            0          0        0        0          576 Bytes   576 Bytes    0 Bytes       yes      0
	DHCP           21704      72       0        0          1 KBytes    1 KBytes     0 Bytes       yes      0
	NTP            0          0        0        0          224 Bytes   224 Bytes    0 Bytes       no       0
	SNMP           0          0        0        0          224 Bytes   224 Bytes    0 Bytes       no       0
	SSDP           1368       8        0        0          752 Bytes   752 Bytes    0 Bytes       yes      0
	Netbios        85897      1231     2        0          3 KBytes    2 KBytes     199 Bytes     yes      0
	CoAP           0          0        0        0          1 KBytes    1 KBytes     0 Bytes       yes      0
	RTP            0          0        0        0          216 Bytes   216 Bytes    0 Bytes       no       0
	Quic           558927     853      18       0          192 Bytes   192 Bytes    0 Bytes       no       0
	UDPGeneric     134802     764      4        0          216 Bytes   216 Bytes    0 Bytes       no       0
	UDPFrequency   0          0        0        0          248 Bytes   248 Bytes    0 Bytes       yes      0
	Total          3030778    11681    100      646        59 KBytes   203 KBytes   5 KBytes               15


Check the anomalies of the engine by executing the show_anomalies stack method

.. code:: bash

  >>> st.show_anomalies()
  Packet Anomalies 
	Total IPv4 Fragmentation:        0
	Total IPv6 Fragmentation:        0
	Total IPv6 Loop ext headers:     0
	Total TCP bad flags:             0
	Total TCP bogus header:          0
	Total UDP bogus header:          0
	Total DNS bogus header:          0
	Total DNS long domain name:      0
	Total SMTP bogus header:         10
	Total IMAP bogus header:         0
	Total POP bogus header:          0
	Total SNMP bogus header:         0
	Total SSL bogus header:          12 Callback:<function anomaly_callback at 0x7f94bf012e60>
	Total HTTP malformed URI:        32 Callback:<function anomaly_callback at 0x7f94bf012e60>
	Total HTTP no headers:           0 Callback:<function anomaly_callback at 0x7f94bf012e60>
	Total CoAP bogus headers:        0
	Total RTP bogus headers:         0
	Total MQTT bogus headers:        0
	Total Netbios bogus headers:     0
	Total DHCP bogus headers:        0

On the other hand, you can use a remote shell for sending commands to the engine

.. code:: python

  with pyaiengine.PacketDispatcher("enp0s25") as pd:
      pd.stack = st
      pd.port = 3000 
      pd.run()

The parameter port will open a UDP socket and will execute the commands recevied over that socket. This will allow 
to receive programable instructions to the engine remotely or by other program, for example an UI.

You can also create a string with python code that will be injected on the engine when you want, for example:

.. code:: python

   """ Create a string with the code want to executed and create a new timer for check every 180 seconds """
   code = """
   def big_consumers():
       for f in st.tcp_flow_manager:
           if (f.bytes > 5000000):
               print("Warning: Flow %s consuming too much" % str(f))

   pd.add_timer(big_consumers, 180)
   """
   socket.sendto(code, (host, 3000)

The engine will activate a timer every 3 minutes to check network connections with more than 5MBytes on them.

 
