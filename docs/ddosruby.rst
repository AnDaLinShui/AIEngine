Detect DDoS attacks
~~~~~~~~~~~~~~~~~~~~~~~

By using the method set_scheduler and the get_counters we can detect easily DDoS attacks, lets see how works:
We create a function handler for the DDoS detection method, in this example we will use the relationship between syn and synack packets for make the detection.

.. code:: ruby

  require "../src/ruaiengine"

  def scheduler_handler_tcp

    c = @s.get_counters("TCPProtocol")

    # Code the intelligence for detect DDoS based on
    # combination flags, bytes, packets and so on.
    syns = c["syns"]
    synacks = c["synacks"]
    if (syns > (synacks * 10))
      print "System under a SYN DoS attack\n"
    end
  end

Create a new IPv6 stack object.

.. code:: ruby

  @s = StackLanIPv6.new
  pd = PacketDispatcher.new
  pd.stack = @s


Allocate the maximum number of flows on the stack, if we are interested on TCP attacks lets create a big TCP cache.

.. code:: ruby

  @s.total_tcp_flows = 1500000
  @s.total_udp_flows = 163840

Use the set_scheduler callback for the PacketDispatcher class, so every 5 seconds the callback will be called.

.. code:: ruby

  pd.set_scheduler(method(:scheduler_handler_tcp),5)

Open the network device and run the engine.

.. code:: ruby
 
  pd.open("ens7")
  begin
    pd.run()
  rescue => e
    print "Stop capturing packets"
    print e.inspect
    print e.backtrace
  end

