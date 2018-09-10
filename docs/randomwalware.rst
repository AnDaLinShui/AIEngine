Detect Unknown malware
~~~~~~~~~~~~~~~~~~~~~~

Nowadays malware is growing fast on the networks. To avoid detection's some type of malware uses random dns or random certificates (such as ToR). This technique allow to malware developers to spread their programs in a safe way due to the lack of detect this type of randomness DNS/Certificate names.

The following example uses a neural network in order to detect this type of malware. The code of the neural network have been download from https://github.com/rrenaud/Gibberish-Detector
First initialize the library according to the example and generate the gib_model.pki file.

.. code:: python

    import pickle
    import gib_detect_train

    model_data = pickle.load(open('gib_model.pki', 'rb'))
    model_mat = model_data['mat']
    threshold = model_data['thresh']

Now we define a function for manage the DNS queries and the SSL client hellos

.. code:: python

    def random_callback_name(flow):
        name = None

        if (flow.http_info):
            name = str(flow.http_info.host_name)
        elif (flow.dns_info):
            name = str(flow.dns_info.domain_name)
        elif (flow.ssl_info):
             name = str(flow.ssl_info.server_name)

        """ Remove the last prefix (.org|.com|.net) and the www if present """
        name = name[:-4]
        if (name.startswith("www.")):
            name = name[4:]

        if (name):
            """ Verify on the neural network how much of random is the name """
            value = gib_detect_train.avg_transition_prob(name, model_mat) > threshold
            if (value == False):
                print("WARNING:%s:%s result:%d" % (flow.l7_protocol_name,name,value))


The main part of the script is as usual

.. code:: python

    st = pyaiengine.StackLan()

    st.tcp_flows = 500000
    st.udp_flows = 163840

Load the malware data on the DNS and SSL protocols and assign them to the stack

.. code:: python

    d1 = pyaiengine.DomainName("Generic com",".com")
    d2 = pyaiengine.DomainName("Generic org",".org")
    d3 = pyaiengine.DomainName("Generic net",".net")

    d1.callback = random_callback_name
    d2.callback = random_callback_name
    d3.callback = random_callback_name

    dm.add_domain_name(d1)
    dm.add_domain_name(d2)
    dm.add_domain_name(d3)

    st.set_domain_name_manager(dm,"DNSProtocol")
    st.set_domain_name_manager(dm,"SSLProtocol")
    st.set_domain_name_manager(dm,"HTTPProtocol")

Open the network device, set the previous stack and run the engine

.. code:: python
    
    with  pyaiengine.PacketDispatcher("eth0") as pd:    
        pd.stack = st
        pd.run()

If you want to verify the example open your ToR browser or inject on the eth0 network device some malware pcap to see the results.
On the other hand, if you want to test with real example on the web http://www.pcapanalysis.com you have a lot of samples to use.
