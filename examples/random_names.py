#!/usr/bin/env python

""" Example for detect random names with a neural network 
    
    For use this example you need to download the neural network
    from https://github.com/rrenaud/Gibberish-Detector and train it.
"""
__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013-2017 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"

import os
import sys
import pyaiengine
import pickle
import gib_detect_train

model_data = pickle.load(open('gib_model.pki', 'rb'))
model_mat = model_data['mat']
threshold = model_data['thresh']

""" For python compatibility """
try:
    xrange
except NameError:
    xrange = range

def random_callback_name(flow):
    """ This is the main function that do the work """

    name = None

    if (flow.dns_info):
        name = str(flow.dns_info.domain_name)
    elif (flow.ssl_info):
        name = str(flow.ssl_info.server_name)
    elif (flow.http_info):
        name = str(flow.http_info.host_name)

    name = name[:-4]
    if (name.startswith("www.")):
        name = name[4:]

    if (name):
        value = gib_detect_train.avg_transition_prob(name, model_mat) > threshold
        if (value == False):
            print("WARNING:%s:%s Unknown malware detected" % (flow.l7_protocol_name,name))

if __name__ == '__main__':

    st = pyaiengine.StackLan()
 
    dm = pyaiengine.DomainNameManager()

    st.tcp_flows = 200000
    st.udp_flows = 100000 

    d1 = pyaiengine.DomainName("Generic com",".com")
    d2 = pyaiengine.DomainName("Generic org",".com")
    d3 = pyaiengine.DomainName("Generic net",".org")

    d1.callback = random_callback_name
    d2.callback = random_callback_name
    d3.callback = random_callback_name
 
    dm.add_domain_name(d1) 
    dm.add_domain_name(d2) 
    dm.add_domain_name(d3) 

    st.set_domain_name_manager(dm,"DNSProtocol")
    st.set_domain_name_manager(dm,"SSLProtocol")
    st.set_domain_name_manager(dm,"HTTPProtocol")

    with pyaiengine.PacketDispatcher("enp0s25") as pd:
        pd.stack = st
        pd.run()

    dm.show()    
    sys.exit(0)

