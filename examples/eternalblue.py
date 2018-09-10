#!/usr/bin/env python

""" Example for detecting eternalblue exploit (used in WannaCry) """

__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013-2017 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"

import sys
import os
sys.path.append("../src/")
import pyaiengine

class loggerAdaptor (pyaiengine.DatabaseAdaptor):
    """ This class inheritance of DatabaseAdaptor that contains 
        the following methods:
        - insert, called on the first insertion of the network flow
        - update, called depending on the sample selected.
        - remove, called when the flow is destroy.
    """
    def __init__(self, filename):
        self.__f = open(filename, "w")

    def update(self,key,data):
        self.__f.write(data + '\n')

    def insert(self,key):
        pass

    def remove(self,key):
        pass

def callback_eternalblue(flow):

    print("EternaBlue exploit detected on %s" % str(flow))

if __name__ == '__main__':

    st = pyaiengine.StackLan()

    rm = pyaiengine.RegexManager()
    r = pyaiengine.Regex("Eternalblue exploit", b"^.{5}SMB.{57}[\x0e\x51\x52]\x00.*$", callback_eternalblue)

    """ We want to have the packet logged on the adaptor """
    r.write_packet = True

    rm.add_regex(r)

    st.tcp_regex_manager = rm

    l = loggerAdaptor("tcp_logfile.dat")

    st.set_tcp_database_adaptor(l, 512)

    st.set_dynamic_allocated_memory(True)

    st.enable_nids_engine = True

    with pyaiengine.PacketDispatcher("eth0") as pd:
        pd.stack = st
        pd.run()

    sys.exit(0)

