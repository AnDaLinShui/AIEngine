#!/usr/bin/env python
#
# PyAIEngine a new generation network intrusion detection system.
#
# Copyright (C) 2013-2018  Luis Campo Giralte
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Library General Public
# License as published by the Ryadnology Team; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Library General Public License for more details.
#
# You should have received a copy of the GNU Library General Public
# License along with this library; if not, write to the
# Ryadnology Team, 51 Franklin St, Fifth Floor,
# Boston, MA  02110-1301, USA.
#
# Written by Luis Campo Giralte <me@ryadpasha.com> 
#
""" Unit tests for the pyaiengine python wrapper """
import os, signal, socket, sys
import pyaiengine
import unittest
import glob
import json
import tempfile
from random import randint
from contextlib import contextmanager

""" For python compatibility """
try:
    xrange
except NameError:
    xrange = range

py_major = sys.version_info.major
py_minor = sys.version_info.minor

class databaseTestAdaptor(pyaiengine.DatabaseAdaptor):
    def __init__(self):
        self.__total_inserts = 0
        self.__total_updates = 0
        self.__total_removes = 0
        self.lastdata = dict() 
        self.all_data = dict()

    def update(self, key, data):
        self.__total_updates = self.__total_updates + 1 
        self.all_data[self.__total_updates] = data
        self.lastdata = data

    def insert(self, key):
        self.__total_inserts = self.__total_inserts + 1
 
    def remove(self, key):
        self.__total_removes = self.__total_removes + 1

    def getInserts(self):
        return self.__total_inserts

    def getUpdates(self):
        return self.__total_updates

    def getRemoves(self):
        return self.__total_removes

def defined(value):
    with open("../config.h") as f:
        for l in f.readlines():
           if (l.startswith("#define %s" % value)):
               return True
    return False 

# Copy from stackoverflow https://stackoverflow.com/questions/4675728/redirect-stdout-to-a-file-in-python#4675744
def fileno(file_or_fd):
    fd = getattr(file_or_fd, 'fileno', lambda: file_or_fd)()
    if not isinstance(fd, int):
        raise ValueError("Expected a file (`.fileno()`) or a file descriptor")
    return fd

@contextmanager
def stdout_redirected(to=os.devnull, stdout=None):
    if stdout is None:
       stdout = sys.stdout

    stdout_fd = fileno(stdout)
    # copy stdout_fd before it is overwritten
    #NOTE: `copied` is inheritable on Windows when duplicating a standard stream
    with os.fdopen(os.dup(stdout_fd), 'wb') as copied: 
        stdout.flush()  # flush library buffers that dup2 knows nothing about
        try:
            os.dup2(fileno(to), stdout_fd)  # $ exec >&to
        except ValueError:  # filename
            with open(to, 'wb') as to_file:
                os.dup2(to_file.fileno(), stdout_fd)  # $ exec > to
        try:
            yield stdout # allow code to be run with the redirected stdout
        finally:
            # restore stdout to its previous value
            #NOTE: dup2 makes stdout_fd inheritable unconditionally
            stdout.flush()
            os.dup2(copied.fileno(), stdout_fd)  # $ exec >&copied

class StackLanTests(unittest.TestCase):

    def setUp(self):
        self.st = pyaiengine.StackLan()
        self.pd = pyaiengine.PacketDispatcher() 
        self.pd.stack = self.st
        self.st.tcp_flows = 2048
        self.st.udp_flows = 1024
        self.called_callback = 0 
        self.ip_called_callback = 0 

    def tearDown(self):
        pass

    def inject(self, pcapfile, pcapfilter = ""):
        with pyaiengine.PacketDispatcher(pcapfile) as pd:
            if (len(pcapfilter) > 0):
                pd.pcap_filter = pcapfilter
            pd.stack = self.st
            pd.run()

    def test01(self):
        """ Create a regex for netbios and detect """
        self.st.link_layer_tag = "vlan"

        rm = pyaiengine.RegexManager()

        self.assertEqual(sys.getrefcount(rm), 2)
        r = pyaiengine.Regex("netbios", "CACACACA")
        rm.add_regex(r)
        self.st.udp_regex_manager = rm
        self.assertEqual(sys.getrefcount(rm), 3)

        self.st.enable_nids_engine = True

        self.assertEqual(self.st.enable_nids_engine, True)
        self.assertEqual(self.st.stats_level, 0)

        self.inject("../pcapfiles/flow_vlan_netbios.pcap")

        self.assertEqual(r.matchs, 1)
        self.assertEqual(self.st.udp_regex_manager, rm)
        self.assertEqual(self.st.link_layer_tag, "vlan")

        # The rm is plugged to the UDP protocol
        self.assertNotEqual(str(rm).find("UDPGenericProtocol"), -1)
        
        self.st.udp_regex_manager = None 
        self.assertEqual(sys.getrefcount(rm), 3)

        """ Test the output and the existance of the function """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.st.show_flows()

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 8)

        f.close()

    def test02(self):
        """ Verify that None is working on the udpregexmanager """
        self.st.link_layer_tag = "vlan"

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("netbios", "CACACACA")
        rm.add_regex(r)
        self.st.udp_regex_manager = rm

        # The rm is plugged to the UDP protocol
        self.assertNotEqual(str(rm).find("UDPGenericProtocol"), -1)

        self.st.udp_regex_manager = None

        # The rm is plugged to the UDP protocol
        self.assertEqual(str(rm).find("UDPGenericProtocol"), -1)

        self.inject("../pcapfiles/flow_vlan_netbios.pcap")

        self.assertEqual(r.matchs, 0)
        self.assertIsNone(self.st.udp_regex_manager)

        """ Test the output and the existance of the function """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.st.show_flows(0)

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 7)
        f.close()

    def test03(self):
        """ Create a regex for netbios with callback """
        def callback(flow):
            self.called_callback += 1 
            self.assertEqual(flow.regex.matchs, 1)
            self.assertEqual(flow.regex.name, "netbios")
            self.assertIsNotNone(flow.regex_manager)
            self.assertEqual(flow.regex_manager.name, rm.name)
    
        self.st.link_layer_tag = "vlan"

        rm = pyaiengine.RegexManager("My regex manager")

        """ Change the name of the regex manager """
        rm.name = "My lovely name"
        self.assertEqual(rm.name, "My lovely name")

        r1 = pyaiengine.Regex("netbios", "CACACACA")
        r1.callback = callback
        r2 = pyaiengine.Regex("other", "This is not on the packets")
        rm.add_regex(r1)
        rm.add_regex(r2)
        self.st.udp_regex_manager = rm
        # print(r)
        self.st.enable_nids_engine = True

        self.inject("../pcapfiles/flow_vlan_netbios.pcap")

        self.assertEqual(r1.matchs, 1)
        self.assertEqual(r2.matchs, 0)
        self.assertEqual(self.called_callback, 1)

        """ Test the output and the existance of the function """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            """ The flow should not be shown """
            self.st.show_flows("DNS")

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 7)
        f.close()

        """ Test the output of the method show_matched_regexs """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            """ The regex should be shown """
            rm.show_matched_regexs()

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 2)
        f.close()
        # Reset the statistics
        rm.reset()

        self.assertEqual(r1.matchs, 0)
        self.assertEqual(r2.matchs, 0)

    def test04(self):
        """ Verify DNS and HTTP traffic """

        self.inject("../pcapfiles/accessgoogle.pcap")

        ft = self.st.tcp_flow_manager 
        fu = self.st.udp_flow_manager

        self.assertEqual(len(ft), 1)
        self.assertEqual(len(fu), 1)

        for flow in self.st.udp_flow_manager:
    	    udp_flow = flow
    	    break

        self.assertEqual(str(udp_flow.dns_info.domain_name), "www.google.com")	

        """ Verify the properties of the flows """
        self.assertEqual(str(udp_flow.src_ip), "192.168.1.13")
        self.assertEqual(str(udp_flow.dst_ip), "89.101.160.5")
        self.assertEqual(int(udp_flow.src_port), 54737)
        self.assertEqual(int(udp_flow.dst_port), 53)

        for flow in ft:
    	    http_flow = flow
    	    break

        """ Read only attributes """
        self.assertEqual(http_flow.packets_layer7, 4)
        self.assertEqual(http_flow.packets, 10)
        self.assertEqual(http_flow.bytes, 1826)
        self.assertEqual(http_flow.have_tag, False)

        self.assertEqual(str(http_flow.http_info.host_name), "www.google.com")
        self.assertEqual(http_flow.http_info.content_type, "text/html")

        """ All the flows can not have ip_set assigned """
        for flow in self.st.tcp_flow_manager:
            self.assertIsNone(flow.ip_set)

        """ Shows the DNS cache """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.st.show_cache("DNS")

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 2)
        f.close()

        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.st.show_flows("http")

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 8)
        f.close()

    def test05(self):
        """ Verify SSL traffic """

        self.inject("../pcapfiles/sslflow.pcap")

        self.assertEqual(len(self.st.tcp_flow_manager), 1)

        for flow in self.st.tcp_flow_manager:
            f = flow
            break

        self.assertEqual(str(f.ssl_info.server_name), "0.drive.google.com")
        self.assertEqual(str(f.ssl_info.issuer_name), "Google Internet Authority")
        self.assertEqual(format(f.ssl_info.cipher, "#04x"), '0xc011')

        """ Test the output and the existance of the function """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.st.show_flows("ssl", 2)

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 8)
        f.close()
        """ Test the output of the show_cache in SSL """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.st.show_cache("ssl")

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 2)
        f.close()

    def test06(self):
        """ Verify SSL traffic with domain callback"""
        
        def domain_callback(flow):
            self.called_callback += 1 

        d1 = pyaiengine.DomainName("Google Drive Cert", ".drive.google.com")
        d2 = pyaiengine.DomainName("No idea", ".pepe.com")
        d1.callback = domain_callback
        d1.regex_manager = None
        d1.http_uri_set = None
        d1.http_uri_regex_manager = None

        self.assertEqual(d1.regex_manager, None)

        dm = pyaiengine.DomainNameManager([ d1, d2 ])
        dm.name = "Some name"
        self.assertEqual(sys.getrefcount(dm), 2)

        self.st.set_domain_name_manager(dm, "SSLProtocol")
        self.assertEqual(sys.getrefcount(dm), 3)

        """ the dm is plugged to the SSLProtocol """
        self.assertNotEqual(str(dm).find("SSLProtocol"), -1)

        self.inject("../pcapfiles/sslflow.pcap")

        self.assertEqual(len(dm), 2)
        self.assertEqual(d1.matchs, 1)
        self.assertEqual(d2.matchs, 0)
        self.assertEqual(self.called_callback, 1)

        """ check also the integrity of the ssl cache and counters """
        ca1 = {'0.drive.google.com': 1}
        ca = self.st.get_cache("SSLProtocol")
        self.assertDictEqual(ca, ca1)

        cc = self.st.get_counters("SSLProtocol")
        self.assertEqual(cc["server hellos"], 1)

        self.st.set_domain_name_manager(None, "SSLProtocol")
        self.assertEqual(sys.getrefcount(dm), 2)

        """ the dm is not plugged to the SSLProtocol """
        self.assertEqual(str(dm).find("SSLProtocol"), -1)

        """ Test the output of the matches domains of the DomainNameManager """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            dm.show_matched_domains()

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 2)
        f.close()

        """ Test the output of the matches domains of the DomainNameManager """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            dm.show()

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 3)
        f.close()
        # Reset the statistics of the DomainNameManager
        dm.reset()

        self.assertEqual(d1.matchs, 0)
        self.assertEqual(d2.matchs, 0)

    def test07(self):
        """ Verify SSL traffic with domain callback and IPset"""

        def ipset_callback(flow):
            self.ip_called_callback += 1

        def domain_callback(flow):
            self.called_callback += 1
            """ Execute some of the properties of the flow """
            self.assertEqual(flow.reject, False)
            self.assertEqual(flow.regex_manager, None)
            flow.accept = True
            self.assertEqual(flow.accept, True) 
            a = flow.duration

        ip = pyaiengine.IPSet("Specific IP address", [ "74.125.24.189", "not valid" ])
        self.assertEqual(sys.getrefcount(ip), 2)

        ip.add_ip_address("2274.125.24.189")

        """ There is only one valid IP address """
        self.assertEqual(len(ip), 1)

        ip.callback = ipset_callback
        self.assertEqual(ip.callback, ipset_callback)

        ipm = pyaiengine.IPSetManager()
        self.assertEqual(sys.getrefcount(ipm), 2)
        ipm.add_ip_set(ip)
        self.assertEqual(sys.getrefcount(ipm), 2)
        self.assertEqual(sys.getrefcount(ip), 3)

        d = pyaiengine.DomainName("Google All", ".google.com")
        d.callback = domain_callback

        dm = pyaiengine.DomainNameManager()
        dm.add_domain_name(d)

        self.st.tcp_ip_set_manager = ipm
        self.assertEqual(sys.getrefcount(ipm), 3)

        """ the ipm is plugged to the TCPProtocol """
        self.assertNotEqual(str(ipm).find("TCPProtocol"), -1)

        self.st.set_domain_name_manager(dm, "SSLProtocol")

        self.inject("../pcapfiles/sslflow.pcap")

        self.assertEqual(d.matchs, 1)
        self.assertEqual(self.called_callback, 1)
        self.assertEqual(self.ip_called_callback, 1)

        self.st.tcp_ip_set_manager = None
        self.assertEqual(sys.getrefcount(ipm), 2)

        """ the ipm is not plugged to the TCPProtocol """
        self.assertEqual(str(ipm).find("TCPProtocol"), -1)

        ip.remove_ip_address("74.125.24.189")

    def test08(self):
        """ Attach a database to the engine """

        db = databaseTestAdaptor()

        self.assertEqual(sys.getrefcount(db), 2)
        self.st.set_tcp_database_adaptor(db, 16)
        self.assertEqual(sys.getrefcount(db), 3)

        self.inject("../pcapfiles/sslflow.pcap")

        self.assertEqual(db.getInserts(), 1)
        self.assertEqual(db.getUpdates(), 5)
        self.assertEqual(db.getRemoves(), 0)
       
        """ Verify the references """ 
        self.st.set_tcp_database_adaptor(None)
        self.st.set_tcp_database_adaptor(None)
        self.st.set_tcp_database_adaptor(None)
        self.assertEqual(sys.getrefcount(db), 2)

    def test09(self):
        """ Attach two databases to the engine """

        self.st.flows_timeout = 1

        db1 = databaseTestAdaptor()
        db2 = databaseTestAdaptor()

        self.assertEqual(sys.getrefcount(db1), 2)
        self.assertEqual(sys.getrefcount(db2), 2)

        self.st.link_layer_tag  = "vlan"
        self.st.set_udp_database_adaptor(db1, 16)

        self.assertEqual(sys.getrefcount(db1), 3)
        self.assertEqual(sys.getrefcount(db2), 2)

        self.inject("../pcapfiles/flow_vlan_netbios.pcap")

        self.assertEqual(db1.getInserts(), 1)
        self.assertEqual(db1.getUpdates(), 1)
        self.assertEqual(db1.getRemoves(), 1)
        self.assertEqual(db2.getInserts(), 0)
        self.assertEqual(db2.getUpdates(), 0)
        self.assertEqual(db2.getRemoves(), 0)

        """ Verify the output of adaptor """
        d = json.loads(db1.lastdata)
        if "info" in d:
            self.assertEqual(d["info"]["netbiosname"], "BLUMGROUP")
       
        d = self.st.get_cache("netbios")
        self.assertIsNotNone(d["BLUMGROUP"])
       
        """ reset the flow """
        self.st.udp_flow_manager.flush()

        self.st.set_udp_database_adaptor(db2, 16)
        
        self.assertEqual(sys.getrefcount(db1), 2)
        self.assertEqual(sys.getrefcount(db2), 3)

        self.inject("../pcapfiles/flow_vlan_netbios.pcap")
        
        self.assertEqual(db1.getInserts(), 1)
        self.assertEqual(db1.getUpdates(), 1)
        self.assertEqual(db1.getRemoves(), 1)
        self.assertEqual(db2.getInserts(), 1)
        self.assertEqual(db2.getUpdates(), 1)
        self.assertEqual(db2.getRemoves(), 0)

        self.st.set_udp_database_adaptor(None)
        
        self.assertEqual(sys.getrefcount(db1), 2)
        self.assertEqual(sys.getrefcount(db2), 2)

        """ Shows the netbios cache """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            """ The regex should be shown """
            self.st.show_cache("netbios")

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 2)
        f.close()

    def test10(self):
        """ Attach a database to the engine and domain name"""

        def domain_callback(flow):
            self.called_callback += 1 
            self.assertEqual(str(flow.ssl_info.server_name), "0.drive.google.com")
            self.assertEqual(flow.l7_protocol_name, "SSLProtocol")
            self.assertEqual(d, flow.ssl_info.matched_domain_name)

        d = pyaiengine.DomainName("Google All", ".google.com")

        self.assertEqual(sys.getrefcount(domain_callback), 2)
        dm = pyaiengine.DomainNameManager()
        d.callback = domain_callback
        self.assertEqual(sys.getrefcount(domain_callback), 3)
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm, "SSLProtocol")

        db = databaseTestAdaptor()

        self.st.set_tcp_database_adaptor(db, 16)

        self.inject("../pcapfiles/sslflow.pcap")

        self.assertEqual(db.getInserts(), 1)
        self.assertEqual(db.getUpdates(), 5)
        self.assertEqual(db.getRemoves(), 0)
        self.assertEqual(d.matchs,  1)
        self.assertEqual(self.called_callback, 1)

        d.callback = None
        self.assertEqual(sys.getrefcount(domain_callback), 2)

    def test11(self):
        """ Verify iterators of the RegexManager """

        rl = [ pyaiengine.Regex("expression %d" % x, "some regex %d" % x) for x in xrange(0, 5) ]

        """ Add a list with regexs to the RegexManager """
        rm = pyaiengine.RegexManager(rl)

        """ For verify that we can iterate over the regexs """
        for r in rm:
            a = r

        self.assertIsNone(rm.callback)
        self.assertIsNone(self.st.tcp_regex_manager) 
      
        self.st.tcp_regex_manager = rm 
        self.st.enable_nids_engine = True

        """ the rm is plugged to the TCPGenericProtocol """
        self.assertNotEqual(str(rm).find("TCPGenericProtocol"), -1)

        self.inject("../pcapfiles/sslflow.pcap")

        self.assertEqual(len(rm), 5)
    
        self.assertEqual(rm, self.st.tcp_regex_manager)
        for r in rl:
    	    self.assertEqual(r.matchs, 0)

        self.st.tcp_regex_manager = None
        """ the rm is not plugged to the TCPGenericProtocol """
        self.assertEqual(str(rm).find("TCPGenericProtocol"), -1)

    @unittest.skipIf(not defined("HAVE_BLOOMFILTER"), "Test not supported")
    def test12(self):
        """ Verify the IPBloomSet class """

        have_bloom = False
        try:
            from pyaiengine import IPBloomSet 
            have_bloom = True
        except ImportError:
            pass
  
        if (have_bloom): # execute the test
            def ipset_callback(flow):
                self.ip_called_callback += 1

            ip = pyaiengine.IPBloomSet("Specific IP address")
            ip = IPBloomSet("Specific IP address")
            ip.add_ip_address("74.125.24.189")
            ip.callback = ipset_callback

            ipm = pyaiengine.IPSetManager()
            ipm.add_ip_set(ip)

            self.st.tcp_ip_set_manager = ipm

            self.inject("../pcapfiles/sslflow.pcap")

            self.assertEqual(self.ip_called_callback, 1)
            ipm.reset()

    def test13(self):
        """ Verify all the URIs of an HTTP flow """

        def domain_callback(flow):
            urls = ("/css/global.css?v=20121120a", "/js/jquery.hoverIntent.js", "/js/ecom/ecomPlacement.js", "/js/scrolldock/scrolldock.css?v=20121120a",
                "/images_blogs/gadgetlab/2013/07/MG_9640edit-200x100.jpg", "/images_blogs/underwire/2013/08/Back-In-Time-200x100.jpg",
                "/images_blogs/thisdayintech/2013/03/set.jpg", "/js/scrolldock/i/sub_righttab.gif", "/images/global_header/new/Marriott_217x109.jpg",
                "/images/global_header/subscribe/gh_flyout_failsafe.jpg", "/images/global_header/new/the-connective.jpg", "/images/covers/120x164.jpg",
                "/images/subscribe/xrail_headline.gif", "/images_blogs/gadgetlab/2013/08/bb10-bg.jpg", "/images_blogs/autopia/2013/08/rescuer_cam06_110830-200x100.jpg",
                "/images_blogs/wiredscience/2013/08/earth-ring-200x100.jpg", "/images_blogs/underwire/2013/08/breaking-bad-small-200x100.png",
                "/insights/wp-content/uploads/2013/08/dotcombubble_660-200x100.jpg","/geekdad/wp-content/uploads/2013/03/wreck-it-ralph-title1-200x100.png",
                "/wiredenterprise/wp-content/uploads/2013/08/apple-logo-pixels-200x100.jpg", "/images_blogs/threatlevel/2013/08/drone-w.jpg",
                "/images_blogs/rawfile/2013/08/CirculationDesk-200x100.jpg", "/images_blogs/magazine/2013/07/theoptimist_wired-200x100.jpg",
                "/images_blogs/underwire/2013/08/Back-In-Time-w.jpg", "/design/wp-content/uploads/2013/08/dyson-w.jpg",
                "/images_blogs/threatlevel/2013/08/aaron_swartz-w.jpg", "/images_blogs/threatlevel/2013/08/aaron_swartz-w.jpg",
                "/images_blogs/wiredscience/2013/08/NegativelyRefracting-w.jpg", "/images_blogs/wiredscience/2013/08/bee-w.jpg",
                "/gadgetlab/2013/08/blackberry-failures/", "/gadgetlab/wp-content/themes/wired-global/style.css?ver=20121114",
                "/css/global.css?ver=20121114", "/js/cn-fe-common/jquery-1.7.2.min.js?ver=1.7.2","/js/cn.minified.js?ver=20121114",
                "/js/videos/MobileCompatibility.js?ver=20121114", "/images_blogs/gadgetlab/2013/06/internets.png",
                "/gadgetlab/wp-content/themes/wired-responsive/i/design-sprite.png", "/images_blogs/gadgetlab/2013/08/Blackberry8820.jpg",
                "/images_blogs/gadgetlab/2013/08/vsapple-60x60.jpg", "/images_blogs/gadgetlab/2013/08/AP090714043057-60x60.jpg"
            )
            self.called_callback += 1

            sw = False
            for url in urls:
                if (str(flow.http_info.uri) == url):
                    sw = True

            self.assertEqual(sw,True)
            self.assertEqual(str(flow.http_info.host_name), "www.wired.com")
            self.assertEqual(flow.l7_protocol_name, "HTTPProtocol")
            self.assertEqual(flow.http_info.matched_domain_name, d1)

        d1 = pyaiengine.DomainName("Wired domain", ".wired.com")
        d2 = pyaiengine.DomainName("Other domain", ".serving-sys.com")

        dm = pyaiengine.DomainNameManager()
        d1.callback = domain_callback
        dm.add_domain_name(d1)
        dm.add_domain_name(d2)

        self.st.set_domain_name_manager(dm, "HTTPProtocol")

        self.inject("../pcapfiles/two_http_flows_noending.pcap")

        self.assertEqual(self.called_callback, 1)

        """ Verify the output of the HTTP cache """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.st.show_cache("http")

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 3)
        f.close()
 
        """ Shows the domain matched on HTTP """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            dm.show_matched_domains()

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 3)
        f.close()

    def test14(self):
        """ Verify cache release functionality """

        self.st.flows_timeout = 50000000 # No timeout :D

        self.pd.open("../pcapfiles/sslflow.pcap")
        self.pd.run()
        self.pd.close()
        
        ft = self.st.tcp_flow_manager

        self.assertEqual(len(ft), 1)

        for flow in ft:
            self.assertNotEqual(flow.ssl_info, None)
       
        self.inject("../pcapfiles/accessgoogle.pcap")

        fu = self.st.udp_flow_manager

        self.assertEqual(len(fu), 1)

        for flow in fu:
            self.assertNotEqual(flow.dns_info, None)

        # release some of the caches
        self.st.release_cache("SSLProtocol")
        
        for flow in ft:
            self.assertEqual(flow.ssl_info, None)

        # release all the caches
        self.st.release_caches()

        for flow in ft:
            self.assertEqual(flow.ssl_info, None)
            self.assertEqual(flow.http_info, None)

        for flow in fu:
            self.assertEqual(flow.dns_info, None)

    def test15(self):
        """ Attach a database to the engine and test timeouts on udp flows """

        db = databaseTestAdaptor()

        self.st.link_layer_tag = "vlan"
        self.st.set_udp_database_adaptor(db, 16)

        self.st.flows_timeout = 1

        self.pd.open("../pcapfiles/flow_vlan_netbios.pcap");
        self.pd.run();
        self.pd.close();

        self.assertEqual(db.getInserts(), 1)
        self.assertEqual(db.getUpdates(), 1)
        self.assertEqual(db.getRemoves(), 1)
        self.assertEqual(self.st.flows_timeout, 1)

    def test16(self):
        """ Verify that ban domains dont take memory """

        d = pyaiengine.DomainName("Wired domain", ".wired.com")

        dm = pyaiengine.DomainNameManager()
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm, "HTTPProtocol", False)

        self.inject("../pcapfiles/two_http_flows_noending.pcap", pcapfilter= "tcp")

        self.assertEqual(d.matchs, 1)

        ft = self.st.tcp_flow_manager

        self.assertEqual(len(ft), 2)

        # Only the first flow is the banned
        for flow in ft:
            info = flow.http_info
            self.assertEqual(info.host_name, "")
            self.assertEqual(info.user_agent, "")
            self.assertEqual(info.uri, "")
            break

    def test17(self):
        """ Verify the ban functionality on the fly with a callback """

        def domain_callback(flow):
            self.called_callback += 1
            
            info = flow.http_info
            url = info.uri

            # Some URI analsys on the first request could be done here
            if (url == "/css/global.css?v=20121120a"):
                info.banned = True

        d = pyaiengine.DomainName("Wired domain", ".wired.com")

        dm = pyaiengine.DomainNameManager()
        d.callback = domain_callback
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm, "HTTPProtocol")

        """ the dm is plugged to the HTTPProtocol """
        self.assertNotEqual(str(dm).find("HTTPProtocol"), -1)

        self.inject("../pcapfiles/two_http_flows_noending.pcap")

        self.assertEqual(self.called_callback, 1)

        ft = self.st.tcp_flow_manager

        self.assertEqual(len(ft), 2)

        # Only the first flow is the banned and released
        for flow in self.st.tcp_flow_manager:
            inf = flow.http_info
            self.assertNotEqual(inf, None)
            self.assertEqual(inf.uri, "")
            self.assertEqual(inf.user_agent, "")
            self.assertEqual(inf.host_name, "")
            break

        self.st.release_caches()
        
        self.st.set_domain_name_manager(pyaiengine.DomainNameManager(), "HTTPProtocol")

        """ the dm is plugged to the HTTPProtocol """
        self.assertEqual(str(dm).find("HTTPProtocol"), -1)

    def test18(self):
        """ Verify the getCounters functionality """

        self.inject("../pcapfiles/two_http_flows_noending.pcap")

        c = self.st.get_counters("EthernetProtocol")

        if (sys.version_info.major > 2):
            self.assertEqual("packets" in c, True) 
            self.assertEqual("bytes" in c, True) 
        else:
            self.assertEqual(c.has_key("packets"), True) 
            self.assertEqual(c.has_key("bytes"), True) 

        self.assertEqual(c["bytes"], 910064)

        c = self.st.get_counters("TCPProtocol")

        self.assertEqual(c["bytes"], 879940)
        self.assertEqual(c["packets"], 886)
        self.assertEqual(c["syns"], 2)
        self.assertEqual(c["synacks"], 2)
        self.assertEqual(c["acks"], 882)
        self.assertEqual(c["rsts"], 0)
        self.assertEqual(c["fins"], 0)

        c = self.st.get_counters("UnknownProtocol")
        self.assertEqual(len(c), 0)

    def test19(self):
        """ Verify SMTP traffic with domain callback """
        self.from_correct = False
        def domain_callback(flow):
            s = flow.smtp_info
            if (s):
                if (str(s.mail_from) == "gurpartap@patriots.in"):
                    self.from_correct = True
                x = s.mail_to
            self.called_callback += 1

        d = pyaiengine.DomainName("Some domain", ".patriots.in")
        d.callback = domain_callback

        dm = pyaiengine.DomainNameManager()
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm, "SMTPProtocol")

        oldstack = None

        with pyaiengine.PacketDispatcher("../pcapfiles/smtp.pcap") as pd:
            pd.stack = self.st
            pd.run();
            oldstack = pd.stack

        self.assertEqual(oldstack, self.st)

        self.assertEqual(d.matchs, 1)
        self.assertEqual(self.called_callback, 1)
        self.assertEqual(self.from_correct, True)
        self.assertEqual(len(self.st.get_cache("smtp")), 1)

        """ Test the show_cache method on smtp """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.st.show_cache("Smtp")

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 2)
        f.close()

    def test20(self):
        """ Test the chains of regex with RegexManagers """

        rlist = [ pyaiengine.Regex("expression %d" % x, "some regex %d" % x) for x in xrange(0, 5) ]

        rmbase = pyaiengine.RegexManager(rlist)
        rm1 = pyaiengine.RegexManager()
        rm2 = pyaiengine.RegexManager()
        rm3 = pyaiengine.RegexManager()

        r1 = pyaiengine.Regex("smtp1", "^AUTH LOGIN")
        r1.next_regex_manager = rm1
        rmbase.add_regex(r1)

        r2 = pyaiengine.Regex("smtp2", "^NO MATCHS")
        r3 = pyaiengine.Regex("smtp3", "^MAIL FROM")

        rm1.add_regex(r2)
        rm1.add_regex(r3)
        r3.next_regex_manager = rm2	

        r4 = pyaiengine.Regex("smtp4", "^NO MATCHS")
        r5 = pyaiengine.Regex("smtp5", "^DATA")
	
        rm2.add_regex(r4)
        rm2.add_regex(r5)
        r5.next_regex_manager = rm3

        r6 = pyaiengine.Regex("smtp6", "^QUIT")
        rm3.add_regex(r6)

        self.st.tcp_regex_manager = rmbase
        self.st.enable_nids_engine = True

        self.inject("../pcapfiles/smtp.pcap") 

        for r in rlist:
            self.assertEqual(r.matchs, 0)

        self.assertEqual(r1.matchs, 1)
        self.assertEqual(r2.matchs, 0)
        self.assertEqual(r3.matchs, 1)
        self.assertEqual(r4.matchs, 0)
        self.assertEqual(r5.matchs, 1)
        self.assertEqual(r6.matchs, 1)


    def test21(self):
        """ Tests the parameters of the callbacks """
        def callback1(flow):
            pass

        def callback2(flow, other):
            pass

        def callback3():
            pass

        r = pyaiengine.Regex("netbios", "CACACACA")

        try: 
            r.callback = None
            self.assertTrue(False)
        except:
            self.assertTrue(True)

        try:
            r.callback = callback2
            self.assertTrue(False)
        except:
            self.assertTrue(True)

        try:
            r.callback = callback1
            self.assertTrue(True)
        except:
            self.assertTrue(False)

    def test22(self):
        """ Verify the functionality of the HTTPUriSets with the callbacks """

        self.uset = pyaiengine.HTTPUriSet()
        def domain_callback(flow):
            self.called_callback += 1

        def uri_callback(flow):
            self.assertEqual(len(self.uset), 1)
            self.assertEqual(self.uset.lookups, 39)
            self.assertEqual(self.uset.lookups_in, 1)
            self.assertEqual(self.uset.lookups_out, 38)
            self.called_callback += 1

        d = pyaiengine.DomainName("Wired domain", ".wired.com")

        dm = pyaiengine.DomainNameManager()
        d.callback = domain_callback
        dm.add_domain_name(d)

        self.uset.add_uri("/images_blogs/gadgetlab/2013/08/AP090714043057-60x60.jpg")
        self.uset.callback = uri_callback

        d.http_uri_set = self.uset

        self.assertEqual(self.uset.callback, uri_callback)
        self.st.set_domain_name_manager(dm, "HTTPProtocol")

        self.inject("../pcapfiles/two_http_flows_noending.pcap") 

        self.assertEqual(d.http_uri_set, self.uset)
        self.assertEqual(len(self.uset), 1)
        self.assertEqual(self.uset.lookups, 39)
        self.assertEqual(self.uset.lookups_in, 1)
        self.assertEqual(self.uset.lookups_out, 38)

        self.assertEqual(self.called_callback, 2)

    def test23(self):
        """ Verify the functionality of the HTTPUriSets with the callbacks """

        self.uset = pyaiengine.HTTPUriSet()
        def domain_callback(flow):
            self.called_callback += 1

        def uri_callback(flow):
            self.assertEqual(len(self.uset), 1)
            self.assertEqual(self.uset.lookups, 4)
            self.assertEqual(self.uset.lookups_in, 1)
            self.assertEqual(self.uset.lookups_out, 3)
            self.called_callback += 1

        d = pyaiengine.DomainName("Wired domain", ".wired.com")

        dm = pyaiengine.DomainNameManager()
        d.callback = domain_callback
        dm.add_domain_name(d)

	# This uri is the thrid of the wired.com flow
        self.uset.add_uri("/js/scrolldock/scrolldock.css?v=20121120a")
        self.uset.callback = uri_callback

        d.http_uri_set = self.uset

        self.st.set_domain_name_manager(dm, "HTTPProtocol")

        self.inject("../pcapfiles/two_http_flows_noending.pcap") 

        self.assertEqual(len(self.uset), 1)
        self.assertEqual(self.uset.lookups, 39)
        self.assertEqual(self.uset.lookups_in, 1)
        self.assertEqual(self.uset.lookups_out, 38)
        self.assertEqual(self.called_callback, 2)

    def test24(self):
        """ Verify the property of the PacketDispatcher.stack """

        p = pyaiengine.PacketDispatcher()

        self.assertEqual(p.stack, None)
        
        # p.stack = p 
        self.pd.stack = None

        self.assertEqual(self.pd.stack, None)

    def test25(self):
        """ Verify the functionality of the SSDP Protocol """

        def callback_ssdp(flow):
            self.assertEqual(flow.ssdp_info.uri, "*")
            self.assertEqual(flow.ssdp_info.host_name, "239.255.255.250:1900")
            self.called_callback += 1  

        d = pyaiengine.DomainName("All", "*", callback_ssdp)

        self.assertEqual(sys.getrefcount(d), 2)

        dm = pyaiengine.DomainNameManager()
        dm.add_domain_name(d)
        self.assertEqual(sys.getrefcount(d), 3)

        # Remove and add again, just verify the ref count 
        dm.remove_domain_name("All")
        self.assertEqual(sys.getrefcount(d), 2)
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm, "ssdp")

        self.inject("../pcapfiles/ssdp_flow.pcap") 

        self.assertEqual(self.called_callback, 1)

        """ Verify the output of the show_cache """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.st.show_cache("ssdp")

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 2)
        f.close()

        c = self.st.get_cache("ssdp")
        c1 = {'239.255.255.250:1900': 1}
        self.assertDictEqual(c, c1)

    def test26(self):
        """ Verify the functionality of the SSDP Protocol and remove the memory of that protocol """

        self.st.decrease_allocated_memory("ssdp", 10000)

        self.inject("../pcapfiles/ssdp_flow.pcap") 

        fu = self.st.udp_flow_manager
        for flow in fu:
            s = flow.ssdp_info
            self.assertEqual(s, None)

    def test27(self):
        """ Verify the functionality of the RegexManager on the HTTP Protocol for analise
            inside the l7 payload of HTTP """

        def callback_domain(flow):
            self.called_callback += 1
            pass

        def callback_regex(flow):
            self.called_callback += 1
            self.assertEqual(flow.packets, 11)
            self.assertEqual(flow.packets_layer7, 4)
 
        d = pyaiengine.DomainName("Wired domain", ".wired.com")

        r1 = pyaiengine.Regex("Regex for analysing the content of HTTP", b"^\\x1f\\x8b\\x08\\x00\\x00\\x00\\x00.*$")
        r2 = pyaiengine.Regex("Regex for analysing the content of HTTP", b"^.{3}\\xcd\\x9c\\xc0\\x0a\\x34.*$")
        r3 = pyaiengine.Regex("Regex for analysing the content of HTTP", b"^.*\\x44\\x75\\x57\\x0c\\x22\\x7b\\xa7\\x6d$")

        r2.next_regex = r3
        r1.next_regex = r2
        r3.callback = callback_regex

        rm = pyaiengine.RegexManager("One manager", [ r1 ])

        """ So the flows from wired.com will be analise the regexmanager attached """
        d.regex_manager = rm

        dm = pyaiengine.DomainNameManager()
        d.callback = callback_domain
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm, "http")

        self.inject("../pcapfiles/two_http_flows_noending.pcap")

        self.assertEqual(self.called_callback, 2)
        self.assertEqual(r1.matchs, 1)
        self.assertEqual(r2.matchs, 1)
        self.assertEqual(r3.matchs, 1)
        self.assertEqual(d.matchs, 1)

    def test28(self):
        """ Verify the correctness of the HTTP Protocol """ 

        """ The filter tcp and port 55354 will filter just one HTTP flow
            that contains exactly 39 requests and 38 responses """
        self.inject("../pcapfiles/two_http_flows_noending.pcap", pcapfilter="tcp and port 55354")

        c = self.st.get_counters("HTTPProtocol")
        self.assertEqual(c["requests"], 39)
        self.assertEqual(c["responses"], 38)

    def test29(self):
        """ Verify the correctness of the HTTP Protocol """

        """ The filter tcp and port 49503 will filter just one HTTP flow
            that contains exactly 39 requests and 38 responses """
        self.inject("../pcapfiles/two_http_flows_noending.pcap", pcapfilter="tcp and port 49503")

        c = self.st.get_counters("HTTPProtocol")
        self.assertEqual(c["requests"], 3)
        self.assertEqual(c["responses"], 3)

    def test30(self):
        """ Verify the functionality of the Evidence manager """

        def domain_callback(flow):
            self.called_callback += 1
            flow.evidence = True

        d = pyaiengine.DomainName("Wired domain", ".wired.com")

        dm = pyaiengine.DomainNameManager()
        d.callback = domain_callback
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm, "HTTPProtocol")

        with pyaiengine.PacketDispatcher("../pcapfiles/two_http_flows_noending.pcap") as pd:
            pd.evidences = True
            pd.stack = self.st
            pd.run()

        self.assertEqual(self.called_callback, 1)
        self.assertEqual(d.matchs, 1)

        """ verify the integrity of the new file created """
        files = glob.glob("evidences.*.pcap")
        os.remove(files[0])

    def test31(self):
        """ Verify the functionality of the RegexManager on the IPSets """

        def regex_callback(flow):
            r = flow.regex
            i = flow.ip_set
            self.assertEqual(flow.dst_ip, "95.100.96.10") 
            self.assertEqual(r.name, "generic http") 
            self.assertEqual(i.name, "Generic set") 
            self.called_callback += 1

        def ipset_callback(flow):
            r = flow.regex
            i = flow.ip_set
            self.assertNotEqual(i, None) 
            self.assertEqual(i.name, "Generic set") 
            self.assertEqual(r, None) 
            self.called_callback += 1

        rm = pyaiengine.RegexManager()
        ip = pyaiengine.IPSet("Generic set", [ "95.100.96.10" ])
        ip.regex_manager = rm
        ip.callback = ipset_callback
        im = pyaiengine.IPSetManager()

        im.add_ip_set(ip)
        self.st.tcp_ip_set_manager = im

        r = pyaiengine.Regex("generic http", "^GET.*HTTP")
        r.callback = regex_callback
        rm.add_regex(r)

        self.st.enable_nids_engine = True

        self.inject("../pcapfiles/two_http_flows_noending.pcap") 
 
        self.assertEqual(self.called_callback, 2)
        self.assertEqual(ip.lookups_in, 1)
        self.assertEqual(r.matchs, 1)

        """ Verify the output of the IPSet """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            """ The regex should be shown """
            ip.show()

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 2)
        f.close()

        im.reset()

        self.assertEqual(ip.lookups_in, 0)
        self.assertEqual(ip.lookups_out, 0)

    def test32(self):
        """ Verify the functionality of the RegexManager on the IPSets """

        def regex_callback(flow):
            r = flow.regex
            i = flow.ip_set
            self.assertEqual(flow.dst_ip, "95.100.96.10")
            self.assertEqual(r.name, "generic http")
            self.assertEqual(i.name, "Generic set")
            self.called_callback += 1

        def ipset_callback(flow):
            r = flow.regex
            i = flow.ip_set
            self.assertNotEqual(i, None)
            self.assertEqual(i.name, "Generic set")
            self.assertEqual(r, None)
            self.called_callback += 1

        rm = pyaiengine.RegexManager()
        i = pyaiengine.IPSet("Generic set")
        i.add_ip_address("95.100.96.10")
        i.regex_manager = rm 
        i.callback = ipset_callback
        im = pyaiengine.IPSetManager()

        im.add_ip_set(i)
        self.st.tcp_ip_set_manager = im

        r = pyaiengine.Regex("generic http", "^GET.*HTTP")
        r.callback = regex_callback
        rm.add_regex(r)

        self.st.enable_nids_engine = True

        self.inject("../pcapfiles/two_http_flows_noending.pcap") 

        self.assertEqual(self.called_callback, 2)
        self.assertEqual(i.lookups_in, 1)
        self.assertEqual(r.matchs, 1)

    def test33(self):
        """ Verify the clean of domains on the domain name manager """
        dm = pyaiengine.DomainNameManager("One domain manager", [
            pyaiengine.DomainName("Wired domain", ".wired.com"),
            pyaiengine.DomainName("Wired domain", ".photos.wired.com"),
            pyaiengine.DomainName("Wired domain", ".aaa.wired.com"),
            pyaiengine.DomainName("Wired domain", ".max.wired.com"),
            pyaiengine.DomainName("domain1", ".paco.com"),
            pyaiengine.DomainName("domain2", ".cisco.com") ])

        self.assertEqual(len(dm), 6)

        dm.remove_domain_name("domain1")
        self.assertEqual(len(dm), 5)
     
        dm.remove_domain_name("Wired domain")
        self.assertEqual(len(dm), 1)

    def test34(self):
        """ Verify the functionality write on the databaseAdaptor when a important event happen on UDP """

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("my regex", b"^HTTP.*$")

        """ Write the packet """
        r.write_packet = True

        rm.add_regex(r)

        db = databaseTestAdaptor()

        self.st.set_udp_database_adaptor(db)

        self.st.udp_regex_manager = rm

        self.st.enable_nids_engine = True

        self.inject("../pcapfiles/ssdp_flow.pcap") 

        d = json.loads(db.lastdata)
        if "matchs" in d:
            self.assertEqual(d["matchs"], "my regex")
        self.assertEqual(r.matchs, 1)

        """ the packet is write on the packet field of the json """
        packet = d["packet"]
        cad = "".join(str(chr(x)) for x in packet)
        self.assertEqual(cad.startswith("HTTP"), True)


    def test35(self):
        """ Verify the coap protocol functionality """

        db = databaseTestAdaptor()

        self.st.set_udp_database_adaptor(db)

        self.inject("../pcapfiles/ipv4_coap.pcap")

        d = json.loads(db.lastdata)
        if "info" in d:
            self.assertEqual(d["info"]["uri"], "/1/1/768/core.power")

        """ Release the cache for coap """
        self.assertEqual(len(self.st.udp_flow_manager), 1)

        for flow in self.st.udp_flow_manager:
            self.assertNotEqual(flow.coap_info, None)

        """ release  the cache """
        self.st.release_cache("CoAPProtocol")

        for flow in self.st.udp_flow_manager:
            self.assertEqual(flow.coap_info, None)

        """ release all the caches """
        self.st.release_caches()

    def test36(self):
        """ Verify the mqtt protocol functionality """

        db = databaseTestAdaptor()

        self.st.set_tcp_database_adaptor(db, 1)

        self.inject("../pcapfiles/ipv4_mqtt.pcap")
           
        d = json.loads(db.lastdata)
        if "info" in d:
            self.assertEqual(d["info"]["operation"], 4)
            self.assertEqual(d["info"]["total_server"], 9)
            self.assertEqual(d["info"]["total_client"], 8)

        # print(json.dumps(d,sort_keys=True,indent=4, separators=(',', ': ')))

        """ Release the cache for mqtt """
        self.assertEqual(len(self.st.tcp_flow_manager), 1)

        for flow in self.st.tcp_flow_manager:
            self.assertNotEqual(flow.mqtt_info, None)
            self.assertEqual(flow.coap_info, None)
            self.assertEqual(flow.http_info, None)
            self.assertEqual(flow.dns_info, None)
            self.assertEqual(flow.ssl_info, None)

        """ release  the cache """
        self.st.release_cache("MQTTProtocol")

        for flow in self.st.tcp_flow_manager:
            self.assertEqual(flow.mqtt_info, None)
            self.assertEqual(flow.coap_info, None)
            self.assertEqual(flow.http_info, None)
            self.assertEqual(flow.dns_info, None)
            self.assertEqual(flow.ssl_info, None)

        """ release all the caches """
        self.st.release_caches()

    def test37(self):
        """ Verify the coap protocol functionality with domains matched """

        def domain_callback(flow):
            self.called_callback += 1
            self.assertNotEqual(flow.coap_info, None)
            self.assertEqual(flow.coap_info.host_name, "localhost")
            self.assertEqual(flow.coap_info.uri, "/somepath/really/maliciousuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuua/time")
            """ the label is the concatenation of the host and the uri """
            flow.label = flow.coap_info.host_name + flow.coap_info.uri
            self.assertEqual(flow.coap_info.matched_domain_name, d)

        d = pyaiengine.DomainName("Localhost domain", "localhost")


        dm = pyaiengine.DomainNameManager()
        d.callback = domain_callback
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm, "CoAPProtocol")

        db = databaseTestAdaptor()

        self.st.set_udp_database_adaptor(db)

        self.inject("../pcapfiles/ipv4_coap_big_uri.pcap") 

        data = json.loads(db.lastdata)
        # print(json.dumps(data,sort_keys=True,indent=4, separators=(',', ': ')))
        if "info" in data:
            self.assertEqual(data["info"]["uri"], "/somepath/really/maliciousuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuua/time")
        else:
            self.assertTrue(False)

        self.assertEqual(data["label"], "localhost/somepath/really/maliciousuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuua/time")
        self.assertEqual(self.called_callback, 1)
        self.assertEqual(d.matchs, 1)

    def test38(self):
        """ Test the modbus protocol """

        self.inject("../pcapfiles/modbus_five_flows.pcap") 

        c = self.st.get_counters("ModbusProtocol")
        self.assertEqual(c["write single coil"], 4)
        self.assertEqual(c["read coils"], 6)

    def test39(self):
        """ Verify the release cache with netbios object attached """
        self.st.link_layer_tag = "vlan"

        self.inject("../pcapfiles/flow_vlan_netbios.pcap")

        fu = self.st.udp_flow_manager
        flow = None
        for f in fu:
            flow = f
        
        self.assertIsNotNone(flow)   
        self.assertIsNotNone(flow.netbios_info)
        self.assertIsNotNone(flow.netbios_info.name)
        self.assertEqual(flow.netbios_info.name, "BLUMGROUP")

        self.st.release_cache("netbios")
       
        flow = None 
        for f in fu:
            flow = f
        
        self.assertIsNotNone(flow)   
        self.assertIsNone(flow.netbios_info)

    def test40(self):
        """ Verify that callbacks with None do not break things """

        def domain_callback(flow):
            self.called_callback += 1

        d = pyaiengine.DomainName("Google Drive Cert", ".drive.google.com")
        d.callback = None

        dm = pyaiengine.DomainNameManager()
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm, "SSLProtocol")

        self.inject("../pcapfiles/sslflow.pcap")

        """ First time nothing happens """
        self.assertEqual(len(dm), 1)
        self.assertEqual(d.matchs, 1)
        self.assertEqual(self.called_callback, 0)

        """ flush the flows from memory """
        self.st.tcp_flow_manager.flush()

        """ reinject the flows with the callback set """
        d.callback = domain_callback

        self.inject("../pcapfiles/sslflow.pcap")

        """ Second time callback is executed """
        self.assertEqual(len(dm), 1)
        self.assertEqual(d.matchs, 2)
        self.assertEqual(self.called_callback, 1)

        """ flush the flows from memory again """
        self.st.tcp_flow_manager.flush()

        """ reinject the flows with the callback set to None """
        d.callback = None

        self.inject("../pcapfiles/sslflow.pcap")

        """ Second time callback is not executed """
        self.assertEqual(len(dm), 1)
        self.assertEqual(d.matchs, 3)
        self.assertEqual(self.called_callback, 1)

    def test41(self):
        """ Create a regex for netbios and add and remove from a RegexManager """
        self.st.link_layer_tag = "vlan"

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("netbios", "CACACACA")
        rm.add_regex(r)
        self.st.udp_regex_manager = rm

        self.st.enable_nids_engine = True

        self.inject("../pcapfiles/flow_vlan_netbios.pcap")

        self.assertEqual(r.matchs, 1)
        self.assertEqual(len(rm), 1)
        self.assertEqual(self.st.udp_regex_manager, rm)
        self.assertEqual(self.st.link_layer_tag, "vlan")
 
        rm.remove_regex(r)
        
        self.assertEqual(len(rm), 0)

        self.st.udp_flow_manager.flush()

        self.inject("../pcapfiles/flow_vlan_netbios.pcap")

        self.assertEqual(r.matchs, 1)

    def test42(self):
        """ Create a regex for netbios with callback and a RegexManager with callback """

        def callback_rm(flow):
            self.called_callback += 1
            self.assertEqual(flow.regex.matchs, 1)
            self.assertEqual(flow.regex.name, "netbios")

        def callback_nb(flow):
            self.fail("shouldn't happen")

        self.st.link_layer_tag = "vlan"

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("netbios", "CACACACA")

        r.callback = callback_nb

        """ The regex manager sets a callback so the regexs will not call their own callbacks """
        rm.callback = callback_rm

        rm.add_regex(r)
        self.st.udp_regex_manager = rm

        self.st.enable_nids_engine = True

        self.inject("../pcapfiles/flow_vlan_netbios.pcap")

        self.assertEqual(r.matchs, 1)
        self.assertEqual(self.called_callback, 1)

    def test43(self):
        """" Create a complex detection on http traffic payload for exercise the code """

        def callback_domain(flow):
            self.called_callback += 1
            self.assertIsNone(flow.regex_manager)
            self.assertEqual(flow.http_info.matched_domain_name.regex_manager, rm1)

        def callback_regex1(flow):
            self.assertEqual(flow.packets, 7) 
            self.assertEqual(flow.packets_layer7, 3) 
            self.assertIsNotNone(flow.regex_manager)
            self.assertEqual(flow.regex_manager.name, rm2.name)

        def callback_regex2(flow):
            self.assertEqual(flow.packets, 40) 
            self.assertEqual(flow.packets_layer7, 20) 
            self.assertEqual(flow.regex_manager.name, rm2.name)

        def callback_regex3(flow):
            self.called_callback += 1
            self.assertEqual(flow.packets, 90)
            self.assertEqual(flow.packets_layer7, 47)

        d = pyaiengine.DomainName("Some domain", ".serving-sys.com")

        rm1 = pyaiengine.RegexManager("Im the first regexs")
        rm2 = pyaiengine.RegexManager("Im the second regexs")
        r1 = pyaiengine.Regex("Regex for analysing the content of HTTP", b"^.*Ducky.*$")
        r2 = pyaiengine.Regex("Regex for analysing the content of HTTP", b"^.*Ducky.*$")
        r3 = pyaiengine.Regex("Regex for analysing the content of HTTP", b"^.*Photoshop.*$")

        r2.next_regex = r3
        self.assertEqual(sys.getrefcount(r3), 3)
           
        r1.next_regex_manager = rm2
 
        rm1.add_regex(r1)
        rm2.add_regex(r2)

        r1.callback = callback_regex1
        r2.callback = callback_regex2
        r3.callback = callback_regex3

        """ attach the regexmanager to the domain """
        d.regex_manager = rm1

        dm = pyaiengine.DomainNameManager()
        d.callback = callback_domain
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm, "http")

        self.inject("../pcapfiles/two_http_flows_noending.pcap")

        self.assertEqual(self.called_callback, 2)
        self.assertEqual(r1.matchs, 1)
        self.assertEqual(r2.matchs, 1)
        self.assertEqual(r3.matchs, 1)
        self.assertEqual(d.matchs, 1)

        r2.next_regex = None 
        self.assertEqual(sys.getrefcount(r3), 2)

    def test44(self):
        """ Test the chains of regex with callbacks and regex on constructors """

        def callback_regex_auth(flow):
            self.called_callback += 1

        def callback_regex_from(flow):
            self.called_callback += 1

        def callback_regex_data(flow):
            self.called_callback += 1
        
        def callback_regex_quit(flow):
            self.called_callback += 1

        rm = pyaiengine.RegexManager()

        """ Example of link regexs with callbacks inside """
        r = pyaiengine.Regex("smtp1", b"^AUTH LOGIN.*$", callback_regex_auth,
            pyaiengine.Regex("smtp2", b"^MAIL FROM.*$", callback_regex_from,
            pyaiengine.Regex("smtp3", b"^DATA.*$", callback_regex_data,
            pyaiengine.Regex("smtp4", b"^QUIT.*$", callback_regex_quit))))

        rm = pyaiengine.RegexManager([ r ])

        self.st.tcp_regex_manager = rm
        self.st.enable_nids_engine = True
        
        self.inject("../pcapfiles/smtp.pcap") 

        self.assertEqual(r.matchs, 1)
        self.assertEqual(r.next_regex.matchs, 1)
        self.assertEqual(r.next_regex.next_regex.matchs, 1)
        self.assertEqual(r.next_regex.next_regex.next_regex.matchs, 1)
        self.assertEqual(self.called_callback, 4)

    def test45(self):
        """ Test use of regexs on the HTTP uri field """

        def callback_uri(flow):
            inf = flow.http_info
            self.assertNotEqual(inf, None)
            self.assertEqual(inf.uri, "/textinputassistant/tia.png")
            self.assertEqual(inf.host_name, "www.google.com")
            self.called_callback += 1

        dm = pyaiengine.DomainNameManager()
        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("my uri regex", b"^.*tia.png$", callback_uri)
        d = pyaiengine.DomainName("Gafas", "google.com")

        """ Attach the RegexManager to process all the Uris from google """
        d.http_uri_regex_manager = rm

        self.assertEqual(d.http_uri_regex_manager, rm)

        dm.add_domain_name(d)
        rm.add_regex(r)
        
        self.st.set_domain_name_manager(dm, "http")

        self.inject("../pcapfiles/accessgoogle.pcap")

        self.assertEqual(self.called_callback, 1)

    def test46(self):
        """ Verify the functionality of dynamic memory with the SSDP Protocol """

        self.st.decrease_allocated_memory("ssdp", 10000)
        self.st.set_dynamic_allocated_memory(True)

        self.inject("../pcapfiles/ssdp_flow.pcap") 

        fu = self.st.udp_flow_manager
        for flow in fu:
            s = flow.ssdp_info
            self.assertNotEqual(s, None)

    def test47(self):
        """ Verify the functionality of dynamic memory with the HTTP Protocol """

        self.st.decrease_allocated_memory("HTTP", 10000)

        # enable the dynamic memory for just http 
        self.st.set_dynamic_allocated_memory("HTTP", True)

        self.inject("../pcapfiles/two_http_flows_noending.pcap")
        
        ft = self.st.tcp_flow_manager
        for flow in ft:
            s = flow.http_info
            self.assertNotEqual(s, None)
            self.assertNotEqual(s.host_name, None)
            self.assertNotEqual(s.uri, None)
            self.assertNotEqual(s.user_agent, None)

    def test48(self):
        """ Complex detection on the HTTP Protocol """

        def callback_1(flow):
            h = flow.http_info
            self.assertEqual(flow.packets_layer7, 2)

            """ The first uri should match on this point """
            self.assertEqual(h.uri, "/css/global.css?v=20121120a")
            self.called_callback += 1

        def callback_2(flow):
            h = flow.http_info
            self.assertEqual(flow.packets_layer7, 5)
            
            """ The first uri should match on this point because didnt change """
            self.assertEqual(h.uri, "/css/global.css?v=20121120a")
            self.called_callback += 1

        def callback_3(flow):
            h = flow.http_info
            self.assertEqual(flow.packets_layer7, 15)
            self.assertEqual(h.uri, "/images_blogs/gadgetlab/2013/07/MG_9640edit-200x100.jpg")
            self.called_callback += 1

        def callback_4(flow):
            h = flow.http_info
            self.assertEqual(flow.packets_layer7, 16)
            self.assertEqual(h.uri, "/images_blogs/gadgetlab/2013/07/MG_9640edit-200x100.jpg")
            self.called_callback += 1
        
        def callback_5(flow):
            h = flow.http_info
            self.assertEqual(flow.packets_layer7, 31)
            self.assertEqual(h.uri, "/images_blogs/thisdayintech/2013/03/set.jpg")
            self.called_callback += 1

        dm = pyaiengine.DomainNameManager()
        rm = pyaiengine.RegexManager()
        r1 = pyaiengine.Regex("matchs on 1 response", b"^\\x1f\\x8b\\x08\\x00\\x00\\x00\\x00\\x00\\x00\\x00.*$", callback_1)
        r2 = pyaiengine.Regex("matchs on last response", b"^.*\\x5a\\xf2\\x74\\x8f\\x39\\x4e\\x00\\x00$", callback_2)
        r3 = pyaiengine.Regex("matchs on 4 response", b"^\\xff\\xd8\\xff\\xe0\\x00\\x10\\x4a\\x46\\x49\\x46.*$", callback_3)
        r4 = pyaiengine.Regex("matchs on 4 response", b"^\\xf6\\xae\\x30\\x7a\\x1f\\x3c\\xea\\x7e.*$", callback_4)
        r5 = pyaiengine.Regex("matchs on other response", b"^\\xff\\xd8\\xff\\xe1\\x00\\x18\\x45\\x78\\x69.*$", callback_5)
        d = pyaiengine.DomainName("No trusted domain", ".wired.com")

        dm.add_domain_name(d)

        rm.add_regex(r1)

        r1.next_regex = r2
        r2.next_regex = r3
        r3.next_regex = r4
        r4.next_regex = r5

        """ Attach the RegexManager to process all the payloads from wired """
        d.regex_manager = rm

        # enable the dynamic memory for just http 
        self.st.set_dynamic_allocated_memory("HTTP", True)

        self.st.set_domain_name_manager(dm, "http")

        self.inject("../pcapfiles/two_http_flows_noending.pcap")

        self.assertEqual(self.called_callback, 5)
        self.assertEqual(d.matchs, 1)
        self.assertEqual(r1.matchs, 1)
        self.assertEqual(r2.matchs, 1)
        self.assertEqual(r3.matchs, 1)
        self.assertEqual(r4.matchs, 1)
        self.assertEqual(r5.matchs, 1)

    def test49(self):
        """ Verify the ban domains on SSL traffic """

        d = pyaiengine.DomainName("Google Drive Cert", ".drive.google.com")
        d.callback = None

        dm = pyaiengine.DomainNameManager()
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm, "SSLProtocol", False)

        self.inject("../pcapfiles/sslflow.pcap")

        self.assertEqual(d.matchs, 1)

        flow = None
        for f in self.st.tcp_flow_manager:
            flow = f
            break
        
        c = self.st.get_cache("ssl")
        self.assertNotEqual(flow, None)
        self.assertNotEqual(flow.ssl_info, None)
        self.assertEqual(flow.ssl_info.server_name, "")
        self.assertEqual(len(c), 0)

    def test50(self):
        """ Verify the order of the flow when iterate through the flow manager 
            192.168.1.1:57077:6:54.230.87.203:443
            192.168.1.1:57078:6:54.230.87.203:443
            192.168.1.1:57079:6:54.230.87.203:443
            192.168.1.1:57080:6:54.230.87.203:443
        """

        source_port = 57077
        self.inject("../pcapfiles/amazon_4ssl_flows.pcap")

        self.assertEqual(len(self.st.tcp_flow_manager), 4)

        for f in self.st.tcp_flow_manager:
            self.assertEqual(source_port, f.src_port)
            source_port = source_port + 1

    def test51(self):
        """ Verify the functionality of the IPRadixTrees """

        def regex_callback(flow):
            r = flow.regex
            i = flow.ip_set
            if (sys.version_info.major > 2):
                self.assertRegex(flow.dst_ip, "(95.100.96.10|95.100.96.48)")
            else:
                self.assertRegexpMatches(flow.dst_ip, "(95.100.96.10|95.100.96.48)")
            self.assertEqual(r.name, "generic http")
            self.assertEqual(i.name, "something")
            self.called_callback += 1

        def ipset_callback(flow):
            r = flow.regex
            i = flow.ip_set
            self.assertNotEqual(i, None)
            self.assertEqual(i.name, "something")
            self.assertEqual(r, None)
            self.called_callback += 1

        rm = pyaiengine.RegexManager()
        ix = pyaiengine.IPRadixTree(["95.100.96.10/24", "192.172.12.1"])

        """ Change the name of the radix tree """
        self.assertEqual(ix.name, "Generic IPRadixTree")
        ix.name = "something"

        ix.regex_manager = rm
        ix.callback = ipset_callback
        im = pyaiengine.IPSetManager()

        self.assertEqual(ix.callback, ipset_callback)

        self.assertEqual("Generic IPSetManager", im.name)
        im.name = "buuu"
        self.assertEqual("buuu", im.name)

        im.add_ip_set(ix)
        self.st.tcp_ip_set_manager = im

        r = pyaiengine.Regex("generic http", "^GET.*HTTP")
        r.callback = regex_callback
        rm.add_regex(r)

        self.st.enable_nids_engine = True

        self.inject("../pcapfiles/two_http_flows_noending.pcap")

        self.assertEqual(self.called_callback, 4)
        self.assertEqual(ix.lookups_in, 2)
        self.assertEqual(r.matchs, 2)

        """ Verify the output of the IPRadixTree """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            ix.show()

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 3)
        f.close()

    def test52(self):
        """ verify that we have two different records on the adaptors with smtp-starttls """

        db = databaseTestAdaptor()

        """ with 16 we generate two records """
        self.st.set_tcp_database_adaptor(db, 16)

        self.inject("../pcapfiles/smtp_starttls.pcap")

        self.assertEqual(len(db.all_data), 2)

        smtp_r = json.loads(db.all_data[1])
        ssl_r = json.loads(db.all_data[2])

        self.assertEqual(smtp_r["layer7"], "smtp")
        self.assertEqual(ssl_r["layer7"], "ssl")
        self.assertEqual(ssl_r["info"]["issuer"], "Google Internet Authority G2")

        self.assertEqual(smtp_r["info"]["tls"], True)
        self.assertEqual(smtp_r["ip"]["src"], ssl_r["ip"]["src"])
        self.assertEqual(smtp_r["ip"]["dst"], ssl_r["ip"]["dst"])
        self.assertEqual(smtp_r["port"]["src"], ssl_r["port"]["src"])
        self.assertEqual(smtp_r["port"]["dst"], ssl_r["port"]["dst"])

    def test53(self):
        """ verify that we have two different records on the adaptors with imap-starttls """

        db = databaseTestAdaptor()

        """ with 16 we generate two records """
        self.st.set_tcp_database_adaptor(db, 16)

        self.inject("../pcapfiles/imap_starttls.pcap")

        self.assertEqual(len(db.all_data), 2)

        imap_r = json.loads(db.all_data[1])
        ssl_r = json.loads(db.all_data[2])

        self.assertEqual(imap_r["layer7"], "imap")
        self.assertEqual(ssl_r["layer7"], "ssl")

        self.assertEqual(imap_r["info"]["tls"], True)
        self.assertEqual(imap_r["ip"]["src"], ssl_r["ip"]["src"])
        self.assertEqual(imap_r["ip"]["dst"], ssl_r["ip"]["dst"])
        self.assertEqual(imap_r["port"]["src"], ssl_r["port"]["src"])
        self.assertEqual(imap_r["port"]["dst"], ssl_r["port"]["dst"])

    def test54(self):
        """ verify that we have two different records on the adaptors with pop-starttls """

        db = databaseTestAdaptor()

        """ with 16 we generate two records """
        self.st.set_tcp_database_adaptor(db, 16)

        self.inject("../pcapfiles/pop3_starttls.pcap")

        self.assertEqual(len(db.all_data), 2)

        pop_r = json.loads(db.all_data[1])
        ssl_r = json.loads(db.all_data[2])

        self.assertEqual(pop_r["layer7"], "pop")
        self.assertEqual(ssl_r["layer7"], "ssl")

        self.assertEqual(pop_r["info"]["tls"], True)
        self.assertEqual(pop_r["ip"]["src"], ssl_r["ip"]["src"])
        self.assertEqual(pop_r["ip"]["dst"], ssl_r["ip"]["dst"])
        self.assertEqual(pop_r["port"]["src"], ssl_r["port"]["src"])
        self.assertEqual(pop_r["port"]["dst"], ssl_r["port"]["dst"])

    def test55(self):

        def callback_domain(flow):
            h = flow.http_info
            self.assertEqual(flow.packets_layer7, 1)
            self.assertEqual(h.uri, "/index.htm?v=5&eh=&ts=0&u2=lpdDC5KtfXqwOCkfKJ0O")
            self.assertEqual(flow.regex, None)
            self.called_callback += 1

        def callback(flow):
            h = flow.http_info
            self.assertEqual(flow.packets_layer7, 2)
            self.assertEqual(h.uri, "/index.htm?v=5&eh=&ts=0&u2=lpdDC5KtfXqwOCkfKJ0O")
            self.assertEqual(flow.regex.name, r.name)
            self.called_callback += 1

        dm = pyaiengine.DomainNameManager()
        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("matchs on 1 response", b"^.*PNG.*(?!.*IHDR).*$", callback)
        d = pyaiengine.DomainName("No trusted domain", ".ru", callback_domain)
        
        dm.add_domain_name(d)

        rm.add_regex(r)

        """ Attach the RegexManager to process all the payloads from wired """
        d.regex_manager = rm

        # enable the dynamic memory for just http 
        self.st.set_dynamic_allocated_memory("HTTP", True)

        self.st.set_domain_name_manager(dm, "http")

        self.inject("../pcapfiles/http_flow.pcap")

        self.assertEqual(self.called_callback, 2)

    def test56(self):

        def callback_domain(flow):
            s = flow.smtp_info
            """ Spammy address """
            self.assertEqual(s.mail_from, "IVepijy@UTkSgBvIxlGQiKRIhmDTUxnmrOwzE.gov")
            self.called_callback += 1

        def callback_anomaly(flow):
            s = flow.smtp_info
            self.assertEqual(s.mail_from, "IVepijy@UTkSgBvIxlGQiKRIhmDTUxnmrOwzE.gov")
            self.assertGreater(len(flow.payload), 512)
            self.called_callback += 1

        dm = pyaiengine.DomainNameManager()
        d = pyaiengine.DomainName("No trusted domain", ".gov", callback_domain)

        dm.add_domain_name(d)

        self.st.set_dynamic_allocated_memory("SMTP", True)

        """ Set the anomaly manager callback """
        self.st.set_anomaly_callback(callback_anomaly, "smtp")
        self.st.set_anomaly_callback(callback_anomaly, "SMTP")
        self.st.set_anomaly_callback(callback_anomaly, "smtpprotocol")

        self.st.set_domain_name_manager(dm, "SMTP")

        self.inject("../pcapfiles/smtp_flow.pcap")

        self.assertEqual(self.called_callback, 2)

        """ Verify the output of the anomaly that have been set """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.st.show_statistics(5)
        f.close()

    def test57(self):
        """ verify the counters and json output of the DCERPC component """

        db = databaseTestAdaptor()

        """ with 16 we generate two records """
        self.st.set_tcp_database_adaptor(db, 16)

        self.inject("../pcapfiles/dcerpc_traffic.pcapng")

        d = json.loads(db.all_data[1])
        c = self.st.get_counters("dcerpc");

        self.assertEqual(d["layer7"], "dcerpc")
        self.assertEqual("uuid" in d["info"], True)
        
        self.assertEqual(c["binds"], 10)
        self.assertEqual(c["bind acks"], 10)

        for f in self.st.tcp_flow_manager:
            a = f.dcerpc_info.uuid

        """ print the output of the cache """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.st.show_cache("dcerpc")

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 4)
        f.close()

    def test58(self):
        """ disable DCERPC protocol and check values """

        self.st.set_dynamic_allocated_memory(True)
        self.st.disable_protocol("dcerpc")

        self.inject("../pcapfiles/dcerpc_traffic.pcapng")

        c = self.st.get_counters("dcerpc");

        self.assertEqual(c["binds"], 0)
        self.assertEqual(c["bind acks"], 0)

    def test59(self):
        """ disable DNS and HTTP protocol and check values """

        self.st.disable_protocol("dns")
        self.st.disable_protocol("HTTPProtocol")

        self.inject("../pcapfiles/accessgoogle.pcap")

        c1 = {'L7 bytes': 0, 'heads': 0, 'responses': 0, 'puts': 0, 'packets': 0, 'bytes': 0,
            'connects': 0, 'options': 0, 'posts': 0, 'banned hosts': 0, 'others': 0,
            'requests': 0, 'gets': 0, 'traces': 0, 'allow hosts': 0, 'deletes': 0}
        c = self.st.get_counters("http")

        self.assertDictEqual(c, c1)

        c2 = {'type SRV': 0, 'type AAAA': 0, 'type SSHFP': 0, 'type LOC': 0, 'type PTR': 0,
            'type NS': 0, 'type A': 0, 'type MX': 0, 'type ANY': 0, 'allow queries': 0,
            'type IXFR': 0, 'type DNSKEY': 0, 'type others': 0, 'queries': 0, 'type CNAME': 0,
            'responses': 0, 'type SOA': 0, 'banned queries': 0, 'type DS': 0, 'type TXT': 0}

        c = self.st.get_counters("DNSProtocol")

        self.assertDictEqual(c, c2)

        c3 = {'bytes': 1826, 'packets': 4}
        c = self.st.get_counters("tcpgeneric") # take the HTTP traffic

        self.assertDictEqual(c, c3)

        """ flush the flow tables """
        self.st.tcp_flow_manager.flush()
        self.st.udp_flow_manager.flush()

        self.st.enable_protocol("DNSProtocol")
        self.st.enable_protocol("HTTP")

        self.inject("../pcapfiles/accessgoogle.pcap")

        c = self.st.get_counters("HtTp");

        c4 = {'L7 bytes': 218, 'heads': 0, 'responses': 2, 'puts': 0, 'packets': 4,
            'bytes': 1826, 'connects': 0, 'options': 0, 'posts': 0, 'banned hosts': 0,
            'others': 0, 'requests': 2, 'gets': 2, 'traces': 0, 'allow hosts': 2, 'deletes': 0}

        self.assertDictEqual(c, c4)

        c5 = {'type MX': 0, 'type DS': 0, 'type SOA': 0, 'type CNAME': 0, 'responses': 2,
            'type SRV': 0, 'type TXT': 0, 'type ANY': 0, 'type others': 0, 'type SSHFP': 0,
            'type LOC': 0, 'type DNSKEY': 0, 'type IXFR': 0, 'type AAAA': 1, 'type NS': 0,
            'queries': 2, 'allow queries': 2, 'banned queries': 0, 'type PTR': 0, 'type A': 1}
        c = self.st.get_counters("DNS");

        self.assertDictEqual(c, c5)

        c = self.st.get_counters("tcpgeneric") # Should be the same as before

        self.assertDictEqual(c, c3)
    
    def test60(self):
        """ Operate with pop traffic """

        def pop_callback(flow):
            a = flow.pop_info
            self.assertEqual(a.user_name, "plod")
            self.called_callback += 1

        dm = pyaiengine.DomainNameManager()
        d = pyaiengine.DomainName("No trusted domain", "*", pop_callback)

        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm, "pop")
        self.st.set_dynamic_allocated_memory(True)

        self.inject("../pcapfiles/pop_flow.pcap")

        c = self.st.get_counters("pop");

        self.assertEqual(c["commands"], 15)
        self.assertEqual(c["responses"], 16)
        self.assertEqual(self.called_callback, 1)

        c = self.st.get_cache("pop")

        """ print the output of the cache """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.st.show_cache("pop")

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 2)
        f.close()

    def test61(self):
        """ Test case for IMAP traffic """

        def imap_callback(flow):
            a = flow.imap_info
            self.assertEqual(a.user_name, "samir")
            self.called_callback += 1

        dm = pyaiengine.DomainNameManager()
        d = pyaiengine.DomainName("No trusted domain", "*", imap_callback)

        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm, "imap")
        self.st.set_dynamic_allocated_memory(True)

        self.inject("../pcapfiles/imap_flow.pcap")

        c = self.st.get_counters("imap");

        self.assertEqual(c["commands"], 6)
        self.assertEqual(c["responses"], 12)
        self.assertEqual(self.called_callback, 1)

        c = self.st.get_cache("imap")

        """ print the output of the cache """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.st.show_cache("imap")

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 2)
        f.close()

    def test62(self):
        """ Test case for SMB traffic """

        self.st.set_dynamic_allocated_memory(True)

        self.inject("../pcapfiles/smb_flow.pcap")

        c = self.st.get_counters("smb");

        self.assertEqual(c["create files"], 8)

        c = self.st.get_cache("smb")

        """ print the output of the cache """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.st.show_cache("smb")

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 3)
        f.close()

        for f in self.st.tcp_flow_manager:
            flow = f.smb_info.filename

    def test63(self):
        """ Test case for MQTT traffic """

        self.st.set_dynamic_allocated_memory(True)

        self.inject("../pcapfiles/ipv4_mqtt.pcap")

        for f in self.st.tcp_flow_manager:
            a = f.mqtt_info.topic

        c = self.st.get_counters("mqtt");

        self.assertEqual(c["commands"], 8)

        c = self.st.get_cache("mqtt")

        """ print the output of the cache """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.st.show_cache("mqtt")

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 2)
        f.close()

    def test64(self):
        """ Test case for matchs several Regexs on DCERPC """

        rm = pyaiengine.RegexManager()
        r1 = pyaiengine.Regex("r1", b"^\\x05\\x00\\x00\\x83\\x10\\x00\\x00\\x00\\x6c.*$")
        r2 = pyaiengine.Regex("r2", b"^\\x05\\x00\\x0b\\x03.*$")
        r3 = pyaiengine.Regex("r3", b"^.*\\xde\\xed\\xfc\\x0c.*$")
        r4 = pyaiengine.Regex("r4", b"^\\xde\\xed\\xfc\\x0c.*$")

        rm.add_regex(r1)
        rm.add_regex(r2)
        rm.add_regex(r3)
        rm.add_regex(r4)

        self.st.enable_nids_engine = True
        self.st.tcp_regex_manager = rm

        self.st.disable_protocol("dcerpc")

        self.inject("../pcapfiles/dcerpc_traffic.pcapng")

        self.assertEqual(r1.matchs, 4)
        self.assertEqual(r2.matchs, 8)
        self.assertEqual(r3.matchs, 0)
        self.assertEqual(r4.matchs, 0)

        """ Shows the matched regexs """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            rm.show_matched_regexs()

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 3)
        f.close()

    def test65(self):
        """ Verify the coap protocol functionality with domains and uri sets """

        def domain_callback(flow):
            self.called_callback += 1

        def uri_callback(flow):
            self.assertEqual(len(uset), 1)
            self.assertEqual(uset.lookups, 1)
            self.assertEqual(uset.lookups_in, 1)
            self.assertEqual(uset.lookups_out, 0)
            self.called_callback += 1

        uset = pyaiengine.HTTPUriSet()
        uset.add_uri("/somepath/really/maliciousuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuua/time")
        uset.callback = uri_callback

        d = pyaiengine.DomainName("Localhost domain", "localhost")
        d.http_uri_set = uset

        dm = pyaiengine.DomainNameManager()
        d.callback = domain_callback
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm, "CoAPProtocol")

        self.inject("../pcapfiles/ipv4_coap_big_uri.pcap")

        self.assertEqual(self.called_callback, 2)
        self.assertEqual(d.matchs, 1)

        """ Shows the coap cache """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.st.show_cache("coap")

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 2)
        f.close()

        c = self.st.get_cache("coap")
        c1 = {'localhost': 1}
        self.assertDictEqual(c, c1)

    def test66(self):
        """ Verify that a Regex that matchs with a URI could handle the link
            to another RegexManager that will have regex for the payload of the HTTP """

        def domain_callback(flow):
            self.called_callback += 1
            self.assertEqual(flow.packets_layer7, 1)
            """ The flow.regex_manager is null on this point and assign
                the flow.http_info.matched_domain_name.regex_manager after this call """
            self.assertIsNone(flow.regex_manager)

        def uri_callback(flow):
            self.called_callback += 1
            self.assertEqual(flow.packets_layer7, 1)
            self.assertIsNone(flow.regex_manager)

        def payload_callback(flow):
            self.called_callback += 1
            self.assertEqual(flow.packets_layer7, 2)
            self.assertEqual(flow.regex_manager.name, rm1.name)

        d = pyaiengine.DomainName("All HTTP", "*", domain_callback)
        r1 = pyaiengine.Regex("Some URI", "^/$", uri_callback)
        r2 = pyaiengine.Regex("HTTP Payload regex", "<HTML><HEAD>", payload_callback)

        dm = pyaiengine.DomainNameManager()
        dm.add_domain_name(d)

        rm1 = pyaiengine.RegexManager([ r1 ])
        rm2 = pyaiengine.RegexManager([ r2 ])

        """ Link to the DomainName d to the RegexManager for analise the uris """
        d.http_uri_regex_manager = rm1

        """ Link to the Regex another RegexManager """
        r1.next_regex_manager = rm2

        self.st.set_domain_name_manager(dm, "HTTP")

        self.inject("../pcapfiles/accessgoogle.pcap")

        self.assertEqual(self.called_callback, 3)
        self.assertEqual(d.matchs, 1)

    def test67(self):
        """ Verify that using the label for inject python code """

        def domain_callback(flow):
            """ The code is executed on other time """
            exec(flow.label) in locals()
            self.called_callback += 1
            self.assertEqual(flow.label, "Hi change me!")

        def ipset_callback(flow):
            """ We use the label to put python code that later will be executed """
            flow.label = "flow.label=\"Hi change me!\""
            self.called_callback += 1

        im = pyaiengine.IPSetManager()
        ipset = pyaiengine.IPSet("Generic set", [ "74.125.24.99" ], ipset_callback)
        d = pyaiengine.DomainName("All HTTP", ".google.com", domain_callback)

        im.add_ip_set(ipset)
        self.st.tcp_ip_set_manager = im

        dm = pyaiengine.DomainNameManager()
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm, "HTTP")

        self.inject("../pcapfiles/accessgoogle.pcap")

        self.assertEqual(self.called_callback, 2)
        self.assertEqual(d.matchs, 1)

    def test68(self):
        """ Verify on SMTP access to mail data with regex """

        def domain_callback(flow):
            self.called_callback += 1

        def regex1_callback(flow):
            self.called_callback += 1
            cad = ""
            for i in flow.payload:
                cad += str(unichr(i))
            self.assertGreater(cad.find("GCC"), 1000)

        def regex2_callback(flow):
            self.called_callback += 1
       
        rm = pyaiengine.RegexManager()
        r1 = pyaiengine.Regex("Some r1", "^.*GCC.*$", regex1_callback)
        r2 = pyaiengine.Regex("Some r2", "^.*(NextPart_000_0004_01CA45B0.095693F0).*$", regex2_callback)
        d = pyaiengine.DomainName("Some SMTP traffic", ".patriots.in", domain_callback)

        rm.add_regex(r1)

        r1.next_regex = r2
        d.regex_manager = rm
        dm = pyaiengine.DomainNameManager()
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm, "SMTP")

        self.inject("../pcapfiles/smtp.pcap")

        self.assertEqual(self.called_callback, 3)
        self.assertEqual(d.matchs, 1)
        self.assertEqual(r1.matchs, 1)
        self.assertEqual(r2.matchs, 1)

class StackMobileTests(unittest.TestCase):

    def setUp(self):
        self.st = pyaiengine.StackMobile()
        self.pd = pyaiengine.PacketDispatcher()
        self.pd.stack = self.st
        self.st.tcp_flows = 2048
        self.st.udp_flows = 1024
        self.called_callback = 0 

    def tearDown(self):
        pass

    def inject(self, pcapfile):
        with pyaiengine.PacketDispatcher(pcapfile) as pd:
            pd.stack = self.st
            pd.run()

    def test01(self):
        """ Verify the integrity of the sip fields """

        db = databaseTestAdaptor()

        self.st.set_udp_database_adaptor(db)

        self.inject("../pcapfiles/gprs_sip_flow.pcap") 

        for flow in self.st.udp_flow_manager:
            self.assertEqual(flow.mqtt_info, None)
            self.assertEqual(flow.coap_info, None)
            self.assertEqual(flow.http_info, None)
            self.assertEqual(flow.dns_info, None)
            self.assertEqual(flow.ssl_info, None)
            self.assertNotEqual(flow.sip_info, None)
            self.assertEqual(flow.sip_info.from_name, "\"User1\" <sip:ng40user1@apn.sip.voice.ng4t.com>;tag=690711")
            self.assertEqual(flow.sip_info.to_name, "\"User1\" <sip:ng40user1@apn.sip.voice.ng4t.com>")
            self.assertEqual(flow.sip_info.uri, "sip:10.255.1.111:5090")
            self.assertEqual(flow.sip_info.via, "SIP/2.0/UDP 10.255.1.1:5090;branch=z9hG4bK199817980098801998")

        d = json.loads(db.lastdata)
        c = self.st.get_counters("SIPProtocol")
        self.assertEqual(c["requests"], 7)
        self.assertEqual(c["responses"], 7)
        self.assertEqual(c["registers"], 2)

        if "info" in d:
            self.assertEqual(d["info"]["uri"], "sip:apn.sip.voice.ng4t.com")
            self.assertEqual(d["info"]["from"], "\"User1\" <sip:ng40user1@apn.sip.voice.ng4t.com>;tag=690711")
            self.assertEqual(d["info"]["to"], "\"User1\" <sip:ng40user1@apn.sip.voice.ng4t.com>")
            self.assertEqual(d["info"]["via"], "SIP/2.0/UDP 10.255.1.1:5090;branch=z9hG4bK199817980098801998")
        else:
            self.assertTrue(False)

        c = self.st.get_cache("SIP")

        """ print the output of the cache """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.st.show_cache("SIP")

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 4)
        f.close()

        self.st.release_cache("SIPProtocol")
        
        for flow in self.st.udp_flow_manager:
            self.assertEqual(flow.sip_info, None)

    def test02(self):
        """ Test some regex on the mobile stack """

        rm = pyaiengine.RegexManager()
        r1 = pyaiengine.Regex("r1", b"^\\x58\\x67\\x77\\x86.*$")
        r2 = pyaiengine.Regex("r2", b"^.*\\xde\\xed\\xfc\\x0c.*$")

        rm.add_regex(r1)

        r1.next_regex = r2
 
        self.assertEqual(sys.getrefcount(r2), 3)

        self.st.tcp_regex_manager = rm

        self.inject("../pcapfiles/gprs_ftp.pcap")

        self.assertEqual(r1.matchs, 1)
        self.assertEqual(r2.matchs, 1)

        ft = self.st.tcp_flow_manager
        self.assertEqual(len(ft), 1)
        ft.flush()
        self.assertEqual(len(ft), 0)

        """ Unset the next regex of r1 """
        r1.next_regex = None
        self.assertEqual(sys.getrefcount(r2), 2)

        self.inject("../pcapfiles/gprs_ftp.pcap")

        self.assertEqual(r1.matchs, 2)
        self.assertEqual(r2.matchs, 1)
        self.assertEqual(r1.next_regex, None)
        self.assertEqual(r2.next_regex, None)

    def test03(self):
        """ Tests the database adaptor on tcp and callbacks on regex """
        def callback1(flow):
            self.called_callback += 1
            self.assertNotEqual(flow.regex, None)
            self.assertEqual(flow.regex.name, "r1")

        def callback2(flow):
            self.assertNotEqual(flow.regex, None)
            self.assertEqual(flow.regex.name, "r2")
            self.called_callback += 1

        db = databaseTestAdaptor()

        self.st.set_tcp_database_adaptor(db)

        rm = pyaiengine.RegexManager()
        r1 = pyaiengine.Regex("r1", b"^\\x58\\x67\\x77\\x86.*$", callback1)
        r2 = pyaiengine.Regex("r2", b"^.*\\xde\\xed\\xfc\\x0c.*$", callback2)

        rm.add_regex(r1)
        r1.next_regex = r2
 
        self.st.tcp_regex_manager = rm
        
        self.inject("../pcapfiles/gprs_ftp.pcap")

        self.assertEqual(self.called_callback, 2)
        self.assertEqual(r1.matchs, 1)
        self.assertEqual(r2.matchs, 1)

        d = json.loads(db.lastdata)
        self.assertEqual(d["matchs"], "r2")

    def test04(self):
        """ disable SIP protocol and check values """

        self.st.set_dynamic_allocated_memory(True)
        self.st.enable_protocol("sip")

        self.inject("../pcapfiles/gprs_sip_flow.pcap") 

        c = self.st.get_counters("SIPProtocol")
        self.assertEqual(c["requests"], 7)
        self.assertEqual(c["responses"], 7)
        self.assertEqual(c["registers"], 2)
        self.assertEqual(c["packets"], 22)
        self.assertEqual(c["bytes"], 14537)

        c = self.st.get_counters("udpgeneric")
        self.assertEqual(c["packets"], 0)
        self.assertEqual(c["bytes"], 0)
       
        self.st.udp_flow_manager.flush()
        self.st.tcp_flow_manager.flush()
        
        self.st.disable_protocol("sip")

        self.inject("../pcapfiles/gprs_sip_flow.pcap") 

        c = self.st.get_counters("SIPProtocol")
        self.assertEqual(c["requests"], 7)
        self.assertEqual(c["responses"], 7)
        self.assertEqual(c["registers"], 2)

        c = self.st.get_counters("udpgeneric")
        self.assertEqual(c["packets"], 22)
        self.assertEqual(c["bytes"], 14537)

class StackLanIPv6Tests(unittest.TestCase):

    def setUp(self):
        self.st = pyaiengine.StackLanIPv6()
        self.pd = pyaiengine.PacketDispatcher()
        self.pd.stack = self.st
        self.st.tcp_flows = 2048
        self.st.udp_flows = 1024
        self.called_callback = 0

    def tearDown(self):
        pass

    def inject(self, pcapfile):
        with pyaiengine.PacketDispatcher(pcapfile) as pd:
            pd.stack = self.st
            pd.run()

    def test01(self):
        """ Create a regex for a generic exploit """

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("generic exploit", b"\\x90\\x90\\x90\\x90\\x90\\x90\\x90")
        rm.add_regex(r)
        self.st.tcp_regex_manager = rm

        self.inject("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")

        self.assertEqual(r.matchs, 1)

    def test02(self):
        """ Create a regex for a generic exploit and a IPSet """
        def ipset_callback(flow):
            self.called_callback += 1 

        ipset = pyaiengine.IPSet("IPv6 generic set", [ "dc20:c7f:2012:11::2", "dc20:c7f:2012:11::1" ])
        ipset.add_ip_address("this is not an ip")
        ipset.add_ip_address("bbbbNOIPdc20:c7f:2012:11::1")
        ipset.add_ip_address("192.168.1.1")
        ipset.callback = ipset_callback
        im = pyaiengine.IPSetManager()

        """ There is only three valid IP address """
        self.assertEqual(len(ipset), 3)

        im.add_ip_set(ipset)
        self.st.tcp_ip_set_manager = im

        rm = pyaiengine.RegexManager()
        r1 = pyaiengine.Regex("generic exploit", b"\\x90\\x90\\x90\\x90\\x90\\x90\\x90")
        rm.add_regex(r1)
        r2 = pyaiengine.Regex("other exploit", "(this can not match)")
        rm.add_regex(r2)
        self.st.tcp_regex_manager = rm

        self.inject("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")

        self.assertEqual(r1.matchs, 1)
        self.assertEqual(r2.matchs, 0)
        self.assertEqual(self.called_callback, 1)

        ipset.remove_ip_address("dc20:c7f:2012:11::2")

    def test03(self):
        """ Create a regex for a generic exploit and a IPSet with no matching"""
        def ipset_callback(flow):
            self.called_callback += 1

         
        ips = [ "dc20:c7f:2012:11::22", 
            "dc20:c7f:2012:11::1" ]

        ipset = pyaiengine.IPSet(ips)
        ipset.callback = ipset_callback
        im = pyaiengine.IPSetManager()

        im.add_ip_set(ipset)
        self.st.tcp_ip_set_manager = im

        rm = pyaiengine.RegexManager()
        r1 = pyaiengine.Regex("generic exploit", b"\\xaa\\xbb\\xcc\\xdd\\x90\\x90\\x90")
        rm.add_regex(r1)
        r2 = pyaiengine.Regex("other exploit", "(this can not match)")
        rm.add_regex(r2)
        self.st.tcp_regex_manager = rm

        self.inject("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")

        self.assertEqual(r1.matchs, 0)
        self.assertEqual(r2.matchs, 0)
        self.assertEqual(self.called_callback, 0)

    def test04(self):
        """ Attach a database to the engine for TCP traffic """

        dbaux = databaseTestAdaptor()
        db = databaseTestAdaptor()
       
        self.assertEqual(sys.getrefcount(db), 2) 
        self.assertEqual(sys.getrefcount(dbaux), 2) 

        self.st.set_tcp_database_adaptor(db, 16)
        self.st.set_tcp_database_adaptor(dbaux, 16)
        self.assertEqual(sys.getrefcount(db), 2) 
        self.assertEqual(sys.getrefcount(dbaux), 3) 

        self.inject("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")

        self.assertEqual(dbaux.getInserts(), 1)
        self.assertEqual(dbaux.getUpdates(), 5)
        self.assertEqual(dbaux.getRemoves(), 1)
      
        self.assertEqual(sys.getrefcount(dbaux), 3) 
        # Check Protocol.cc there is a bug with python3.5 needs investigation  
        # self.st.set_tcp_database_adaptor(None)
        # self.assertEqual(sys.getrefcount(db), 2) 

    def test05(self):
        """ Attach a database to the engine for UDP traffic """

        db_udp = databaseTestAdaptor()
        db_tcp = databaseTestAdaptor()

        self.st.set_udp_database_adaptor(db_udp, 16)
        self.st.set_tcp_database_adaptor(db_tcp)

        self.inject("../pcapfiles/ipv6_google_dns.pcap")

        self.assertEqual(db_udp.getInserts(), 1)
        self.assertEqual(db_udp.getUpdates(), 1)
        self.assertEqual(db_udp.getRemoves(), 0)

        self.assertEqual(db_tcp.getInserts(), 0)
        self.assertEqual(db_tcp.getUpdates(), 0)
        self.assertEqual(db_tcp.getRemoves(), 0)
        
    def test06(self):
        """ Several IPSets with no matching"""
        def ipset_callback(flow):
            self.called_callback += 1

        ipset1 = pyaiengine.IPSet("IPSet 1", [ "dcbb:c7f:2012:11::22" ])
        ipset2 = pyaiengine.IPSet("IPSet 2", [ "dcaa:c7f:2012:11::22" ])
        ipset3 = pyaiengine.IPSet("IPSet 3", [ "dc20:c7f:2012:11::2" ])

        im = pyaiengine.IPSetManager()

        im.add_ip_set(ipset1)
        im.add_ip_set(ipset2)
        im.add_ip_set(ipset3)

        self.st.tcp_ip_set_manager = im

        self.inject("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")

        self.assertEqual(len(im), 3)
        self.assertEqual(self.called_callback, 0)
        self.assertEqual(self.st.tcp_ip_set_manager, im)

    def test07(self):
        """ Extract IPv6 address from a DomainName matched and IPSet functionality """
        def dns_callback(flow):
            for ip in flow.dns_info:
                if (ip == "2607:f8b0:4001:c05::6a"):
                    self.called_callback += 1
            self.assertEqual(flow.dns_info.matched_domain_name, d)
            self.assertEqual(flow.dns_info.query_type, 28)

        def ipset_callback(flow):
            self.called_callback += 1

        d = pyaiengine.DomainName("Google test", ".google.com")
        d.callback = dns_callback

        dm = pyaiengine.DomainNameManager()
        dm.add_domain_name(d)

        ipset1 = pyaiengine.IPSet("IPSet 1", [ "2001:abcd::1" ], ipset_callback)

        im = pyaiengine.IPSetManager()
        im.add_ip_set(ipset1)

        self.st.udp_ip_set_manager = im
        self.assertEqual(self.st.udp_ip_set_manager, im)

        self.st.set_domain_name_manager(dm, "dns")

        self.inject("../pcapfiles/ipv6_google_dns.pcap")

        self.assertEqual(ipset1.lookups, 1)
        self.assertEqual(ipset1.lookups_in, 1)
        self.assertEqual(ipset1.lookups_out, 0)
        self.assertEqual(self.called_callback, 2)

        """ Verify some of the counters of the dns protocol """

        c = self.st.get_counters("dns")
        self.assertEqual(c["queries"], 1)
        self.assertEqual(c["allow queries"], 1)
        self.assertEqual(c["banned queries"], 0)
        self.assertEqual(c["responses"], 1)
        self.assertEqual(c["type AAAA"], 1)

        for i in im:
            a = i

    def test08(self):
        """ Test the functionality of make graphs of regex, for complex detecctions """ 

        rmbase = pyaiengine.RegexManager()
        rm2 = pyaiengine.RegexManager()
        r1 = pyaiengine.Regex("r1", b"^(No hacker should visit Las Vegas).*$")
      
        rmbase.add_regex(r1)

        r1.next_regex_manager = rm2 

        r2 = pyaiengine.Regex("r2", b"(this can not match)")
        r3 = pyaiengine.Regex("r3", b"^\\x90\\x90\\x90\\x90.*$")
        rm2.add_regex(r2)
        rm2.add_regex(r3)

        self.st.tcp_regex_manager = rmbase

        self.inject("../pcapfiles/generic_exploit_ipv6_defcon20.pcap") 

        self.assertEqual(r1.matchs, 1)
        self.assertEqual(r2.matchs, 0)
        self.assertEqual(r3.matchs, 1)

    def test09(self):
        """ Another test for the functionality of make graphs of regex, for complex detecctions """

        rm1 = pyaiengine.RegexManager()
        rm2 = pyaiengine.RegexManager()
        rm3 = pyaiengine.RegexManager()
        r1 = pyaiengine.Regex("r1", b"^(No hacker should visit Las Vegas).*$")

        r1.next_regex_manager = rm2
        rm1.add_regex(r1)

        r2 = pyaiengine.Regex("r2", b"(this can not match)")
        r3 = pyaiengine.Regex("r3", b"^\\x90\\x90\\x90\\x90.*$")
        rm2.add_regex(r2)
        rm2.add_regex(r3)

        r3.next_regex_manager = rm3

        r4 = pyaiengine.Regex("r4", b"^Upgrade.*$")
        r5 = pyaiengine.Regex("r5", b"(this can not match)")

        rm3.add_regex(r4)
        rm3.add_regex(r5)

        self.st.tcp_regex_manager = rm1

        oldstack = None

        with pyaiengine.PacketDispatcher("../pcapfiles/generic_exploit_ipv6_defcon20.pcap") as pd:
            pd.stack = self.st
            pd.run()
            oldstack = self.st

        self.assertEqual(self.st, oldstack)

        self.assertEqual(r1.matchs, 1)
        self.assertEqual(r2.matchs, 0)
        self.assertEqual(r3.matchs, 1)
        self.assertEqual(r4.matchs, 1)

    def test10(self):
        """ Verify the functionality of the getCache method """

        self.inject("../pcapfiles/ipv6_google_dns.pcap") 

        d = self.st.get_cache("DNSProtocol")
        self.assertEqual(len(self.st.get_cache("DNSProtocol")), 1)
        self.assertEqual(len(self.st.get_cache("DNSProtocolNoExists")), 0)
        self.st.release_cache("DNSProtocol")
        self.assertEqual(len(self.st.get_cache("DNSProtocol")), 0)
        self.assertEqual(len(self.st.get_cache("HTTPProtocol")), 0)
        self.assertEqual(len(self.st.get_cache("SSLProtocol")), 0)

        self.assertIsNotNone(d["www.google.com"])

    def test11(self):
        """ Verify the correctness of the HTTP Protocol on IPv6 """

        self.inject("../pcapfiles/http_over_ipv6.pcap")

        c = self.st.get_counters("HTTPProtocol")
        self.assertEqual(c["requests"], 11)
        self.assertEqual(c["responses"], 11)

        d = self.st.get_cache("http")
        self.assertIsNotNone(d["media.us.listen.com"])


    def test12(self):
        """ Verify the functionality of the RegexManager on the HTTP Protocol for analise
            inside the l7 payload of HTTP on IPv6 traffic """

        def callback_domain(flow):
            self.called_callback += 1

        def callback_regex(flow):
            self.called_callback += 1
            self.assertEqual(flow.regex.name, "Regex for analysing the content of HTTP")
            self.assertEqual(flow.http_info.host_name, "media.us.listen.com")

        d = pyaiengine.DomainName("Music domain", ".us.listen.com")

        rm = pyaiengine.RegexManager()
        r1 = pyaiengine.Regex("Regex for analysing the content of HTTP", b"^\\x89\\x50\\x4e\\x47\\x0d\\x0a\\x1a\\x0a.*$")

        rm.add_regex(r1)
        r1.callback = callback_regex

        """ So the flows from listen.com will be analise the regexmanager attached """
        d.regex_manager = rm

        dm = pyaiengine.DomainNameManager()
        d.callback = callback_domain
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm, "HTTPProtocol")

        self.inject("../pcapfiles/http_over_ipv6.pcap")

        self.assertEqual(self.called_callback, 2)
        self.assertEqual(r1.matchs, 1)
        self.assertEqual(d.matchs, 1)

    def test13(self):
        """ Verify the functionality of the Evidence manager with IPv6 and UDP """

        def domain_callback(flow):
            self.called_callback += 1
            flow.evidence = True

        d = pyaiengine.DomainName("Google domain", ".google.com")

        dm = pyaiengine.DomainNameManager()
        d.callback = domain_callback
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm, "DNSProtocol")

        with pyaiengine.PacketDispatcher("../pcapfiles/ipv6_google_dns.pcap") as pd:
            pd.evidences = True
            pd.stack = self.st
            pd.run()

        self.assertEqual(self.called_callback, 1)
        self.assertEqual(d.matchs, 1)

        """ verify the integrity of the new file created """
        files = glob.glob("evidences.*.pcap")
        os.remove(files[0])

    def test14(self):
        """ Verify the functionality write on the databaseAdaptor when a important event happen on TCP """

        r = pyaiengine.Regex("my regex", b"^Upgrade.*$")

        """ Force to write the packet """        
        r.write_packet = True

        rm = pyaiengine.RegexManager([ r ])

        db = databaseTestAdaptor()

        self.st.set_tcp_database_adaptor(db)

        self.st.tcp_regex_manager = rm

        self.inject("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")

        d = json.loads(db.lastdata)
        if "matchs" in d:
            self.assertEqual(d["matchs"], "my regex")
        else:
            self.assertTrue(False)

        """ the packet is write on the packet field of the json """
        self.assertEqual(r.write_packet, True)

        packet = d["packet"]
        cad = "".join(str(chr(x)) for x in packet)
        self.assertEqual(cad.startswith("Upgrade Your Liquor Cabinet"), True)

    def test15(self):
        """ Verify the flush functionality of the FlowManager """

        """ increase the timeout of the flows because the difference between the pcaps
            is more than one year """
        self.st.flows_timeout = 60 * 60 * 500 

        self.inject("../pcapfiles/ipv6_google_dns.pcap")
        self.inject("../pcapfiles/http_over_ipv6.pcap")

        fu = self.st.udp_flow_manager
        ft = self.st.tcp_flow_manager

        self.assertEqual(len(fu), 1)
        self.assertEqual(len(ft), 1)

        fu.flush()

        self.assertEqual(len(fu), 0)
        self.assertEqual(len(ft), 1)

        ft.flush()
        
        self.assertEqual(len(fu), 0)
        self.assertEqual(len(ft), 0)

    def test16(self):
        """ Test the callbacks on the RegexManager for TCP traffic """

        def callback_re(flow):
            self.fail("shouldn't happen")

        def callback_rm(flow):
            self.assertEqual(flow.regex.matchs, 1)
            self.assertEqual(flow.regex.name, "generic exploit")
            self.called_callback += 1

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("generic exploit", b"\\x90\\x90\\x90\\x90\\x90\\x90\\x90")
        r.callback = callback_re
        rm.callback = callback_rm

        rm.add_regex(r)
        self.st.tcp_regex_manager = rm

        self.inject("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")

        self.assertEqual(self.called_callback, 1)
        self.assertEqual(r.matchs, 1)

    def test17(self):
        """ Extract IPv6 address from a DomainName matched on a adaptor """

        d = pyaiengine.DomainName("Google test", ".google.com")

        dm = pyaiengine.DomainNameManager()
        dm.add_domain_name(d)

        db = databaseTestAdaptor()
        self.st.set_udp_database_adaptor(db)

        self.inject("../pcapfiles/ipv6_google_dns.pcap")

        """ There is no domainname manager attached so the ips should not be populated """
        d = json.loads(db.lastdata)

        if "info" in d:
            if "ips" in d["info"]:
                self.assertTrue(False)
            else:
                self.assertTrue(True)
        else:
            self.assertTrue(False)

        self.st.udp_flow_manager.flush()

        self.st.set_domain_name_manager(dm, "dns")
        self.inject("../pcapfiles/ipv6_google_dns.pcap")

        """ The ips should be on the ips secction """
        d = json.loads(db.lastdata)

        if "info" in d:
            if "ips" in d["info"]:
                self.assertTrue(True)
            else:
                self.assertTrue(False)
        else:
            self.assertTrue(False)

    def test18(self):
        """ Check integrity of banned domains on DNS traffic"""

        def domain_callback(flow):
            self.called_callback += 1

        d = pyaiengine.DomainName("Google test", ".google.com")

        d.callback = domain_callback

        dm = pyaiengine.DomainNameManager()
        dm.add_domain_name(d)

        """ we are not interested on traffic from google """ 
        self.st.set_domain_name_manager(dm, "dns", False)
        self.inject("../pcapfiles/ipv6_google_dns.pcap")

        """ There is no callbacks for domains that we are not
            interested """
        self.assertEqual(self.called_callback, 0)
        self.assertEqual(d.matchs, 1)
        d = self.st.get_cache("DNSProtocol")
      
        flow = None 
        """ just one flow on the pcap """ 
        ft = self.st.udp_flow_manager
        for f in ft:
            flow = f 

        self.assertEqual("www.google.com" in d, False)
        self.assertNotEqual(flow, None)
        self.assertNotEqual(flow.dns_info, None)
        self.assertEqual(flow.dns_info.domain_name, "")

    def test19(self):
        """ Check the operator * on the DomainName """

        def domain_callback(flow):
            self.called_callback += 1

        d = pyaiengine.DomainName("All domains", "*")

        d.callback = domain_callback

        dm = pyaiengine.DomainNameManager()
        dm.add_domain_name(d)
        self.st.set_domain_name_manager(dm, "dns")

        self.inject("../pcapfiles/ipv6_google_dns.pcap")

        self.assertEqual(self.called_callback, 1)
        self.assertEqual(d.matchs, 1)
        d = self.st.get_cache("DNSProtocol")

        flow = None
        """ just one flow on the pcap """
        ft = self.st.udp_flow_manager
        for f in ft:
            flow = f

        self.assertEqual("www.google.com" in d, True)
        self.assertNotEqual(flow, None)
        self.assertNotEqual(flow.dns_info, None)
        self.assertEqual(flow.dns_info.domain_name, "www.google.com")

    def test20(self):
        """ disable DNS traffic"""

        self.inject("../pcapfiles/ipv6_google_dns.pcap")

        c = self.st.get_counters("DNSProtocol")
        c1 = {'type MX': 0, 'type DS': 0, 'type SOA': 0, 'type CNAME': 0, 
            'responses': 1, 'type SRV': 0, 'type TXT': 0, 'type ANY': 0, 
            'type others': 0, 'type SSHFP': 0, 'type LOC': 0, 'type DNSKEY': 0, 
            'type IXFR': 0, 'type AAAA': 1, 'type NS': 0, 'queries': 1, 
            'allow queries': 1, 'banned queries': 0, 'type PTR': 0, 'type A': 0}
        
        self.assertDictEqual(c, c1)

        c2 = {'bytes': 0, 'packets': 0}
        c = self.st.get_counters("UDPGenericProtocol")

        self.assertDictEqual(c, c2)

        self.st.udp_flow_manager.flush()
        self.st.disable_protocol("dns")

        self.inject("../pcapfiles/ipv6_google_dns.pcap")

        c = self.st.get_counters("DNSProtocol")

        self.assertDictEqual(c, c1)

        c3 = {'bytes': 92, 'packets': 2}
        c = self.st.get_counters("udpgeneric")

        self.assertDictEqual(c, c3)

    def test21(self):
        """ Disable and enable HTTP """

        self.inject("../pcapfiles/http_over_ipv6.pcap")

        c = self.st.get_counters("httP")
        c1 = {'L7 bytes': 394393, 'heads': 0, 'responses': 11, 'puts': 0, 'packets': 318, 
            'bytes': 400490, 'connects': 0, 'options': 0, 'posts': 0, 'banned hosts': 0, 
            'others': 0, 'requests': 11, 'gets': 11, 'traces': 0, 'allow hosts': 11, 'deletes': 0}

        self.assertDictEqual(c, c1)

        c2 = {'bytes': 0, 'packets': 0}
        c = self.st.get_counters("tcpgeneric")

        self.assertDictEqual(c, c2)

        self.st.tcp_flow_manager.flush()
        self.st.disable_protocol("http")

        self.inject("../pcapfiles/http_over_ipv6.pcap")

        c = self.st.get_counters("httP")
        self.assertDictEqual(c, c1)

        c3 = {'bytes': 400490, 'packets': 318}
        c = self.st.get_counters("tcpgeneric")

        self.assertDictEqual(c, c3)

    def test22(self):
        """ DHCPv6 traffic test """

        self.st.set_dynamic_allocated_memory(True)

        self.inject("../pcapfiles/ipv6_dhcp6.pcap")

        """ Test the output show_cache """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.st.show_cache("dhcp6")

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 2)
        f.close()

        c = self.st.get_cache("dhcp6")
        c1 = {'TSE-MANAGEMENT': 1}
        self.assertDictEqual(c, c1)

        for f in self.st.udp_flow_manager:
            a = f.dhcp6_info.host_name 
            b = f.dhcp6_info.ip

class StackLanLearningTests(unittest.TestCase):

    def setUp(self):
        self.st = pyaiengine.StackLan()
        self.pd = pyaiengine.PacketDispatcher()
        self.pd.stack = self.st
        self.st.tcp_flows = 2048
        self.st.udp_flows = 1024
        self.f = pyaiengine.FrequencyGroup()

    def tearDown(self):
        pass

    def inject(self, pcapfile, pcapfilter = None):
        self.pd.open(pcapfile)
        if (pcapfilter != None):
            self.pd.pcap_filter = pcapfilter 
        self.pd.run()
        self.pd.close()

    def test01(self):

        self.f.reset()
        self.st.enable_frequency_engine = True

        self.inject("../pcapfiles/two_http_flows_noending.pcap")

        self.assertEqual(self.f.total_process_flows, 0)
        self.assertEqual(self.f.total_computed_frequencies, 0)

        """ Add the TCP Flows of the FlowManager on the FrequencyEngine """
        self.f.add_flows_by_destination_port(self.st.tcp_flow_manager)
        self.f.compute()
    
        self.assertEqual(self.f.total_process_flows, 2)
        self.assertEqual(self.f.total_computed_frequencies, 1)

    def test02(self):
        
        self.f.reset()
        self.st.enable_frequency_engine = True
        
        self.inject("../pcapfiles/tor_4flows.pcap")

        self.assertEqual(self.f.total_process_flows, 0)
        self.assertEqual(self.f.total_computed_frequencies, 0)

        """ Add the TCP Flows of the FlowManager on the FrequencyEngine """
        self.f.add_flows_by_destination_port(self.st.tcp_flow_manager)
        self.f.compute()

        self.assertEqual(len(self.f.get_reference_flows_by_key("80")), 4)
        self.assertEqual(len(self.f.get_reference_flows()), 4)
        self.assertEqual(len(self.f.get_reference_flows_by_key("8080")), 0)
        self.assertEqual(self.f.total_process_flows, 4)
        self.assertEqual(self.f.total_computed_frequencies, 1)

    def test03(self):
        """ Integrate with the learner to generate a regex """
        learn = pyaiengine.LearnerEngine()

        self.f.reset()
        self.st.enable_frequency_engine = True
        
        self.inject("../pcapfiles/tor_4flows.pcap")

        """ Add the TCP Flows of the FlowManager on the FrequencyEngine """
        self.f.add_flows_by_destination_port(self.st.tcp_flow_manager)
        self.f.compute()

        flow_list = self.f.get_reference_flows()
        self.assertEqual(self.f.total_computed_frequencies, 1)
        learn.agregate_flows(flow_list)
        learn.compute()

        self.assertEqual(learn.flows_process, 4)
 
        """ Get the generated regex and compile with the regex module """
        try:
            rc = re.compile(learn.regex)		
            self.assertTrue(True)	
        except:
            self.assertFalse(False)	
      
    def test04(self):
        """ Switch from normal mode to learner mode and check flow and caches status """
        learn = pyaiengine.LearnerEngine()

        self.f.reset()
        self.st.enable_frequency_engine = True

        """ The filter tcp and port 55354 will filter just one HTTP flow
            that contains exactly 39 requests and 38 responses """
        self.inject("../pcapfiles/two_http_flows_noending.pcap", pcapfilter="tcp and port 55354")

        """ Add the TCP Flows of the FlowManager on the FrequencyEngine """
        self.f.add_flows_by_destination_port(self.st.tcp_flow_manager)
        self.f.compute()

        flow_list = self.f.get_reference_flows()
        self.assertEqual(self.f.total_computed_frequencies, 1)
        learn.agregate_flows(flow_list)
        learn.compute()

        self.assertEqual(learn.flows_process, 1)
        self.assertEqual(len(self.st.tcp_flow_manager), 1)

        flow1 = None
        flow2 = None
        for f in self.st.tcp_flow_manager:
            flow1 = f

        """ Switch to normal mode and inject the other flow """

        self.st.enable_frequency_engine = False
        self.inject("../pcapfiles/two_http_flows_noending.pcap", pcapfilter="tcp and port 49503")

        for f in self.st.tcp_flow_manager:
            if f.src_port == 49503:
                flow2 = f

        self.assertIsNotNone(flow1)
        self.assertEqual(flow1.l7_protocol_name, "TCPFrequencyProtocol")
        self.assertIsNotNone(flow1.frequencies)
        self.assertIsNotNone(flow1.packet_frequencies)

        self.assertIsNotNone(flow2)
        self.assertEqual(flow2.l7_protocol_name, "HTTPProtocol")
        self.assertIsNotNone(flow2.http_info)
        self.assertIsNone(flow2.frequencies)

        self.assertEqual(len(self.st.tcp_flow_manager), 2)

        self.st.release_caches()

        self.assertEqual(flow1.l7_protocol_name, "TCPFrequencyProtocol")
        self.assertIsNone(flow1.frequencies)
        self.assertIsNone(flow1.packet_frequencies)

        self.assertEqual(flow2.l7_protocol_name, "HTTPProtocol")
        self.assertIsNone(flow2.http_info)
        self.assertIsNone(flow2.frequencies)

class StackVirtualTests(unittest.TestCase):

    def setUp(self):
        self.st = pyaiengine.StackVirtual()
        self.pd = pyaiengine.PacketDispatcher()
        self.pd.stack = self.st
        self.st.tcp_flows = 2048
        self.st.udp_flows = 1024
        self.called_callback = 0

    def tearDown(self):
        pass

    def inject(self, pcapfile):
        with pyaiengine.PacketDispatcher(pcapfile) as pd:
            pd.stack = self.st
            pd.run()

    def test01(self):
        """ Create a regex for a detect the flow on a virtual network """

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("Bin directory", "^bin$")
        rm.add_regex(r)
        self.st.tcp_regex_manager = rm

        self.inject("../pcapfiles/vxlan_ftp.pcap")

        self.assertEqual(r.matchs, 1)

    def test02(self):
        """ Create a regex for a detect the flow on a virtual network on the GRE side """

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("Bin directory", b"^SSH-2.0.*$")
        rm.add_regex(r)
        self.st.tcp_regex_manager = rm

        self.inject("../pcapfiles/gre_ssh.pcap")

        self.assertEqual(r.matchs, 1)

        self.assertEqual(len(self.st.tcp_flow_manager), 1)
        self.assertEqual(len(self.st.udp_flow_manager), 0)

    def test03(self):
        """ Inject two pcapfiles with gre and vxlan traffic and verify regex """

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("SSH activity", b"^SSH-2.0.*$")
        rm.add_regex(r)
        self.st.tcp_regex_manager = rm

        self.st.enable_nids_engine = True	

        # The first packet of the pcapfile is from 18 sep 2014
        self.inject("../pcapfiles/vxlan_ftp.pcap")

        """ This FlowManagers points to the virtualize layer """
        ft = self.st.tcp_flow_manager
        fu = self.st.udp_flow_manager

        self.assertEqual(ft.flows, 1)
        self.assertEqual(ft.process_flows, 1)
        self.assertEqual(ft.timeout_flows, 0)

        self.assertEqual(r.matchs, 0)
        self.assertEqual(len(self.st.tcp_flow_manager), 1)
        self.assertEqual(len(self.st.udp_flow_manager), 0)

        self.st.flows_timeout = (60 * 60 * 24)

        # The first packet of the pcapfile is from 19 sep 2014
        self.inject("../pcapfiles/gre_ssh.pcap")
      
        self.assertEqual(ft.flows, 2)
        self.assertEqual(ft.process_flows, 2)
        self.assertEqual(ft.timeout_flows, 0)

        self.assertEqual(r.matchs, 1)
        self.assertEqual(len(ft), 2)
        self.assertEqual(len(fu), 0)

    def test04(self):
        """ Test the extraction of the tag from the flow when matches """

        def virt_callback(flow):
            if ((flow.have_tag == True)and(flow.tag == 1)):
                self.called_callback += 1

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("Bin directory", b"^bin$")
        r.callback = virt_callback
        rm.add_regex(r)
        self.st.tcp_regex_manager = rm

        self.st.enable_nids_engine = True

        self.inject("../pcapfiles/vxlan_ftp.pcap")

        self.assertEqual(r.callback, virt_callback)
        self.assertEqual(r.matchs, 1)
        self.assertEqual(self.called_callback, 1)

    def test05(self):
        """ Verify regex on the constructor for easy management """

        """ Create a multi regex that match with different packets """
        r = pyaiengine.Regex("First that matchs", b"^SSH-2.0.*$",
            pyaiengine.Regex("Second that matchs", b"^SSH-2.0.*$",
            pyaiengine.Regex("Third that matchs", b"^.*diffie-hellman.*$",
            pyaiengine.Regex("For dont that matchs", b"This can not match"))))

        rm = pyaiengine.RegexManager()
        rm.add_regex(r)
        self.st.tcp_regex_manager = rm
        self.st.enable_nids_engine = True	

        self.inject("../pcapfiles/gre_ssh.pcap")

        r1 = r.next_regex
        r2 = r.next_regex.next_regex
        r3 = r.next_regex.next_regex.next_regex

        self.assertEqual(r.matchs, 1)
        self.assertEqual(r1.matchs, 1)
        self.assertEqual(r2.matchs, 1)
        self.assertEqual(r3.matchs, 0)

        flow = None
        for f in self.st.tcp_flow_manager:
            flow = f.ssh_info
            flow = f.bitcoin_info

        self.assertEqual(flow, None)

    def test06(self):
        """ Verify regex on the constructor for easy management """

        """ Create a regex list that match with different packets """
        rm = pyaiengine.RegexManager("Some regexs", [
            pyaiengine.Regex("First that matchs", b"^SSH-2.0.*$") ,
            pyaiengine.Regex("Second dont matchs", b"^SSH-2.0.*$"),
            pyaiengine.Regex("Third dont matchs", b"^.*diffie-hellman.*$"),
            pyaiengine.Regex("Four dont that matchs", b"This can not match") ]) 
                
        self.st.tcp_regex_manager = rm
        self.st.enable_nids_engine = True	

        self.inject("../pcapfiles/gre_ssh.pcap")

        """ Just match the first regex """
        self.assertNotEqual(str(rm).find("Name:First that matchs         Matchs:1"), -1)
        self.assertNotEqual(str(rm).find("Name:Second dont matchs        Matchs:0"), -1)

    def test07(self):
        """ Enable and Disable the DHCP protocol """

        self.inject("../pcapfiles/gre_dhcp.pcap")

        """ Test the show_cache on DHCP """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.st.show_cache("dhcp")

        f.close()

        c = self.st.get_cache("dhcp")
        c1 = {'PAQUITO': 1}
        self.assertDictEqual(c, c1)

        for f in self.st.udp_flow_manager:
            b = f.dhcp_info.host_name
            a = f.dhcp_info.ip

        c1 = {'releases': 0, 'packets': 1, 'bytes': 253, 'informs': 0, 'offers': 0, 
            'discovers': 1, 'acks': 0, 'declines': 0, 'requests': 0, 'naks': 0}
        c2 = {'bytes': 0, 'packets': 0}
        c = self.st.get_counters("dhcp")

        self.assertDictEqual(c, c1)

        c = self.st.get_counters("udpgeneric")
        self.assertDictEqual(c, c2)

        self.st.udp_flow_manager.flush()
        self.st.disable_protocol("dhcp")

        self.inject("../pcapfiles/gre_dhcp.pcap")

        c = self.st.get_counters("dhcp")

        self.assertDictEqual(c, c1)

        c3 = {'bytes': 253, 'packets': 1}
        c = self.st.get_counters("udpgeneric")

        self.assertDictEqual(c, c3)

class StackOpenFlowTests(unittest.TestCase):

    def setUp(self):
        self.st = pyaiengine.StackOpenFlow()
        self.pd = pyaiengine.PacketDispatcher()
        self.pd.stack = self.st
        self.st.tcp_flows = 2048
        self.st.udp_flows = 1024
        self.called_callback = 0

    def tearDown(self):
        pass 

    def inject(self, pcapfile, pcapfilter = ""):
        with pyaiengine.PacketDispatcher(pcapfile) as pd:
            if (len(pcapfilter) > 0):
                pd.pcap_filter = pcapfilter
            pd.stack = self.st
            pd.run()

    def test01(self):
        """ Create a regex for a detect the flow on a openflow network """

        rm = pyaiengine.RegexManager()
        r1 = pyaiengine.Regex("Bin directory", b"^\\x26\\x01")
        r2 = pyaiengine.Regex("All", b"^.*$")
        rm.add_regex(r1)
        rm.add_regex(r2)
        self.st.tcp_regex_manager = rm

        self.inject("../pcapfiles/openflow.pcap")

        self.assertEqual(r1.matchs, 0)
        self.assertEqual(r2.matchs, 1)

    def test02(self):
        """ Test the with statement of the PacketDispatcher """

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("Bin directory", b"^\\x26\\x01")

        """ We want to see the matched packet """
        r.write_packet = True

        rm.add_regex(r)
        self.st.tcp_regex_manager = rm

        db = databaseTestAdaptor()
        self.st.set_tcp_database_adaptor(db, 1)

        self.inject("../pcapfiles/openflow.pcap") 

        d = json.loads(db.lastdata)

        if "matchs" in d:
            self.assertEqual(d["matchs"], "Bin directory")
        else:
            self.assertTrue(False)

        self.assertEqual(r.matchs, 1)

        """ the packet is write on the packet field of the json """
        packet = d["packet"]

        self.assertEqual(packet[0], 38)
        self.assertEqual(packet[1], 1)
        self.assertEqual(r.write_packet , True)

    def test03(self):
        """ Test the flowmanager flush functionality """

        self.inject("../pcapfiles/openflow.pcap")

        ft = self.st.tcp_flow_manager

        self.assertEqual(ft.flows , 1)
        self.assertEqual(ft.process_flows , 1)
        self.assertEqual(ft.timeout_flows, 0)
        self.assertEqual(len(ft), 1)

        ft.flush()

        self.assertEqual(ft.flows , 0)
        self.assertEqual(ft.process_flows , 1)
        self.assertEqual(ft.timeout_flows, 0)
        self.assertEqual(len(ft), 0)

    def test04(self):
        """ Test DNS query on openflow """
        def domain_callback(flow):
            self.assertNotEqual(flow.dns_info, None)
            self.assertEqual(flow.dns_info.domain_name, "daisy.ubuntu.com")
            self.called_callback += 1

        d = pyaiengine.DomainName("test",".ubuntu.com")

        d.callback = domain_callback

        dm = pyaiengine.DomainNameManager()
        dm.add_domain_name(d)

        db = databaseTestAdaptor()
        self.st.set_udp_database_adaptor(db,1)

        self.st.set_domain_name_manager(dm, "dns")

        self.inject("../pcapfiles/openflow_dns.pcap")

        c = self.st.get_cache("DNSProtocol")
        c1 = {'daisy.ubuntu.com': 2}

        self.assertDictEqual(c, c1)
        self.assertEqual(d.matchs, 1)
        self.assertEqual(self.called_callback, 1)

        """ Verify the output of adaptor """
        d = json.loads(db.lastdata)

        d1 = {u'info': {u'dnsdomain': u'daisy.ubuntu.com', u'ips': [u'91.189.92.55', u'91.189.92.57'], 
            u'matchs': u'test', u'qtype': 0}, u'layer7': u'dns', u'proto': 17, 
            u'ip': {u'src': u'129.21.3.17', u'dst': u'192.168.2.6'}, 
            u'bytes': 94, u'anomaly': 6, u'port': {u'src': 53, u'dst': 28848}}

        self.assertDictEqual(d, d1)

    def test05(self):
        """ Enable and disable DNS protocol """

        self.inject("../pcapfiles/openflow_dns.pcap")

        c1 = {'type MX': 0, 'type DS': 0, 'type SOA': 0, 'type CNAME': 0, 'responses': 1, 
            'type SRV': 0, 'type TXT': 0, 'type ANY': 0, 'type others': 0, 'type SSHFP': 0, 
            'type LOC': 0, 'type DNSKEY': 0, 'type IXFR': 0, 'type AAAA': 1, 'type NS': 0, 
            'queries': 1, 'allow queries': 1, 'banned queries': 0, 'type PTR': 0, 'type A': 1}

        c2 = {'bytes': 0, 'packets': 0}
        c = self.st.get_counters("DNSProtocol")

        self.assertDictEqual(c, c1)

        c = self.st.get_counters("udpgenericprotocol")
       
        self.assertDictEqual(c, c2)

        self.st.udp_flow_manager.flush()

        self.st.disable_protocol("dns")
        self.inject("../pcapfiles/openflow_dns.pcap")

        c = self.st.get_counters("DNSProtocol")

        self.assertDictEqual(c, c1)

        c3 = {'bytes': 120, 'packets': 2}        
        c = self.st.get_counters("udpgenericprotocol")

        self.assertDictEqual(c, c3)

        """ Test the output of show_anomalies and show_protocol_statistics """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.st.show_anomalies()
            self.st.show_protocol_statistics()

        f.close()

class PacketDispatcherTests(unittest.TestCase):

    def setUp(self):
        self.pd = pyaiengine.PacketDispatcher()

    def tearDown(self):
        del self.pd 

    def test01(self):
        """ The packet dispatcher should process the packets without stack """
        self.pd.open("../pcapfiles/vxlan_ftp.pcap")
        self.pd.run()
        # self.pd.show_current_packet()
        self.pd.close()
        self.assertEqual(self.pd.bytes, 900)
        self.assertEqual(self.pd.packets, 8)

        """ Check some default properties """
        self.assertEqual(self.pd.evidences, False)
        self.assertEqual(len(self.pd.pcap_filter), 0)   
        self.assertEqual(self.pd.is_packet_accepted, True)
 
    def test02(self):
        """ check the port functionality """
        self.pd.open("../pcapfiles/vxlan_ftp.pcap")
        self.pd.enable_shell = True
         
        port = randint(2000, 65000)
       
        self.pd.port = port
        self.assertEqual(self.pd.port, port)
        self.assertEqual(self.pd.enable_shell, True)

        """ The socket should be in use """
        try:
            """ Use psutil for verify if the current process have a socket open on 
                the port """
            import psutil
    
            proc = psutil.Process(os.getpid())        
            nc = proc.connections()[0]
            self.assertEquals(port, nc.laddr[1])
        except:
            pass 
 
        self.pd.run()
        self.pd.close()

    def test03(self):
        """ Run the dispatcher of a unknown device name """
        self.pd.open("I_dont think this will work")
        self.pd.run()
        self.pd.close()
        self.assertEqual(self.pd.bytes, 0)
        self.assertEqual(self.pd.packets, 0)

    def test04(self):
        """ Test case for the add_timer functionality """

        def timer1():
            pass
        def timer2():
            pass
        def timer3():
            pass

        self.pd.add_timer(timer1, 1)
        self.pd.add_timer(timer2, 10)
        self.pd.add_timer(timer3, 1)
        self.pd.add_timer(None, 1)

        self.pd.open("../pcapfiles/vxlan_ftp.pcap")
        self.pd.run()
        self.pd.close()

        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.pd.show()

        f.close()
        self.pd.add_timer(None, 10)

class StackMobileIPv6Tests(unittest.TestCase):

    def setUp(self):
        self.st = pyaiengine.StackMobileIPv6()
        self.pd = pyaiengine.PacketDispatcher()
        self.pd.stack = self.st
        self.st.tcp_flows = 2048
        self.st.udp_flows = 1024
        self.called_callback = 0

    def tearDown(self):
        pass

    def inject(self, pcapfile):
        with pyaiengine.PacketDispatcher(pcapfile) as pd:
            pd.stack = self.st
            pd.run()

    def test01(self):
        """ Verify the integrity of the sip fields """

        db = databaseTestAdaptor()

        self.st.set_tcp_database_adaptor(db)

        self.inject("../pcapfiles/gprs_ip6_tcp.pcap")
       
        for flow in self.st.tcp_flow_manager:
            self.assertEqual(flow.mqtt_info, None)
            self.assertEqual(flow.coap_info, None)
            self.assertEqual(flow.http_info, None)
            self.assertEqual(flow.dns_info, None)
            self.assertEqual(flow.ssl_info, None)

        c1 = {'bytes': 3198, 'packets': 11, 'fragmented packets': 0, 'extension header packets': 0} 
        c = self.st.get_counters("IPv6Protocol")
        self.assertDictEqual(c, c1)

    def test02(self):
        """ Verify the integrity of the sip fields """

        db = databaseTestAdaptor()

        self.st.set_udp_database_adaptor(db)

        self.inject("../pcapfiles/gprs_ip6_udp.pcap")

        for flow in self.st.udp_flow_manager:
            self.assertEqual(flow.mqtt_info, None)
            self.assertEqual(flow.coap_info, None)
            self.assertEqual(flow.http_info, None)
            self.assertEqual(flow.dns_info, None)
            self.assertEqual(flow.ssl_info, None)
            self.assertNotEqual(flow.sip_info, None)
            self.assertEqual(flow.sip_info.from_name, "<tel:+88270006>;tag=9Q5V3XeXXf")
            self.assertEqual(flow.sip_info.to_name, "<tel:+88270006>")
            self.assertEqual(flow.sip_info.uri, "tel:+7")
            self.assertEqual(flow.sip_info.via, "SIP/2.0/UDP [fd00:183:1:1:1886:9040:8605:32b8]:5060;branch=z9hG4bKOJ5umQnnq16M2Cr;rport")

        d = json.loads(db.lastdata)
        c = self.st.get_counters("SIPProtocol")
        self.assertEqual(c["requests"], 2)
        self.assertEqual(c["responses"], 2)
        self.assertEqual(c["registers"], 0)

        c = self.st.get_cache("SIP")

        """ print the output of the cache """
        f = tempfile.TemporaryFile()
        with stdout_redirected(f):
            self.st.show_cache("SIP")

        f.seek(0)
        total_lines = len(f.readlines())
        self.assertEqual(total_lines, 3)
        f.close()

    def test03(self):
        """ Verify the integrity of the DNS traffic """

        def callback_domain(flow):
            self.called_callback += 1

        d = pyaiengine.DomainName("Some domain", ".org")

        dm = pyaiengine.DomainNameManager()
        d.callback = callback_domain
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm, "DNSProtocol")

        db = databaseTestAdaptor()

        self.st.set_udp_database_adaptor(db)

        self.inject("../pcapfiles/gtp_ip6_dns.pcap")

        self.assertEqual(self.called_callback, 1)
        
        d = json.loads(db.lastdata)
        self.assertEqual(d["ip"]["src"], "2001:507:0:1:200:8600:0:1")
        self.assertEqual(d["ip"]["dst"], "2001:507:0:1:200:8600:0:2")
        self.assertEqual(d["info"]["dnsdomain"], "itojun.org")

    def test04(self):
        """ Verify the integrity of the SSL traffic """

        def callback_domain(flow):
            self.called_callback += 1
            self.assertEqual(flow.ssl_info.server_name, "search.services.mozilla.com")
            """ Is no issuer because the cert packet is just after """
            self.assertEqual(flow.ssl_info.issuer_name, "")

        d = pyaiengine.DomainName("Some domain", ".mozilla.com")

        dm = pyaiengine.DomainNameManager()
        d.callback = callback_domain
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm, "SSLProtocol")

        db = databaseTestAdaptor()

        self.st.set_tcp_database_adaptor(db)

        self.inject("../pcapfiles/gtp_ip6_ssl.pcap")

        self.assertEqual(self.called_callback, 1)

        c = self.st.get_counters("SSL")
        self.assertEqual(c["server hellos"], 1)
        self.assertEqual(c["server dones"], 0)
        self.assertEqual(c["records"], 3)
        self.assertEqual(c["alerts"], 1)
        self.assertEqual(c["client hellos"], 1)
        self.assertEqual(c["handshakes"], 3)
        self.assertEqual(c["certificates"], 1)

        d = json.loads(db.lastdata)
	self.assertEqual(d["info"]["issuer"], "DigiCert SHA2 Secure Server CA")

    def test05(self):
        """ Verify DomainName with IPSets on TCP traffic """

        def callback_ipset(flow):
            self.called_callback += 1
            self.assertEqual(flow.ssl_info, None)

        def callback_domain(flow):
            self.called_callback += 1
            self.assertEqual(flow.ssl_info.server_name, "search.services.mozilla.com")

        d = pyaiengine.DomainName("Some domain", ".mozilla.com")

        dm = pyaiengine.DomainNameManager()
        d.callback = callback_domain
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm, "SSLProtocol")

        ipset = pyaiengine.IPSet("IPv6 generic set", [ "2001:507:0:1:200:8600:0:2", "2001:507:0:1:200:8600:0:100" ])
        ipset.callback = callback_ipset
        im = pyaiengine.IPSetManager()

        im.add_ip_set(ipset)
        self.st.tcp_ip_set_manager = im

        self.inject("../pcapfiles/gtp_ip6_ssl.pcap")

        self.assertEqual(self.called_callback, 2)

    def test06(self):
        """ Verify Regex with IPSets on UDP traffic """

        def callback_ipset(flow):
            self.called_callback += 1

        def callback_regex(flow):
            self.called_callback += 1

        rm = pyaiengine.RegexManager()

        r = pyaiengine.Regex("Something", "^MESSAGE.*$", callback_regex)
        rm.add_regex(r)
        self.st.udp_regex_manager = rm

        self.st.enable_nids_engine = True

        ipset = pyaiengine.IPSet("IPv6 generic set", [ "fd01::183", "2001:507:0:1:200:8600:0:100" ])
        ipset.callback = callback_ipset
        im = pyaiengine.IPSetManager()

        im.add_ip_set(ipset)
        self.st.udp_ip_set_manager = im

        self.inject("../pcapfiles/gprs_ip6_udp.pcap")

        self.assertEqual(self.called_callback, 2)

    def test07(self):
        """ Verify the change of execution by changing the regex_manager of the flow """

        def callback1(flow):
            self.assertIsNotNone(flow.regex_manager)
            self.assertIsNotNone(flow.regex)
            self.assertEquals(flow.regex_manager.name, rm1.name)
            self.called_callback += 1
            """ On a regular execution, without changing the regex_manager, the flow
                will stop the check of new regex, because there is one that matches.
                However, by changing the matched RegexManager to other value we tell
                the engine to continue the exection but with the use of other RegexManager 
            """
            flow.regex_manager = rm2

        def callback2(flow):
            self.assertIsNotNone(flow.regex_manager)
            self.assertEquals(flow.regex_manager.name, rm2.name)
            flow.regex_manager = rm3
            self.called_callback += 1

        def callback3(flow):
            self.assertIsNotNone(flow.regex_manager)
            self.assertEquals(flow.regex_manager.name, rm3.name)

            """ Stop the execution """
            flow.regex_manager = None
            self.called_callback += 1

        def callback4(flow):
            """ This callback is not called """
            self.called_callback += 1

        r1 = pyaiengine.Regex("Rule1", "^SUBSCRIBE.*$", callback1)
        rother = pyaiengine.Regex("Rule1 extra", "^OTHER THING.*$")
        r2 = pyaiengine.Regex("Rule2", "^(SIP/2.0 405).*$", callback2)
        r3 = pyaiengine.Regex("Rule3", "^MESSAGE.*$", callback3)
        r4 = pyaiengine.Regex("Rule4", "^(SIP/2.0 202).*$", callback4)

        rm1 = pyaiengine.RegexManager("one", [ r1, rother ])
        rm2 = pyaiengine.RegexManager("two", [ r2 ])
        rm3 = pyaiengine.RegexManager("three", [ r3 ])
        rm4 = pyaiengine.RegexManager("four", [ r4 ])

        db = databaseTestAdaptor()
        self.st.set_udp_database_adaptor(db, 1)

        self.st.udp_regex_manager = rm1
        self.st.enable_nids_engine = True

        self.inject("../pcapfiles/gprs_ip6_udp.pcap")

        self.assertEqual(r1.matchs, 1)
        self.assertEqual(rother.matchs, 0)
        self.assertEqual(r2.matchs, 1)
        self.assertEqual(r3.matchs, 1)
        self.assertEqual(r4.matchs, 0)
        self.assertEqual(self.called_callback, 3)

        d = json.loads(db.all_data[1])
        """ The first to records, that correspond to the first two packets, shoudnt
            have any reference to regex """
        self.assertEqual(d.has_key("matchs"), False)
        d = json.loads(db.all_data[2])
        self.assertEqual(d.has_key("matchs"), False)

        """ The 3 and 4 packet should have the regex """
        d = json.loads(db.all_data[3])
        self.assertEqual(d.has_key("matchs"), True)
        self.assertEqual(d["matchs"], "Rule3")

        d = json.loads(db.all_data[4])
        self.assertEqual(d.has_key("matchs"), True)
        self.assertEqual(d["matchs"], "Rule3")

if __name__ == "__main__":

    unittest.main()

    sys.exit(0)

