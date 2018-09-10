"""
    https://www.cac.cornell.edu/wiki/index.php?title=Python_Distutils_Tips

"""

import os
import sys
import distutils.sysconfig
from setuptools import setup, Extension, Command

long_description = """AIEngine is a next generation interactive/programmable Python/Ruby/Java/Lua network intrusion detection system engine
, DNS domain classification, Spam detection, network collector, network forensics and many others. 

AIEngine also helps network/security professionals to identify traffic and develop
signatures for use them on NIDS, Firewalls, Traffic classifiers and so on.

The main functionalities of AIEngine are:

- Support for interacting/programing with the user while the engine is running.
- Support for PCRE JIT for regex matching.
- Support for regex graphs (complex detection patterns).
- Support five types of NetworkStacks (lan,mobile,lan6,virtual and oflow).
- Support Sets and Bloom filters for IP searches.
- Supports x86_64, ARM and MIPS architecture over operating systems such as Linux, FreeBSD and MacOS.
- Support for HTTP,DNS and SSL Domains matching.
- Support for banned domains and hosts for HTTP, DNS, SMTP and SSL.
- Frequency analysis for unknown traffic and auto-regex generation.
- Generation of Yara signatures.
- Easy integration with databases (MySQL, Redis, Cassandra, Hadoop, etc...) for data correlation.
- Easy integration with other packet engines (Netfilter).
- Support memory clean caches for refresh stored memory information.
- Support for detect DDoS at network/application layer.
- Support for rejecting TCP/UDP connections.
- Support for network forensics on real time.
- Supports protocols such as Bitcoin,CoAP,DCERPC,DHCP,DNS,GPRS,GRE,HTTP,ICMPv4/ICMPv6,IMAP,IPv4/v6,Modbus,
  MPLS,MQTT,Netbios,NTP,OpenFlow,POP,Quic,RTP,SIP,SMTP,SSDP,SSH,SSL,TCP,UDP,VLAN,VXLAN. 
"""


""" List of the files of the lib """
src_files =  ["Multiplexer.cc", "FlowForwarder.cc", "PacketDispatcher.cc"]
src_files += ["Packet.cc", "IPAddress.cc", "Flow.cc", "Protocol.cc", "StringCache.cc"]
src_files += ["Callback.cc", "Interpreter.cc", "NetworkStack.cc", "EvidenceManager.cc", "AnomalyManager.cc"]
src_files += ["FlowRegexEvaluator.cc"]
src_files += ["flow/FlowManager.cc"] 
src_files += ["protocols/ethernet/EthernetProtocol.cc"]
src_files += ["protocols/vlan/VLanProtocol.cc"]
src_files += ["protocols/mpls/MPLSProtocol.cc"]
src_files += ["protocols/pppoe/PPPoEProtocol.cc"]
src_files += ["protocols/ip/IPProtocol.cc"]
src_files += ["ipset/IPAbstractSet.cc","ipset/IPSet.cc", "ipset/IPBloomSet.cc", "ipset/IPSetManager.cc"]
src_files += ["ipset/IPRadixTree.cc"]
src_files += ["protocols/ip6/IPv6Protocol.cc"]
src_files += ["protocols/icmp6/ICMPv6Protocol.cc"]
src_files += ["protocols/icmp/ICMPProtocol.cc"]
src_files += ["protocols/udp/UDPProtocol.cc"]
src_files += ["protocols/tcp/TCPProtocol.cc", "protocols/tcp/TCPInfo.cc"]
src_files += ["protocols/tcpgeneric/TCPGenericProtocol.cc", "protocols/udpgeneric/UDPGenericProtocol.cc"]
src_files += ["protocols/gre/GREProtocol.cc"]
src_files += ["protocols/vxlan/VxLanProtocol.cc"]
src_files += ["protocols/openflow/OpenFlowProtocol.cc"]
src_files += ["protocols/gprs/GPRSProtocol.cc", "protocols/gprs/GPRSInfo.cc"]
src_files += ["protocols/http/HTTPProtocol.cc", "protocols/http/HTTPUriSet.cc", "protocols/http/HTTPInfo.cc"]
src_files += ["protocols/ssl/SSLProtocol.cc", "protocols/ssl/SSLInfo.cc"]
src_files += ["protocols/ssh/SSHProtocol.cc", "protocols/ssh/SSHInfo.cc"]
src_files += ["protocols/smtp/SMTPProtocol.cc", "protocols/smtp/SMTPInfo.cc"]
src_files += ["protocols/imap/IMAPProtocol.cc", "protocols/imap/IMAPInfo.cc"]
src_files += ["protocols/pop/POPProtocol.cc", "protocols/pop/POPInfo.cc"]
src_files += ["protocols/dns/DNSProtocol.cc", "protocols/dns/DNSInfo.cc"]
src_files += ["protocols/sip/SIPProtocol.cc", "protocols/sip/SIPInfo.cc"]
src_files += ["protocols/dhcp/DHCPProtocol.cc", "protocols/dhcp/DHCPInfo.cc"]
src_files += ["protocols/ntp/NTPProtocol.cc"]
src_files += ["protocols/snmp/SNMPProtocol.cc"]
src_files += ["protocols/ssdp/SSDPProtocol.cc", "protocols/ssdp/SSDPInfo.cc"]
src_files += ["protocols/modbus/ModbusProtocol.cc"]
src_files += ["protocols/bitcoin/BitcoinProtocol.cc", "protocols/bitcoin/BitcoinInfo.cc"]
src_files += ["protocols/coap/CoAPProtocol.cc", "protocols/coap/CoAPInfo.cc"]
src_files += ["protocols/rtp/RTPProtocol.cc"]
src_files += ["protocols/mqtt/MQTTProtocol.cc", "protocols/mqtt/MQTTInfo.cc"]
src_files += ["protocols/netbios/NetbiosProtocol.cc", "protocols/netbios/NetbiosInfo.cc"]
src_files += ["protocols/quic/QuicProtocol.cc"]
src_files += ["protocols/smb/SMBProtocol.cc", "protocols/smb/SMBInfo.cc"]
src_files += ["protocols/dhcp6/DHCPv6Protocol.cc", "protocols/dhcp6/DHCPv6Info.cc"]
src_files += ["protocols/dcerpc/DCERPCProtocol.cc", "protocols/dcerpc/DCERPCInfo.cc"]
src_files += ["regex/Regex.cc", "regex/RegexManager.cc"]
src_files += ["protocols/frequency/PacketFrequencies.cc"]
src_files += ["protocols/frequency/Frequencies.cc", "protocols/frequency/FrequencyProtocol.cc"]
src_files += ["protocols/frequency/FrequencyCounter.cc", "learner/LearnerEngine.cc"]
src_files += ["names/DomainNode.cc", "names/DomainName.cc", "names/DomainNameManager.cc"]
src_files += ["System.cc"]
src_files += ["StackMobile.cc", "StackLan.cc", "StackLanIPv6.cc", "StackVirtual.cc", "StackOpenFlow.cc", "StackMobileIPv6.cc"]
src_files += ["TimerManager.cc"]
src_files += ["python_wrapper.cc"]

class SetupBuildCommand(Command):
    """
    Master setup build command to subclass from.
    """

    user_options = []

    def initialize_options(self):
        """
        Setup the current dir.
        """
        self._dir = os.getcwd()

    def finalize_options(self):
        """
        Set final values for all the options that this command supports.
        """
        pass

class TODOCommand(SetupBuildCommand):
    """
    Quick command to show code TODO's.
    """

    description = "prints out TODO's in the code"

    def run(self):
        """
        Prints out TODO's in the code.
        """
        import re

        # The format of the string to print: file_path (line_no): %s line_str
        format_str = "%s (%i): %s"
        # regex to remove whitespace in front of TODO's
        remove_front_whitespace = re.compile("^[ ]*(.*)$")

        # Look at all non pyc files in src/ and bin/
        for rootdir in ['./']:
            # walk down each root directory
            for root, dirs, files in os.walk(rootdir):
                # for each single file in the files
                for afile in files:
                    # if the file doesn't end with .pyc
                    if ((afile.endswith('.cc')) or (afile.endswith('.h'))):
                    #if not afile.endswith('.pyc'):
                        full_path = os.path.join(root, afile)
                        fobj = open(full_path, 'r')
                        line_no = 0
                        # look at each line for TODO's
                        for line in fobj.readlines():
                            if 'todo' in line.lower():
                                nice_line = remove_front_whitespace.match(
                                    line).group(1)
                                # print the info if we have a TODO
                                print(format_str % (
                                    full_path, line_no, nice_line))
                            line_no += 1

def setup_compiler ():
    distutils.sysconfig.get_config_vars()
    config_vars = distutils.sysconfig._config_vars

    includes = list()
    macros = list()

    macros.append(('BINDING','1'))
    macros.append(('PYTHON_BINDING','1'))
    macros.append(('HAVE_CONFIG_H','1'))
    includes.append(".")
    includes.append("..")
    includes.append("../..")


    print(sys.platform)
    if (sys.platform == 'sunos5'):
        config_vars['LDSHARED'] = "gcc -G"
        config_vars['CCSHARED'] = ""
    elif ('freebsd1' in sys.platform):
        os.environ["CC"] = "c++"
        includes.append("/usr/local/include")
        macros.append(('__FREEBSD__','1'))
    elif (sys.platform == 'openbsd5'):
        macros.append(('__OPENBSD__','1'))
        os.environ["CC"] = "eg++"
    elif (sys.platform == 'darwin'):
        macros.append(('__DARWIN__','1'))
        os.environ["CC"] = "g++"
    else:
        os.environ["CC"] = "g++"
        os.environ["CXX"] = "g++"

    return includes,macros

aiengine_module = Extension("pyaiengine",
    sources = src_files,
    libraries = ["boost_system","pcap","pcre","boost_iostreams"],
    define_macros = [],
    extra_compile_args = ["-O3","-Wreorder","-std=c++14","-lpthread","-lstdc++"],
    )

def isUbuntuBaseDistro():

    try:
        os.stat("/etc/debian_version")
        return True
    except:
        return False


if __name__ == "__main__":

    py_major = sys.version_info.major
    py_minor = sys.version_info.minor

    boost_python_lib = ""

    if (py_major > 2):
        """ Ubuntu loves to change names of the libs """
        if (isUbuntuBaseDistro()):
            boost_python_lib = "boost_python-py" + str(py_major) + str(py_minor)
        else:
            boost_python_lib = "boost_python3"
    else:
        boost_python_lib = "boost_python"

    long_desc = long_description

    if (len(sys.argv) > 1):
        if (sys.argv[1].startswith("build_ext")):
            includes, macros = setup_compiler()

            print("Compiling aiengine extension for %s" % sys.platform)
            print("\tOS name %s" % (os.name))
            print("\tArchitecture %s" % os.uname()[4])
            print("\tBoost python lib %s" % boost_python_lib)

            aiengine_module.include_dirs = includes
            aiengine_module.define_macros = macros
            aiengine_module.libraries.append(boost_python_lib)

    setup(name="aiengine",
        version = "1.9",
        author = "Luis Campo Giralte",
        author_email = "me@ryadpasha.com",
        url = "https://ryadpasha.com",
        license = "GPLv2",
        package_dir = {'': '.'},
        description = "A next generation interactive/programmable Python network intrusion detection system",
        long_description = long_desc ,
        ext_modules = [aiengine_module],
        py_modules = ["pyaiengine"],
        keywords = ["security", "network", "intrusion"],
        classifiers=[
            "Development Status :: 5 - Production/Stable",
            "Environment :: Console",
            "Intended Audience :: Information Technology",
            "Intended Audience :: Science/Research",
            "Intended Audience :: System Administrators",
            "Intended Audience :: Telecommunications Industry",
            "Intended Audience :: Developers",
            "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
            "Operating System :: POSIX :: BSD :: FreeBSD",
            "Operating System :: POSIX :: Linux",
            "Programming Language :: C++",
            "Programming Language :: Python :: 2.7",
            "Programming Language :: Python :: 3.3",
            "Programming Language :: Python :: 3.4",
            "Programming Language :: Python :: 3.5",
            "Programming Language :: Python :: 3.6",
            "Topic :: Internet",
            "Topic :: Scientific/Engineering :: Information Analysis",
            "Topic :: Security",
            "Topic :: System :: Networking",
            "Topic :: System :: Networking :: Monitoring",
          ],
       cmdclass = {'todo': TODOCommand},
    )

