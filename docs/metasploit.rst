Metasploit encoders
~~~~~~~~~~~~~~~~~~~

By using the framework Metasploit(http://www.metasploit.com/) we launch some exploits by using some of the most interesting encoders. On the example we generate five attacks by using a HTTP exploit.

.. code:: bash

    [luis@localhost src]$ ./aiengine -i /tmp/metasploit_linux_exec_shikata_ga_nai.pcap -d
    AIEngine running on Linux kernel 3.19.5-100.fc20.x86_64 #1 SMP Mon Apr 20 19:51:16 UTC 2015 x86_64
    [05/14/15 19:47:40] Lan network stack ready.
    [05/14/15 19:47:40] Processing packets from file /tmp/metasploit_linux_exec_shikata_ga_nai.pcap
    PacketDispatcher(0x1bee1a0) statistics
            Connected to Lan network stack
	    Total packets:                  40
	    Total bytes:                  7770
    Flows on memory

    Flow                                                             Bytes      Packets    FlowForwarder      Info        
    [127.0.0.1:45458]:6:[127.0.0.1:2000]                             1010       8          HTTPProtocol       TCP:S(1)SA(1)A(4)F(2)P(1)Seq(2242799999,1931887886) Req(1)Res(0)Code(0) 
    [127.0.0.1:33507]:6:[127.0.0.1:2000]                             1010       8          HTTPProtocol       TCP:S(1)SA(1)A(4)F(2)P(1)Seq(1588580017,3374858971) Req(1)Res(0)Code(0) 
    [127.0.0.1:44065]:6:[127.0.0.1:2000]                             1010       8          HTTPProtocol       TCP:S(1)SA(1)A(4)F(2)P(1)Seq(3050505632,3899294455) Req(1)Res(0)Code(0) 
    [127.0.0.1:54207]:6:[127.0.0.1:2000]                             1010       8          HTTPProtocol       TCP:S(1)SA(1)A(4)F(2)P(1)Seq(851146721,922463182) Req(1)Res(0)Code(0) 
    [127.0.0.1:53648]:6:[127.0.0.1:2000]                             1010       8          HTTPProtocol       TCP:S(1)SA(1)A(4)F(2)P(1)Seq(3282896143,2659021029) Req(1)Res(0)Code(0) 

    Flow                                                             Bytes      Packets    FlowForwarder      Info  

Now we let to the FrequencyEngine and the LearnerEngine do the work by using the following parameters.

.. code:: bash

    Frequencies optional arguments:
      -F [ --enable-frequencies ]       Enables the Frequency engine.
      -g [ --group-by ] arg (=dst-port) Groups frequencies by src-ip,dst-ip,src-por
                                    t and dst-port.
      -f [ --flow-type ] arg (=tcp)     Uses tcp or udp flows.
      -L [ --enable-learner ]           Enables the Learner engine.
      -k [ --key-learner ] arg (=80)    Sets the key for the Learner engine.
      -b [ --buffer-size ] arg (=64)    Sets the size of the internal buffer for 
                                    generate the regex.
      -y [ --enable-yara ]              Generates a yara signature.

And now execute with the selected parameters

.. code:: bash

    [luis@localhost src]$ ./aiengine -i /tmp/metasploit_linux_exec_shikata_ga_nai.pcap -F -L 
    AIEngine running on Linux kernel 3.19.5-100.fc20.x86_64 #1 SMP Mon Apr 20 19:51:16 UTC 2015 x86_64
    [05/14/15 19:55:38] Lan network stack ready.
    [05/14/15 19:55:38] Enable FrequencyEngine on Lan network stack
    [05/14/15 19:55:38] Processing packets from file /tmp/metasploit_linux_exec_shikata_ga_nai.pcap
    PacketDispatcher(0x15d9a00) statistics
	    Connected to Lan network stack
	    Total packets:                  40
	    Total bytes:                  7770
    Agregating frequencies by destination port
    Computing 5 frequencies by destination port
    Frequency Group(by destination port) total frequencies groups:1
	    Total process flows:5
	    Total computed frequencies:1
	    Key                    Flows      Bytes      Dispersion Enthropy  
	    2000                   5          5050       14         0         

    Exiting process

By using the minimal options (-F and -L) we can verify that five flows have been computed by using the destination port 2000. So at this point we just add the parameter -k for generate a valid regex for the flows.

.. code::bash

    [luis@localhost src]$ ./aiengine -i /tmp/metasploit_linux_exec_shikata_ga_nai.pcap -F -L -k 2000
    AIEngine running on Linux kernel 3.19.5-100.fc20.x86_64 #1 SMP Mon Apr 20 19:51:16 UTC 2015 x86_64
    [05/14/15 20:01:49] Lan network stack ready.
    [05/14/15 20:01:49] Enable FrequencyEngine on Lan network stack
    [05/14/15 20:01:49] Processing packets from file /tmp/metasploit_linux_exec_shikata_ga_nai.pcap
    PacketDispatcher(0x239fa60) statistics
	    Connected to Lan network stack
	    Total packets:                  40
	    Total bytes:                  7770
    Agregating frequencies by destination port
    Computing 5 frequencies by destination port
    Frequency Group(by destination port) total frequencies groups:1
	    Total process flows:5
	    Total computed frequencies:1
	    Key                    Flows      Bytes      Dispersion Enthropy  
	    2000                   5          5050       14         0         

    Agregating 5 to the LearnerEngine
    Regular expression generated with key:2000 buffer size:64
    Regex:^\x47\x45\x54\x20\x2f\x73\x74\x72\x65\x61\x6d\x2f\x3f.{51}
    Ascii buffer:GET /stream/?
    Exiting process

It seems that the generated regex will be too generic and will have false positives. So by extending the internal buffer of the FrequencyEngine (-b option) we extend the regex length.

.. code:: bash

    [luis@localhost src]$ ./aiengine -i /tmp/metasploit_linux_exec_shikata_ga_nai.pcap -F -L -k 2000 -b 2048
    [05/14/15 20:03:58] Processing packets from file /tmp/metasploit_linux_exec_shikata_ga_nai.pcap
    PacketDispatcher(0x16f7c70) statistics
	    Connected to Lan network stack
	    Total packets:                  40
	    Total bytes:                  7770
    Agregating frequencies by destination port
    Computing 5 frequencies by destination port
    Frequency Group(by destination port) total frequencies groups:1
	    Total process flows:5
	    Total computed frequencies:1
	    Key                    Flows      Bytes      Dispersion Enthropy  
	    2000                   5          5050       14         0         

    Agregating 5 to the LearnerEngine
    Regular expression generated with key:2000 buffer size:2048
    Regex:^\x47\x45\x54\x20\x2f\x73\x74\x72\x65\x61\x6d\x2f\x3f.{780}\xf7\x22\x09\x08.{137}\xd9\x74\x24\xf4.{2}\xc9\xb1\x0b.{9}\xe2.{44}\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\x0d\x0a\x0d\x0a
    Ascii buffer:GET /stream/?g"   It$d9!
                                     R HTTP/1.0


    Exiting process

The interesting part is how iaengine have been capable of identify some invariant parts of the exploit such as the "\xf7\x22\x09\x08", "\xd9\x74\x24\xf4" and the "\xc9\xb1\x0b". But whats that?
Lets use the python disassembler (distorm3 https://pypi.python.org/pypi/distorm3/3.3.0) to check what is the meaning of those bytes

.. code:: python

    Python 2.6.6 (r266:84292, Nov 21 2013, 10:50:32) 
    [GCC 4.4.7 20120313 (Red Hat 4.4.7-4)] on linux2
    Type "help", "copyright", "credits" or "license" for more information.
    >>> from distorm3 import Decode, Decode16Bits, Decode32Bits, Decode64Bits
    >>> opcodes = "f7220908"
    >>> Decode(0x400000, opcodes.decode('hex'), Decode32Bits)
    [(4194304L, 2L, 'MUL DWORD [EDX]', 'f722'), (4194306L, 2L, 'OR [EAX], ECX', '0908')]

A multiply opcode? may be is a false positive or a important component of the exploit, but lets continue

.. code:: python

    >>> opcodes = "d97424f4"
    >>> Decode(0x400000, opcodes.decode('hex'), Decode64Bits)
    [(4194304L, 4L, 'FNSTENV [RSP-0xc]', 'd97424f4')]

Alternatively you can use capstone(http://www.capstone-engine.org/) as dissembler if you want

.. code:: python

    >>> from capstone import *
    >>> CODE = b"\xf7\x22\x09\x08"
    >>> md = Cs(CS_ARCH_X86, CS_MODE_64)
    >>> for i in md.disasm(CODE, 0x1000):
    ...     print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    ... 
    0x1000:	mul	dword ptr [rdx]
    0x1002:	or	dword ptr [rax], ecx
    >>> CODE = b"\xd9\x74\x24\xf4"
    >>> for i in md.disasm(CODE, 0x0000):
    ...     print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    ... 
    0x0:	fnstenv	dword ptr [rsp - 0xc]

The instruction fnstenv saves the current FPU operating environment at the memory location specified with the destination operand, the The FPU operating environment consists of the FPU control word, status word, tag word, instruction pointer, data pointer, and last opcode. This means that with that instruction you can retrieve the instruction pointer. This is commmon behavior on polymorphic exploits, so now we have a candidate for our final regex. Lets see how we can verify the regex also.

.. code:: bash

    [luis@localhost src]$ ./aiengine -i /tmp/metasploit_linux_exec_shikata_ga_nai.pcap -R -r "^GET.*\xd9\x74\x24\xf4.*$" -m 
    AIEngine running on Linux kernel 3.19.5-100.fc20.x86_64 #1 SMP Mon Apr 20 19:51:16 UTC 2015 x86_64
    [05/14/15 20:55:02] Lan network stack ready.
    [05/14/15 20:55:02] Enable NIDSEngine on Lan network stack
    [05/14/15 20:55:02] Processing packets from file /tmp/metasploit_linux_exec_shikata_ga_nai.pcap
    TCP Flow:127.0.0.1:44065:6:127.0.0.1:2000 matchs with regex experimental0
    TCP Flow:127.0.0.1:53648:6:127.0.0.1:2000 matchs with regex experimental0
    TCP Flow:127.0.0.1:45458:6:127.0.0.1:2000 matchs with regex experimental0
    TCP Flow:127.0.0.1:54207:6:127.0.0.1:2000 matchs with regex experimental0
    TCP Flow:127.0.0.1:33507:6:127.0.0.1:2000 matchs with regex experimental0
    PacketDispatcher(0xa99a90) statistics
 	    Connected to Lan network stack
	    Total packets:                  40
	    Total bytes:                  7770
    RegexManager(0xc03310) statistics
	    Regex:experimental0 matches:5

    Exiting process

So now we have a regex capable of detecting exploits encoded with the metasploit framework.
