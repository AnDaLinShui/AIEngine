Extracting information
~~~~~~~~~~~~~~~~~~~~~~~

By using the traces from the defcon21 we will try to find signatures on a easy way.

For extracting information we will use the FrequencyEngine and the LearnerEngine. These two engines allow us to find signatures of unknown traffic such as new malware, traffic signatures and so on.

.. code:: bash


  Frequencies optional arguments:
    -F [ --enable-frequencies ]        Enables the Frequency engine.
    -g [ --group-by ] arg (=dst-port)  Groups frequencies by 
                                       src-ip,dst-ip,src-port and dst-port.
    -f [ --flow-type ] arg (=tcp)      Uses tcp or udp flows.
    -L [ --enable-learner ]            Enables the Learner engine.
    -k [ --key-learner ] arg (=80)     Sets the key for the Learner engine.
    -b [ --buffer-size ] arg (=64)     Sets the size of the internal buffer for 
                                       generate the regex.
    -y [ --enable-yara ]               Generates a yara signature.


Now first we see the traffic distribution by grouping by destination IP.

.. code:: bash

  ./aiengine -i /defcon21/european_defcon/  -F -g dst-ip
  3 [0x7f2ec98fe760] INFO aiengine.stacklan null - Lan network stack ready.
  1167 [0x7f2ec98fe760] INFO aiengine.stacklan null - Enable FrequencyEngine on Lan network stack
  1168 [0x7f2ec98fe760] INFO aiengine.packetdispatcher null - processing packets from:/defcon21/european_defcon//euronop_00092_20130802191248.cap
  1586 [0x7f2ec98fe760] INFO aiengine.packetdispatcher null - processing packets from:/defcon21/european_defcon//euronop_00031_20130802140748.cap
  1612 [0x7f2ec98fe760] INFO aiengine.packetdispatcher null - processing packets from:/defcon21/european_defcon//euronop_00049_20130802153748.cap
  ...
  Aggregating frequencies by destination IP
  Computing frequencies by destination IP
  Frequency Group(by destination IP) total frequencies groups:32
        Total process flows:30599
        Total computed frequencies:32
        Key                    Flows      Bytes      Dispersion Enthropy
        10.3.1.5               292        867421     12         0
        10.5.1.2               650        2661026    48         0
        10.5.10.2              645        1583049    40         0
        10.5.11.2              675        1778046    41         0
        10.5.12.2              670        9860998    42         0
        10.5.13.2              664        2852632    48         0
        10.5.14.118            9          276131     89         -105.036
        10.5.14.119            2          703        14         0
        10.5.14.12             1          2511       44         0
        10.5.14.2              649        2927839    48         0
        10.5.15.2              640        1852931    44         0
        10.5.16.2              665        2835281    40         0
        10.5.17.2              676        5620496    48         0
        10.5.18.2              664        1710898    41         0
        10.5.19.2              676        1797309    43         0
        10.5.2.2               671        1494479    41         0
        10.5.20.2              647        1502374    39         0
        10.5.3.2               668        1676005    41         0
        10.5.4.2               658        5795289    52         0
        10.5.5.2               675        1533368    37         0
        10.5.6.2               662        7079837    47         0
        10.5.7.12              1          1661       27         0
        10.5.7.13              4          322        4          0
        10.5.7.15              3          2265       9          0
        10.5.7.17              90         247224     44         0
        10.5.7.2               17590      220311075  30         0
        10.5.8.2               679        2201575    40         0
        10.5.8.25              5          20882      56         0
        10.5.9.13              1          1537       38         0
        10.5.9.14              2          699        15         0
        10.5.9.16              2          699        15         0
        10.5.9.2               663        2468757    48         0

So aiengine have been capable of analyzing 30599 TCP flows and grouping by 32 IPs. 
Now lets get an IP with flows and bytes, for example 10.5.7.2, and execute again aiengine but with a different grouping.

.. code:: bash

  ./aiengine -i /defcon21/european_defcon/  -F -g dst-ip -L -k "10.5.7.2"
  ...
  Aggregating 17590 to the LearnerEngine
  Regular expression generated with key:10.5.7.2
  Regex:^\x5b\x45\x52\x52\x4f\x52\x5d\x20\x69\x70\x76\x34\x20\x62\x69\x6e\x64\x28\x29\x20\x66\x61\x69\x6c\x65\x64\x20\x36\x32\x0a\x5d\x20\x69\x70\x76\x34\x20\x62\x69\x6e\x64\x28\x29\x20\x66\x61\x69\x6c\x65\x64\x20\x36\x32\x0a\x5b\x45\x52\x52\x4f\x52\x5d\x20\x69\x70
  Ascii buffer:[ERROR] ipv4 bind() failed 62
  ] ipv4 bind() failed 62
  [ERROR] ip


So it seems that the machine 10.5.7.2 is generating some kind of error binding, don't have two much sense but the regex generated is valid for identify that traffic.

Lets analyze another directory 

.. code:: bash

  ./aiengine -i /pwningyeti/  -F -g dst-ip,dst-port 
  5 [0x7f6583946760] INFO aiengine.stacklan null - Lan network stack ready.
  1164 [0x7f6583946760] INFO aiengine.stacklan null - Enable FrequencyEngine on Lan network stack
  1189 [0x7f6583946760] INFO aiengine.packetdispatcher null - processing packets from:/tmp/pwningyeti//pwningyeti_00001_20130802113656.cap
  1199 [0x7f6583946760] INFO aiengine.packetdispatcher null - processing packets from:/tmp/pwningyeti//pwningyeti_00001_20130802113748.cap
  1203 [0x7f6583946760] INFO aiengine.packetdispatcher null - processing packets from:/tmp/wningyeti//pwningyeti_00002_20130802113659.cap
  1208 [0x7f6583946760] INFO aiengine.packetdispatcher null - processing packets from:/tmp/pwningyeti//pwningyeti_00002_20130802114248.cap
  ...
  Aggregating frequencies by destination IP and port
  Computing frequencies by destination IP and port
  Frequency Group(by destination IP and port) total frequencies groups:156
        Total process flows:8755
        Total computed frequencies:156
        Key                    Flows      Bytes      Dispersion Enthropy
        10.3.1.5:443           3482       16521854   15         0
        10.5.14.2:34872        1          15275      17         0
        10.5.17.250:53230      1          74         3          0
        10.5.17.250:54359      1          3949       26         0
        10.5.17.250:54555      1          3949       26         0
        10.5.17.250:57654      1          390        11         0
        10.5.17.250:57711      1          390        11         0
        10.5.17.250:57718      1          390        11         0
        10.5.17.250:58251      1          6521       39         0
        10.5.17.250:58328      1          159        3          0
        10.5.17.250:58952      1          1998       19         0
        10.5.17.250:60286      1          37         3          0
        10.5.17.2:1011         2          16632      9          -8.75489
        10.5.17.2:10215        1          984        9          0
        10.5.17.2:1025         1          1620       5          0
        10.5.17.2:1029         1          13944      9          -47.6257

And now we choose destination IP and port.

.. code:: bash

  ./aiengine -i /pwningyeti/  -F -g dst-ip,dst-port -L -k 10.5.17.2:4321
  5 [0x7f6583946760] INFO aiengine.stacklan null - Lan network stack ready.
  1164 [0x7f6583946760] INFO aiengine.stacklan null - Enable FrequencyEngine on Lan network stack
  1189 [0x7f6583946760] INFO aiengine.packetdispatcher null - processing packets from:/tmp/pwningyeti//pwningyeti_00001_20130802113656.cap
  1199 [0x7f6583946760] INFO aiengine.packetdispatcher null - processing packets from:/tmp/pwningyeti//pwningyeti_00001_20130802113748.cap
  1203 [0x7f6583946760] INFO aiengine.packetdispatcher null - processing packets from:/tmp/wningyeti//pwningyeti_00002_20130802113659.cap
  1208 [0x7f6583946760] INFO aiengine.packetdispatcher null - processing packets from:/tmp/pwningyeti//pwningyeti_00002_20130802114248.cap
  ...
  Aggregating frequencies by destination IP and port
  ...
  Aggregating 1675 to the LearnerEngine
  Regular expression generated with key:10.5.17.2:4321
  Regex:^\x43\x6f\x6e\x6e\x65\x63\x74\x20\x74\x6f\x20\x35\x8b\x52\x30\x8b\x20\x74\x6f\x20\x76\x69\x65\x77\x20\x74\x68\x65\x20\x64\x69\x73\x70\x6c\x61\x79\x2e\x0a\x31\x20\x29\x20\x43\x68\x61\x6e\x67\x65\x20\x64\x69\x73\x70\x6c\x61\x79\x20\x74\x65\x78\x74\x2e\x0a\x32
  Ascii buffer:Connect to 5<8b>R0<8b> to view the display.
  1 ) Change display text.
  2



