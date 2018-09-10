In this section we are going to explore and compare the different performance values such as CPU and memory comsumption
with other engines such as tshark, snort, suricata and nDPI.

The main tools used for evaluate the performance is perf(https://linux.die.net/man/1/perf-stat).

+----------+---------+
| Tool     | Version |
+==========+=========+
| Snort    | 2.9.9.0 |
+----------+---------+
| Tshark   |   2.0.2 |
+----------+---------+
| Suricata |   3.2.1 |
+----------+---------+
| nDPI     |   2.1.0 |
+----------+---------+
| AIEngine |   1.9.0 |
+----------+---------+

The machine is a 8 CPUS Intel(R) Core(TM) i7-6820HQ CPU @ 2.70GHz with 16 GB memory. 

The first pcap file use is from (http://www.unb.ca/cic/research/datasets/index.html) is aproximately 17GB size with the mayority of traffic HTTP.
The pcap file used for these tests contains a distribution of traffic shown below

+-----------------+------------+---------+-------------+
| Network Protocol| Percentage | Bytes   | Packets     |
+=================+============+=========+=============+
| IPv4            |        97% | 12154MB |    17292813 |
+-----------------+------------+---------+-------------+
| TCP             |        95% | 11821MB |    17029774 | 
+-----------------+------------+---------+-------------+
| HTTP            |        88% | 11001MB |     9237421 | 
+-----------------+------------+---------+-------------+
| SSL             |         1% |   205MB |      223309 |
+-----------------+------------+---------+-------------+

The second pcap file used is from (https://download.netresec.com/pcap/ists-12/2015-03-07/). We downloaded the first 55 files and generate a pcap file about 8GB.
The pcap file used for these tests contains a distribution of traffic shown below

+-----------------+------------+---------+-------------+
| Network Protocol| Percentage | Bytes   | Packets     |
+=================+============+=========+=============+
| IPv4            |        97% |  7604MB |    13512877 |
+-----------------+------------+---------+-------------+
| TCP             |        88% |  6960MB |    12261324 |
+-----------------+------------+---------+-------------+
| UDP             |         4% |   374MB |      928563 |
+-----------------+------------+---------+-------------+
| HTTP            |        27% |  2160MB |     1763905 |
+-----------------+------------+---------+-------------+
| SSL             |        38% |  3046MB |     2508241 |
+-----------------+------------+---------+-------------+

The thrird pcap file used is from (https://www.unsw.adfa.edu.au/australian-centre-for-cyber-security/cybersecurity/ADFA-NB15-Datasets/). We downloaded 20 samples and generate
a pcap file of 40GB. The traffic distribution is shown bellow.

+-----------------+------------+---------+-------------+
| Network Protocol| Percentage | Bytes   | Packets     |
+=================+============+=========+=============+
| IPv4            |        97% | 36006MB |    70030290 |
+-----------------+------------+---------+-------------+
| TCP             |        93% | 34586MB |    68877826 |
+-----------------+------------+---------+-------------+
| HTTP            |        25% |  9366MB |     7285451 |
+-----------------+------------+---------+-------------+
| SMTP            |         5% |  1855MB |     2201546 |
+-----------------+------------+---------+-------------+


Be aware that the results depends on the type of traffic of the network.

Test I
......

In this section we are going to perform the first pcap (http://www.unb.ca/cic/research/datasets/index.html)


Test I processing traffic
~~~~~~~~~~~~~~~~~~~~~~~~~

In this section we explore how fast are the engines just processing the traffic without any rules or any logic on them.

Snort
*****

.. code:: bash

   Performance counter stats for './snort -r /pcaps/iscx/testbed-17jun.pcap -c ./snort.conf':

      64269.015098      task-clock (msec)         #    0.981 CPUs utilized          
             1,760      context-switches          #    0.027 K/sec                  
                36      cpu-migrations            #    0.001 K/sec                  
            44,841      page-faults               #    0.698 K/sec                  
   204,394,163,771      cycles                    #    3.180 GHz                    
   375,256,677,520      instructions              #    1.84  insns per cycle        
    98,031,161,725      branches                  # 1525.325 M/sec                  
       565,404,035      branch-misses             #    0.58% of all branches        

      65.487290231 seconds time elapsed

Tshark
******

.. code:: bash

   Performance counter stats for 'tshark -q -z conv,tcp -r /pcaps/iscx/testbed-17jun.pcap':

     112070.498904      task-clock (msec)         #    0.909 CPUs utilized          
            11,390      context-switches          #    0.102 K/sec                  
               261      cpu-migrations            #    0.002 K/sec                  
         2,172,942      page-faults               #    0.019 M/sec                  
   310,196,020,123      cycles                    #    2.768 GHz                    
   449,687,949,322      instructions              #    1.45  insns per cycle        
    99,620,662,743      branches                  #  888.911 M/sec                  
       729,598,416      branch-misses             #    0.73% of all branches        

     123.265736897 seconds time elapsed

Suricata
********

With 9 packet processing threads

.. code:: bash

   Performance counter stats for './suricata -c suricata.yaml -r /pcaps/iscx/testbed-17jun.pcap':

     100446.349460      task-clock (msec)         #    3.963 CPUs utilized          
         2,264,381      context-switches          #    0.023 M/sec                  
           220,905      cpu-migrations            #    0.002 M/sec                  
           108,722      page-faults               #    0.001 M/sec                  
   274,824,170,581      cycles                    #    2.736 GHz                    
   249,152,605,118      instructions              #    0.91  insns per cycle        
    56,052,176,697      branches                  #  558.031 M/sec                  
       538,776,158      branch-misses             #    0.96% of all branches        

      25.345742192 seconds time elapsed

With one packet processing thread

.. code:: bash

   Performance counter stats for './suricata -c suricata.yaml --runmode single -r /pcaps/iscx/testbed-17jun.pcap':

      94797.134432      task-clock (msec)         #    1.989 CPUs utilized          
           124,424      context-switches          #    0.001 M/sec                  
             1,158      cpu-migrations            #    0.012 K/sec                  
            71,535      page-faults               #    0.755 K/sec                  
   261,166,110,590      cycles                    #    2.755 GHz                    
   306,188,504,447      instructions              #    1.17  insns per cycle        
    72,333,018,827      branches                  #  763.030 M/sec                  
       468,673,879      branch-misses             #    0.65% of all branches        

      47.668130400 seconds time elapsed

nDPI
****

.. code:: bash

   Performance counter stats for './ndpiReader -i /pcaps/iscx/testbed-17jun.pcap':

      20134.419533      task-clock (msec)         #    0.758 CPUs utilized          
            78,990      context-switches          #    0.004 M/sec                  
               104      cpu-migrations            #    0.005 K/sec                  
            44,408      page-faults               #    0.002 M/sec                  
    55,566,151,984      cycles                    #    2.760 GHz                    
    62,980,097,786      instructions              #    1.13  insns per cycle        
    15,048,874,292      branches                  #  747.420 M/sec                  
       281,671,995      branch-misses             #    1.87% of all branches        

      26.559667812 seconds time elapsed

AIengine
********

.. code:: bash

    Performance counter stats for './aiengine -i /pcaps/iscx/testbed-17jun.pcap -o':

      19202.090831      task-clock (msec)         #    0.734 CPUs utilized          
            88,991      context-switches          #    0.005 M/sec                  
               169      cpu-migrations            #    0.009 K/sec                  
             9,056      page-faults               #    0.472 K/sec                  
    52,329,128,833      cycles                    #    2.725 GHz                    
    62,936,409,522      instructions              #    1.20  insns per cycle        
    13,381,787,761      branches                  #  696.892 M/sec                  
       192,876,738      branch-misses             #    1.44% of all branches        

      26.146906918 seconds time elapsed

+-------------+----------+--------------+---------+
| Test        | Cycles   | Instructions | Seconds |
+=============+==========+==============+=========+
| Snort       | 204.394M |     375.256M |      65 |
+-------------+----------+--------------+---------+
| Tshark      | 310.196M |      99.620M |     123 |
+-------------+----------+--------------+---------+
| Suricata(9) | 274.824M |     249.152M |      25 |
+-------------+----------+--------------+---------+
| Suricata(1) | 261.166M |     306.188M |      47 |
+-------------+----------+--------------+---------+
| nDPI        |  55.566M |      62.980M |      26 |
+-------------+----------+--------------+---------+
| AIEngine    |  52.329M |      62.936M |      26 |
+-------------+----------+--------------+---------+

Tests I with rules
~~~~~~~~~~~~~~~~~~

On this section we evalute simple rules in order to compare the different systems.

The rule that we are going to use is quite simple, it consists on find the string "cmd.exe" on the payload of all the TCP traffic.

Snort
*****

.. code:: bash

   alert tcp any any -> any any (content:"cmd.exe"; msg:"Traffic with cmd.exe on it"; sid:1)

.. code:: bash

   Performance counter stats for './snort -r /pcaps/iscx/testbed-17jun.pcap -c ./snort.conf':

     271091.019789      task-clock (msec)         #    0.994 CPUs utilized          
             3,213      context-switches          #    0.012 K/sec                  
                80      cpu-migrations            #    0.000 K/sec                  
            65,124      page-faults               #    0.240 K/sec                  
   731,608,435,272      cycles                    #    2.699 GHz                    
 1,033,203,748,622      instructions              #    1.41  insns per cycle        
   193,558,431,134      branches                  #  713.998 M/sec                  
       655,588,320      branch-misses             #    0.34% of all branches        

     272.704320602 seconds time elapsed

Suricata
********

.. code:: bash

   alert tcp any any -> any any (content:"cmd.exe"; msg:"Traffic with cmd.exe on it"; sid:1; rev:1;)

With 9 packet processing threads

.. code:: bash

   Performance counter stats for './suricata -c suricata.yaml -r /pcaps/iscx/testbed-17jun.pcap':

     147104.764348      task-clock (msec)         #    4.864 CPUs utilized          
         1,380,685      context-switches          #    0.009 M/sec                  
            49,927      cpu-migrations            #    0.339 K/sec                  
           388,670      page-faults               #    0.003 M/sec                  
   404,341,193,048      cycles                    #    2.749 GHz                    
   426,566,148,876      instructions              #    1.05  insns per cycle        
    80,421,852,312      branches                  #  546.698 M/sec                  
       624,570,278      branch-misses             #    0.78% of all branches        

      30.242149664 seconds time elapsed

With one packet processing thread

.. code:: bash

   Performance counter stats for './suricata -c suricata.yaml --runmode single -r /pcaps/iscx/testbed-17jun.pcap':

     158579.888281      task-clock (msec)         #    1.976 CPUs utilized          
            97,030      context-switches          #    0.612 K/sec                  
             1,143      cpu-migrations            #    0.007 K/sec                  
            52,539      page-faults               #    0.331 K/sec                  
   442,028,848,482      cycles                    #    2.787 GHz                    
   591,840,610,271      instructions              #    1.34  insns per cycle        
   125,011,110,377      branches                  #  788.316 M/sec                  
       493,436,768      branch-misses             #    0.39% of all branches        

      80.250462424 seconds time elapsed

AIEngine
********

Rule: "cmd.exe"

.. code:: bash

   Performance counter stats for './aiengine -i /pcaps/iscx/testbed-17jun.pcap -R -r cmd.exe -m -c tcp':

      26747.368819      task-clock (msec)         #    0.951 CPUs utilized          
            39,676      context-switches          #    0.001 M/sec                  
                25      cpu-migrations            #    0.001 K/sec                  
             2,474      page-faults               #    0.092 K/sec                  
    82,052,637,330      cycles                    #    3.068 GHz                    
   171,741,160,953      instructions              #    2.09  insns per cycle        
    48,822,142,461      branches                  # 1825.306 M/sec                  
       455,827,134      branch-misses             #    0.93% of all branches        

      28.137060566 seconds time elapsed

+-------------+----------+--------------+---------+
| Test        | Cycles   | Instructions | Seconds |
+=============+==========+==============+=========+
| Snort       | 731.608M |   1.033.203M |     272 |
+-------------+----------+--------------+---------+
| Suricata(9) | 404.341M |     426.566M |      30 |
+-------------+----------+--------------+---------+
| Suricata(1) | 442.028M |     591.840M |      80 |
+-------------+----------+--------------+---------+
| AIEngine    |  82.052M |     172.741M |      28 |
+-------------+----------+--------------+---------+

Snort
*****

A simliar rules as before but just trying to help a bit to Snort.

.. code:: bash

   alert tcp any any -> any 80 (content:"cmd.exe"; msg:"Traffic with cmd.exe on it"; sid:1; rev:1;)

.. code:: bash

   Performance counter stats for './snort -r /pcaps/iscx/testbed-17jun.pcap -c ./snort.conf':

      70456.213488      task-clock (msec)         #    0.984 CPUs utilized          
             5,901      context-switches          #    0.084 K/sec                  
                63      cpu-migrations            #    0.001 K/sec                  
            79,927      page-faults               #    0.001 M/sec                  
   214,846,354,228      cycles                    #    3.049 GHz                    
   385,107,871,838      instructions              #    1.79  insns per cycle        
   100,011,250,526      branches                  # 1419.481 M/sec                  
       579,460,528      branch-misses             #    0.58% of all branches        

      71.582493144 seconds time elapsed

Suricata
********

Change the rule just for HTTP traffic

.. code:: bash

   alert http any any -> any any (content:"cmd.exe"; msg:"Traffic with cmd.exe on it"; sid:1; rev:1;)

With 9 processing packet threads

.. code:: bash

   Performance counter stats for './suricata -c suricata.yaml -r /pcaps/iscx/testbed-17jun.pcap':

     140314.604419      task-clock (msec)         #    5.007 CPUs utilized          
         1,326,047      context-switches          #    0.009 M/sec                  
            81,882      cpu-migrations            #    0.584 K/sec                  
           287,767      page-faults               #    0.002 M/sec                  
   385,297,597,444      cycles                    #    2.746 GHz                    
   427,295,175,085      instructions              #    1.11  insns per cycle        
    80,682,776,679      branches                  #  575.013 M/sec                  
       570,289,598      branch-misses             #    0.71% of all branches        

      28.023789653 seconds time elapsed

With one processing packet thread

.. code:: bash

   Performance counter stats for './suricata -c suricata.yaml --runmode single -r /pcaps/iscx/testbed-17jun.pcap':

     148652.663600      task-clock (msec)         #    1.974 CPUs utilized          
            96,622      context-switches          #    0.650 K/sec                  
               637      cpu-migrations            #    0.004 K/sec                  
            53,167      page-faults               #    0.358 K/sec                  
   426,698,526,702      cycles                    #    2.870 GHz                    
   591,218,425,219      instructions              #    1.39  insns per cycle        
   124,816,600,210      branches                  #  839.653 M/sec                  
       475,639,059      branch-misses             #    0.38% of all branches        

      75.314408592 seconds time elapsed

AIEngine
********

.. code:: python

  def anomaly_callback(flow):
      print("rule on HTTP %s" % str(flow))

  if __name__ == '__main__':

      st = StackLan()

      http = DomainNameManager() 
      rm = RegexManager()
      r = Regex("my cmd.exe", "cmd.exe", anomaly_callback)

      d1 = DomainName("Generic net",".net")
      d2 = DomainName("Generic com",".com")
      d3 = DomainName("Generic org",".org")
 
      http.add_domain_name(d1) 
      http.add_domain_name(d2) 
      http.add_domain_name(d3) 

      d1.regex_manager = rm
      d2.regex_manager = rm
      d3.regex_manager = rm

      rm.add_regex(r)

      st.set_domain_name_manager(http, "HTTPProtocol")

      st.set_dynamic_allocated_memory(True)
    
      with pyaiengine.PacketDispatcher("/pcaps/iscx/testbed-17jun.pcap") as pd:
          pd.stack = st
          pd.run()

.. code:: bash

   Performance counter stats for 'python performance_test01.py':

      26968.177275      task-clock (msec)         #    0.945 CPUs utilized          
            36,929      context-switches          #    0.001 M/sec                  
                24      cpu-migrations            #    0.001 K/sec                  
            11,524      page-faults               #    0.427 K/sec                  
    87,786,718,727      cycles                    #    3.255 GHz                    
   166,828,029,212      instructions              #    1.90  insns per cycle        
    46,444,468,574      branches                  # 1722.195 M/sec                  
       499,183,656      branch-misses             #    1.07% of all branches        

      28.527290319 seconds time elapsed

+-------------+----------+--------------+---------+
| Test        | Cycles   | Instructions | Seconds |
+=============+==========+==============+=========+
| Snort       | 214.846M |     385.107M |      71 |
+-------------+----------+--------------+---------+
| Suricata(9) | 385.297M |     591.218M |      28 |
+-------------+----------+--------------+---------+
| Suricata(1) | 426.698M |     591.840M |      75 |
+-------------+----------+--------------+---------+
| AIEngine    |  87.786M |     166.828M |      28 |
+-------------+----------+--------------+---------+

Tests I with 31.000 rules
~~~~~~~~~~~~~~~~~~~~~~~~~

On this section we evalute aproximatelly 31.000 rules in order to compare the different systems.
Basically we load 31.000 different domains on each engine and loaded into memory and compare the performance.

Snort
*****

.. code:: bash
   
   alert tcp any any -> any 80 (content:"lb.usemaxserver.de"; msg:"Traffic"; sid:1; rev:1;)
   ....

.. code:: bash

   Performance counter stats for './snort -r /pcaps/iscx/testbed-17jun.pcap -c ./snort.conf':

     239911.454192      task-clock (msec)         #    0.994 CPUs utilized          
             1,866      context-switches          #    0.008 K/sec                  
                29      cpu-migrations            #    0.000 K/sec                  
           275,912      page-faults               #    0.001 M/sec                  
   730,183,866,577      cycles                    #    3.044 GHz                    
   523,549,153,058      instructions              #    0.72  insns per cycle        
   151,703,407,200      branches                  #  632.331 M/sec                  
       784,133,786      branch-misses             #    0.52% of all branches        

     241.344591225 seconds time elapsed

Suricata
********

.. code:: bash

   alert http any any -> any any (content:"lb.usemaxserver.de"; http_host; msg:"Traffic"; sid:1; rev:1;)
   ....

With 9 processing packet threads

.. code:: bash

   Performance counter stats for './suricata -r /pcaps/iscx/testbed-17jun.pcap -c suricata.yaml':

     129366.651117      task-clock (msec)         #    3.812 CPUs utilized          
         1,484,897      context-switches          #    0.011 M/sec                  
           115,294      cpu-migrations            #    0.891 K/sec                  
           347,011      page-faults               #    0.003 M/sec                  
   354,238,365,666      cycles                    #    2.738 GHz                    
   330,226,571,287      instructions              #    0.93  insns per cycle        
    81,479,451,099      branches                  #  629.834 M/sec                  
       598,088,820      branch-misses             #    0.73% of all branches        

      33.935354390 seconds time elapsed

With one single packet thread

.. code:: bash

   Performance counter stats for './suricata -c suricata.yaml --runmode single -r /pcaps/iscx/testbed-17jun.pcap':

     137079.150338      task-clock (msec)         #    1.872 CPUs utilized          
           101,577      context-switches          #    0.741 K/sec                  
             1,481      cpu-migrations            #    0.011 K/sec                  
           291,789      page-faults               #    0.002 M/sec                  
   370,552,220,742      cycles                    #    2.703 GHz                    
   443,891,171,842      instructions              #    1.20  insns per cycle        
   112,343,969,730      branches                  #  819.555 M/sec                  
       518,724,581      branch-misses             #    0.46% of all branches        

      73.230102972 seconds time elapsed

nDPI
****

.. code:: bash

   host:"lb.usemaxserver.de"@MyProtocol

.. code:: bash

   Performance counter stats for './ndpiReader -p http_ndpi.rules -i /pcaps/iscx/testbed-17jun.pcap':

      21913.851054      task-clock (msec)         #    0.779 CPUs utilized          
            59,037      context-switches          #    0.003 M/sec                  
                83      cpu-migrations            #    0.004 K/sec                  
           716,580      page-faults               #    0.033 M/sec                  
    59,048,108,901      cycles                    #    2.695 GHz                    
    63,994,766,870      instructions              #    1.08  insns per cycle        
    15,288,226,665      branches                  #  697.651 M/sec                  
       284,549,749      branch-misses             #    1.86% of all branches        

      28.147959104 seconds time elapsed

AIEngine
********

.. code:: bash

   h = pyaiengine.DomainName("domain_1" % i, "b.usemaxserver.de")
   h.callback = http_callback
   dm.add_domain_name(h)
   ....

.. code:: bash

   Performance counter stats for 'python performance_test02.py':

      19294.337975      task-clock (msec)         #    0.736 CPUs utilized          
            89,548      context-switches          #    0.005 M/sec                  
                69      cpu-migrations            #    0.004 K/sec                  
            18,062      page-faults               #    0.936 K/sec                  
    54,283,291,704      cycles                    #    2.813 GHz                    
    66,073,464,439      instructions              #    1.22  insns per cycle        
    14,268,669,502      branches                  #  739.526 M/sec                  
       193,337,567      branch-misses             #    1.35% of all branches        

      26.212025353 seconds time elapsed

+-------------+----------+--------------+---------+
| Test        | Cycles   | Instructions | Seconds |
+=============+==========+==============+=========+
| Snort       | 730.183M |     523.549M |     241 |
+-------------+----------+--------------+---------+
| Suricata(9) | 354.238M |     330.226M |      33 |
+-------------+----------+--------------+---------+
| Suricata(1) | 370.552M |     443.891M |      73 |
+-------------+----------+--------------+---------+
| nDPI        |  59.048M |      63.994M |      28 |
+-------------+----------+--------------+---------+
| AIEngine    |  54.283M |      66.073M |      26 |
+-------------+----------+--------------+---------+

Now we are going to make a complex rule.

The idea is to analyze the HTTP uri and search for a word in our case "exe".

Snort
*****

.. code:: bash

   alert tcp any any -> any 80 (content:"lb.usemaxserver.de"; uricontent:"exe"; msg:"Traffic"; sid:1; rev:1;)
   ....

.. code:: bash

   Performance counter stats for './snort -r /pcaps/iscx/testbed-17jun.pcap -c ./snort.conf':

      76455.475108      task-clock (msec)         #    0.981 CPUs utilized          
             3,594      context-switches          #    0.047 K/sec                  
                99      cpu-migrations            #    0.001 K/sec                  
           111,397      page-faults               #    0.001 M/sec                  
   229,619,037,994      cycles                    #    3.003 GHz                    
   405,962,474,441      instructions              #    1.77  insns per cycle        
   106,466,397,876      branches                  # 1392.528 M/sec                  
       594,124,564      branch-misses             #    0.56% of all branches        

      77.938067412 seconds time elapsed

Suricata
********

.. code:: bash

   alert http any any -> any any (content:"lb.usemaxserver.de"; http_host; conent:"exe"; http_uri; msg:"Traffic"; sid:1; rev:1;)
   ....

With 9 processing packet threads

.. code:: bash

   Performance counter stats for './suricata -r /pcaps/iscx/testbed-17jun.pcap -c suricata.yaml':

     123037.997614      task-clock (msec)         #    3.475 CPUs utilized          
         1,765,919      context-switches          #    0.014 M/sec                  
           148,475      cpu-migrations            #    0.001 M/sec                  
           353,585      page-faults               #    0.003 M/sec                  
   332,912,328,748      cycles                    #    2.706 GHz                    
   332,626,051,284      instructions              #    1.00  insns per cycle        
    81,934,929,717      branches                  #  665.932 M/sec                  
       592,853,289      branch-misses             #    0.72% of all branches        

      35.411677796 seconds time elapsed

With one single packet thread

.. code:: bash

   Performance counter stats for './suricata -c suricata.yaml --runmode single -r /pcaps/iscx/testbed-17jun.pcap':

     111133.956719      task-clock (msec)         #    1.843 CPUs utilized          
           111,599      context-switches          #    0.001 M/sec                  
             1,077      cpu-migrations            #    0.010 K/sec                  
           306,054      page-faults               #    0.003 M/sec                  
   310,127,777,799      cycles                    #    2.791 GHz                    
   412,013,001,291      instructions              #    1.33  insns per cycle        
   103,895,197,621      branches                  #  934.865 M/sec                  
       508,998,872      branch-misses             #    0.49% of all branches        

      60.309266689 seconds time elapsed

AIEngine
********

.. code:: python 

   rm = pyaiengine.RegexManager()
   r = pyaiengine.Regex("on the uri", "^.*(exe).*$")
   rm.add_regex(r)

   h = pyaiengine.DomainName("domain_1" % i, "b.usemaxserver.de")
   h.callback = http_callback
   h.http_uri_regex_manager = rm
   dm.add_domain_name(h)
   ....

.. code:: bash

   Performance counter stats for 'python performance_test03.py':

      19918.838043      task-clock (msec)         #    0.754 CPUs utilized          
            86,064      context-switches          #    0.004 M/sec                  
                61      cpu-migrations            #    0.003 K/sec                  
            18,424      page-faults               #    0.925 K/sec                  
    56,079,876,263      cycles                    #    2.815 GHz                    
    71,568,179,654      instructions              #    1.28  insns per cycle        
    15,251,338,373      branches                  #  765.674 M/sec                  
       199,032,932      branch-misses             #    1.31% of all branches        

      26.411278022 seconds time elapsed

+-------------+----------+--------------+---------+
| Test        | Cycles   | Instructions | Seconds |
+=============+==========+==============+=========+
| Snort       | 229.619M |     405.962M |      77 |
+-------------+----------+--------------+---------+
| Suricata(9) | 332.912M |     332.626M |      35 |
+-------------+----------+--------------+---------+
| Suricata(1) | 310.127M |     412.013M |      60 |
+-------------+----------+--------------+---------+
| AIEngine    |  56.079M |      71.568M |      26 |
+-------------+----------+--------------+---------+


Another tests by making more complex the rule 

The idea is to analyze the HTTP uri and search for different words(exe, bat and png).

Snort
*****

.. code:: bash

   alert tcp any any -> any 80 (content:"lb.usemaxserver.de"; pcre:"/^.*(exe|bat|png).*$/"; msg:"Traffic"; sid:1; rev:1;)
   ...

.. code:: bash 

   Run time for packet processing was 87.8067 seconds
   Snort processed 17310684 packets.
   Snort ran for 0 days 0 hours 1 minutes 27 seconds
      Pkts/min:     17310684
      Pkts/sec:       198973

   ...

   Performance counter stats for './snort -r /pcaps/iscx/testbed-17jun.pcap -c ./snort.conf':

     332419.465677      task-clock (msec)         #    0.996 CPUs utilized          
             1,897      context-switches          #    0.006 K/sec                  
                70      cpu-migrations            #    0.000 K/sec                  
           298,836      page-faults               #    0.899 K/sec                  
   870,336,957,271      cycles                    #    2.618 GHz                    
   527,446,002,353      instructions              #    0.61  insns per cycle        
   152,281,712,268      branches                  #  458.101 M/sec                  
       771,410,918      branch-misses             #    0.51% of all branches        

     333.678629049 seconds time elapsed

The packet processing takes about 88 seconds but the full load of the rules takes a long time, probably due to the use of the pcre.

Suricata
********

.. code:: bash

   alert http any any -> any any (content:"lb.usemaxserver.de"; http_host; pcre:"/^.*(exe|bat|png).*$/"; msg:"Traffic"; sid:1; rev:1;)
   ...

With 9 processing packet threads

.. code:: bash

   Performance counter stats for './suricata -c suricata.yaml -r /pcaps/iscx/testbed-17jun.pcap':

     133747.431539      task-clock (msec)         #    3.796 CPUs utilized          
         1,507,433      context-switches          #    0.011 M/sec                  
           123,806      cpu-migrations            #    0.926 K/sec                  
           374,176      page-faults               #    0.003 M/sec                  
   362,046,514,184      cycles                    #    2.707 GHz                    
   335,210,037,408      instructions              #    0.93  insns per cycle        
    82,517,301,739      branches                  #  616.964 M/sec                  
       598,287,782      branch-misses             #    0.73% of all branches        

      35.237027328 seconds time elapsed

Running suricata with one single thread (same has AIEngine)

.. code:: bash

   Performance counter stats for './suricata -c suricata.yaml --runmode single -r /pcaps/iscx/testbed-17jun.pcap':

     122334.651821      task-clock (msec)         #    1.864 CPUs utilized          
            97,856      context-switches          #    0.800 K/sec                  
             1,073      cpu-migrations            #    0.009 K/sec                  
           300,312      page-faults               #    0.002 M/sec                  
   344,624,244,835      cycles                    #    2.817 GHz                    
   439,114,648,308      instructions              #    1.27  insns per cycle        
   110,921,840,589      branches                  #  906.708 M/sec                  
       513,286,800      branch-misses             #    0.46% of all branches        

      65.636419341 seconds time elapsed

AIEngine
********

By using the or exclusive on the regex

.. code:: python

   rm = pyaiengine.RegexManager()
   r = pyaiengine.Regex("on the uri", "^.*(exe|png|bat).*$")
   rm.add_regex(r)

   h = pyaiengine.DomainName("domain_1" % i, "b.usemaxserver.de")
   h.callback = http_callback
   h.http_uri_regex_manager = rm
   dm.add_domain_name(h)
   ....

.. code:: bash

   Performance counter stats for 'python performance_test04_a.py':

      20849.169415      task-clock (msec)         #    0.778 CPUs utilized          
            81,424      context-switches          #    0.004 M/sec                  
                69      cpu-migrations            #    0.003 K/sec                  
            18,432      page-faults               #    0.884 K/sec                  
    58,908,878,403      cycles                    #    2.825 GHz                    
    78,849,595,244      instructions              #    1.34  insns per cycle        
    16,315,789,886      branches                  #  782.563 M/sec                  
       204,727,568      branch-misses             #    1.25% of all branches        

      26.789375316 seconds time elapsed

Creating three different regex

.. code:: python

   rm = pyaiengine.RegexManager()
   r1 = pyaiengine.Regex("on the uri1", "^.*(exe).*$")
   r2 = pyaiengine.Regex("on the uri2", "^.*(png).*$")
   r3 = pyaiengine.Regex("on the uri3", "^.*(bat).*$")
   rm.add_regex(r1)
   rm.add_regex(r2)
   rm.add_regex(r3)

.. code:: bash

   Performance counter stats for 'python performance_test04_b.py':

      20849.731942      task-clock (msec)         #    0.779 CPUs utilized          
            81,160      context-switches          #    0.004 M/sec                  
                68      cpu-migrations            #    0.003 K/sec                  
            18,419      page-faults               #    0.883 K/sec                  
    59,083,780,002      cycles                    #    2.834 GHz                    
    80,040,676,871      instructions              #    1.35  insns per cycle        
    16,776,535,223      branches                  #  804.640 M/sec                  
       207,899,147      branch-misses             #    1.24% of all branches        

      26.759843925 seconds time elapsed

+-------------+----------+--------------+---------+
| Test        | Cycles   | Instructions | Seconds |
+=============+==========+==============+=========+
| Snort       | 870.336M |     527.446M |      87 |
+-------------+----------+--------------+---------+
| Suricata(9) | 362.046M |     335.210M |      35 |
+-------------+----------+--------------+---------+
| Suricata(1) | 344.624M |     439.114M |      65 |
+-------------+----------+--------------+---------+
| AIEngine    |  59.083M |      80.040M |      26 |
+-------------+----------+--------------+---------+

Test II
.......

In this section we are going to perform the second pcap (https://download.netresec.com/pcap/ists-12/2015-03-07/)


Test II processing traffic
~~~~~~~~~~~~~~~~~~~~~~~~~~

Same principal as the previous test, execute the engines without any rules or logic on them.

Snort
*****

.. code:: bash

   Performance counter stats for './snort -c snort.conf -r /pcaps/ists/snort.sample.142574.pcap':

      20239.719847      task-clock (msec)         #    0.896 CPUs utilized          
            13,720      context-switches          #    0.678 K/sec                  
                34      cpu-migrations            #    0.002 K/sec                  
            64,599      page-faults               #    0.003 M/sec                  
    60,253,485,863      cycles                    #    2.977 GHz                    
   103,576,923,708      instructions              #    1.72  insns per cycle        
    23,248,922,048      branches                  # 1148.678 M/sec                  
       145,650,931      branch-misses             #    0.63% of all branches        

      22.594726539 seconds time elapsed

Tshark
******

.. code:: bash

   Performance counter stats for 'tshark -q -z conv,tcp -r /pcaps/ists/snort.sample.142574.pcap':

     172043.327012      task-clock (msec)         #    0.986 CPUs utilized          
             8,925      context-switches          #    0.052 K/sec                  
                54      cpu-migrations            #    0.000 K/sec                  
         2,246,437      page-faults               #    0.013 M/sec                  
   507,338,842,395      cycles                    #    2.949 GHz                    
   490,075,423,649      instructions              #    0.97  insns per cycle        
   110,140,671,629      branches                  #  640.191 M/sec                  
       908,018,085      branch-misses             #    0.82% of all branches        

     174.515503354 seconds time elapsed

Suricata
********

With 9 packet processing threads

.. code:: bash

   Performance counter stats for './suricata -c suricata.yaml -r /pcaps/ists/snort.sample.142574.pcap':

      49619.488693      task-clock (msec)         #    2.567 CPUs utilized          
         2,146,042      context-switches          #    0.043 M/sec                  
           274,824      cpu-migrations            #    0.006 M/sec                  
            41,016      page-faults               #    0.827 K/sec                  
   133,760,571,310      cycles                    #    2.696 GHz                    
   137,849,439,654      instructions              #    1.03  insns per cycle        
    29,990,793,429      branches                  #  604.416 M/sec                  
       240,231,193      branch-misses             #    0.80% of all branches        

      19.327455566 seconds time elapsed

With one packet processing thread

.. code:: bash

   Performance counter stats for './suricata -c suricata.yaml --runmode single -r /pcaps/ists/snort.sample.142574.pcap':

      27516.148594      task-clock (msec)         #    1.761 CPUs utilized          
            16,899      context-switches          #    0.614 K/sec                  
               152      cpu-migrations            #    0.006 K/sec                  
            28,250      page-faults               #    0.001 M/sec                  
    78,898,553,305      cycles                    #    2.867 GHz                    
   117,482,892,525      instructions              #    1.49  insns per cycle        
    26,234,850,954      branches                  #  953.435 M/sec                  
       173,307,394      branch-misses             #    0.66% of all branches        

      15.622774603 seconds time elapsed

nDPI
****

.. code:: bash

   Performance counter stats for './ndpiReader -i /pcaps/ists/snort.sample.142574.pcap':

       8334.169519      task-clock (msec)         #    1.000 CPUs utilized          
                15      context-switches          #    0.002 K/sec                  
                 4      cpu-migrations            #    0.000 K/sec                  
           117,034      page-faults               #    0.014 M/sec                  
    24,556,541,541      cycles                    #    2.946 GHz                    
    35,137,201,115      instructions              #    1.43  insns per cycle        
     7,695,905,629      branches                  #  923.416 M/sec                  
       109,421,601      branch-misses             #    1.42% of all branches        

       8.336547614 seconds time elapsed

AIengine
********

.. code:: bash

   Performance counter stats for './aiengine -i /pcaps/ists/snort.sample.142574.pcap -o':

       9000.634228      task-clock (msec)         #    1.000 CPUs utilized          
                15      context-switches          #    0.002 K/sec                  
                 0      cpu-migrations            #    0.000 K/sec                  
            22,805      page-faults               #    0.003 M/sec                  
    28,329,853,044      cycles                    #    3.148 GHz                    
    34,935,688,899      instructions              #    1.23  insns per cycle        
     6,795,995,969      branches                  #  755.057 M/sec                  
        58,891,094      branch-misses             #    0.87% of all branches        

       9.002452681 seconds time elapsed

+-------------+----------+--------------+---------+
| Test        | Cycles   | Instructions | Seconds |
+=============+==========+==============+=========+
| Snort       |  60.253M |     103.576M |      22 |
+-------------+----------+--------------+---------+
| Tshark      | 507.338M |     490.075M |     174 |
+-------------+----------+--------------+---------+
| Suricata(9) | 133.760M |     137.849M |      19 |
+-------------+----------+--------------+---------+
| Suricata(1) |  78.898M |     117.482M |      15 |
+-------------+----------+--------------+---------+
| nDPI        |  24.556M |      35.137M |       8 |
+-------------+----------+--------------+---------+
| AIEngine    |  28.329M |      34.935M |       9 |
+-------------+----------+--------------+---------+

Tests II with rules
~~~~~~~~~~~~~~~~~~~

The rule that we are going to use consists on find the string "cmd.exe" on the payload of all the TCP traffic.

Snort
*****

.. code:: bash

   alert tcp any any -> any any (content:"cmd.exe"; msg:"Traffic with cmd.exe on it"; sid:1)

.. code:: bash

   Performance counter stats for './snort -c snort.conf -r /pcaps/ists/snort.sample.142574.pcap':

      57274.705850      task-clock (msec)         #    0.978 CPUs utilized          
             1,475      context-switches          #    0.026 K/sec                  
                30      cpu-migrations            #    0.001 K/sec                  
            74,055      page-faults               #    0.001 M/sec                  
   170,108,684,940      cycles                    #    2.970 GHz                    
   249,563,724,967      instructions              #    1.47  insns per cycle        
    44,950,506,837      branches                  #  784.823 M/sec                  
       166,126,757      branch-misses             #    0.37% of all branches        

      58.554078720 seconds time elapsed

Suricata
********

.. code:: bash

   alert tcp any any -> any any (content:"cmd.exe"; msg:"Traffic with cmd.exe on it"; sid:1; rev:1;)

.. code:: bash 

   Performance counter stats for './suricata -c suricata.yaml -r /pcaps/ists/snort.sample.142574.pcap':

      55413.061279      task-clock (msec)         #    3.707 CPUs utilized          
         1,832,228      context-switches          #    0.033 M/sec                  
           208,029      cpu-migrations            #    0.004 M/sec                  
           178,505      page-faults               #    0.003 M/sec                  
   152,711,396,141      cycles                    #    2.756 GHz                    
   169,560,770,675      instructions              #    1.11  insns per cycle        
    33,695,213,952      branches                  #  608.073 M/sec                  
       254,682,262      branch-misses             #    0.76% of all branches        

      14.948748524 seconds time elapsed

With one packet processing thread

.. code:: bash

   Performance counter stats for './suricata -c suricata.yaml --runmode single -r /pcaps/ists/snort.sample.142574.pcap':

      37532.872741      task-clock (msec)         #    1.689 CPUs utilized          
            20,394      context-switches          #    0.543 K/sec                  
               166      cpu-migrations            #    0.004 K/sec                  
            28,466      page-faults               #    0.758 K/sec                  
   112,217,535,031      cycles                    #    2.990 GHz                    
   171,185,106,113      instructions              #    1.53  insns per cycle        
    35,464,805,544      branches                  #  944.900 M/sec                  
       178,621,523      branch-misses             #    0.50% of all branches        

      22.228136143 seconds time elapsed

AIEngine
********

Rule: "cmd.exe"

.. code:: bash

   Performance counter stats for './aiengine -R -r cmd.exe -c tcp -i /pcaps/ists/snort.sample.142574.pcap':

      12125.044384      task-clock (msec)         #    1.000 CPUs utilized          
                23      context-switches          #    0.002 K/sec                  
                 0      cpu-migrations            #    0.000 K/sec                  
            21,019      page-faults               #    0.002 M/sec                  
    40,456,778,797      cycles                    #    3.337 GHz                    
    84,076,255,167      instructions              #    2.08  insns per cycle        
    24,479,629,056      branches                  # 2018.931 M/sec                  
       106,652,753      branch-misses             #    0.44% of all branches        

      12.126841699 seconds time elapsed

+-------------+----------+--------------+---------+
| Test        | Cycles   | Instructions | Seconds |
+=============+==========+==============+=========+
| Snort       | 170.108M |     249.563M |      58 |
+-------------+----------+--------------+---------+
| Suricata(9) | 152.711M |     169.560M |      14 |
+-------------+----------+--------------+---------+
| Suricata(1) | 112.217M |     171.185M |      22 |
+-------------+----------+--------------+---------+
| AIEngine    |  40.456M |      84.076M |      13 |
+-------------+----------+--------------+---------+

Snort
*****

A simliar rules as before but just trying to help a bit to Snort.

.. code:: bash

   alert tcp any any -> any 80 (content:"cmd.exe"; msg:"Traffic with cmd.exe on it"; sid:1; rev:1;)

.. code:: bash

   Performance counter stats for './snort -c snort.conf -r /pcaps/ists/snort.sample.142574.pcap':

      18891.239382      task-clock (msec)         #    0.961 CPUs utilized          
               277      context-switches          #    0.015 K/sec                  
                12      cpu-migrations            #    0.001 K/sec                  
            75,406      page-faults               #    0.004 M/sec                  
    61,694,270,612      cycles                    #    3.266 GHz                    
   108,319,753,502      instructions              #    1.76  insns per cycle        
    24,001,563,160      branches                  # 1270.513 M/sec                  
       138,490,930      branch-misses             #    0.58% of all branches        

      19.653087466 seconds time elapsed

Suricata
********

Change the rule just for HTTP traffic

.. code:: bash

   alert http any any -> any any (content:"cmd.exe"; msg:"Traffic with cmd.exe on it"; sid:1; rev:1;)

With 9 processing packet threads

.. code:: bash

   Performance counter stats for './suricata -c suricata.yaml -r /pcaps/ists/snort.sample.142574.pcap':

      55218.532532      task-clock (msec)         #    3.725 CPUs utilized          
         1,830,002      context-switches          #    0.033 M/sec                  
           194,003      cpu-migrations            #    0.004 M/sec                  
           190,322      page-faults               #    0.003 M/sec                  
   152,046,385,482      cycles                    #    2.754 GHz                    
   168,972,894,992      instructions              #    1.11  insns per cycle        
    33,590,489,520      branches                  #  608.319 M/sec                  
       250,682,512      branch-misses             #    0.75% of all branches        

      14.825638711 seconds time elapsed

With one processing packet thread

.. code:: bash

   Performance counter stats for './suricata -c suricata.yaml --runmode single -r /pcaps/ists/snort.sample.142574.pcap':

      37795.997821      task-clock (msec)         #    1.689 CPUs utilized          
            18,530      context-switches          #    0.490 K/sec                  
               211      cpu-migrations            #    0.006 K/sec                  
            28,111      page-faults               #    0.744 K/sec                  
   112,302,644,819      cycles                    #    2.971 GHz                    
   171,212,241,453      instructions              #    1.52  insns per cycle        
    35,470,318,890      branches                  #  938.468 M/sec                  
       178,287,454      branch-misses             #    0.50% of all branches        

      22.376103005 seconds time elapsed

AIEngine
********

The python code used is the same as the previous examples

.. code:: bash

   Performance counter stats for 'python performance_test01.py':

      10380.023003      task-clock (msec)         #    0.999 CPUs utilized          
                64      context-switches          #    0.006 K/sec                  
                 5      cpu-migrations            #    0.000 K/sec                  
            26,505      page-faults               #    0.003 M/sec                  
    33,118,324,614      cycles                    #    3.191 GHz                    
    50,205,755,209      instructions              #    1.52  insns per cycle        
    12,277,431,224      branches                  # 1182.794 M/sec                  
        74,797,014      branch-misses             #    0.61% of all branches        

      10.394503035 seconds time elapsed

+-------------+----------+--------------+---------+
| Test        | Cycles   | Instructions | Seconds |
+=============+==========+==============+=========+
| Snort       |  61.694M |     108.319M |      19 |
+-------------+----------+--------------+---------+
| Suricata(9) | 152.046M |     168.972M |      14 |
+-------------+----------+--------------+---------+
| Suricata(1) | 112.302M |     171.212M |      22 |
+-------------+----------+--------------+---------+
| AIEngine    |  33.118M |      50.205M |      10 |
+-------------+----------+--------------+---------+

Tests II with 31.000 rules
~~~~~~~~~~~~~~~~~~~~~~~~~~

On this section we evalute aproximatelly 31.000 rules in order to compare the different systems.
We will execute a complex rule directly instead of test a basic one as did on previous tests

Be aware that the portion of HTTP on this pcap is different and the rules generated are for HTTP traffic basically.

Snort
*****

.. code:: bash

   alert tcp any any -> any 80 (content:"lb.usemaxserver.de"; pcre:"/^.*(exe|bat|png).*$/"; msg:"Traffic"; sid:1; rev:1;) 
   ...

.. code:: bash

   Run time for packet processing was 27.3672 seconds
   Snort processed 14021863 packets.
   Snort ran for 0 days 0 hours 0 minutes 27 seconds
      Pkts/sec:       519328
   ...

   Performance counter stats for './snort -c snort.conf -r /pcaps/ists/snort.sample.142574.pcap':

     188025.287538      task-clock (msec)         #    0.987 CPUs utilized          
            13,598      context-switches          #    0.072 K/sec                  
                45      cpu-migrations            #    0.000 K/sec                  
           276,745      page-faults               #    0.001 M/sec                  
   589,679,607,434      cycles                    #    3.136 GHz                    
   247,581,636,213      instructions              #    0.42  insns per cycle        
    75,802,520,939      branches                  #  403.151 M/sec                  
       332,483,691      branch-misses             #    0.44% of all branches        

     190.513077863 seconds time elapsed

Suricata
********

.. code:: bash

   alert http any any -> any any (content:"lb.usemaxserver.de"; http_host; pcre:"/^.*(exe|bat|png).*$/"; msg:"Traffic"; sid:1; rev:1;)
   ...

With 9 processing packet threads

.. code:: bash

   Performance counter stats for './suricata -c suricata.yaml -r /pcaps/ists/snort.sample.142574.pcap':

      63154.209557      task-clock (msec)         #    2.605 CPUs utilized          
         1,939,476      context-switches          #    0.031 M/sec                  
           224,117      cpu-migrations            #    0.004 M/sec                  
           273,255      page-faults               #    0.004 M/sec                  
   175,477,179,743      cycles                    #    2.779 GHz                    
   221,833,693,652      instructions              #    1.26  insns per cycle        
    55,880,187,462      branches                  #  884.821 M/sec                  
       288,292,750      branch-misses             #    0.52% of all branches        

      24.242640026 seconds time elapsed

Running suricata with one single thread

.. code:: bash

   Performance counter stats for './suricata -c suricata.yaml --runmode single -r /pcaps/ists/snort.sample.142574.pcap':

      43689.975427      task-clock (msec)         #    1.470 CPUs utilized          
            20,138      context-switches          #    0.461 K/sec                  
               171      cpu-migrations            #    0.004 K/sec                  
           231,460      page-faults               #    0.005 M/sec                  
   129,790,681,545      cycles                    #    2.971 GHz                    
   219,021,005,746      instructions              #    1.69  insns per cycle        
    56,543,491,574      branches                  # 1294.198 M/sec                  
       214,892,514      branch-misses             #    0.38% of all branches        

      29.723236744 seconds time elapsed

AIEngine
********

.. code:: python

   rm = pyaiengine.RegexManager()
   r = pyaiengine.Regex("on the uri", "^.*(exe|png|bat).*$")
   rm.add_regex(r)

   h = pyaiengine.DomainName("domain_1" % i, "b.usemaxserver.de")
   h.callback = http_callback
   h.http_uri_regex_manager = rm
   dm.add_domain_name(h)
   ....

.. code:: bash

   Performance counter stats for 'python performance_test03.py':

       9541.147365      task-clock (msec)         #    1.000 CPUs utilized          
                23      context-switches          #    0.002 K/sec                  
                 1      cpu-migrations            #    0.000 K/sec                  
            33,139      page-faults               #    0.003 M/sec                  
    29,465,252,731      cycles                    #    3.088 GHz                    
    36,976,416,022      instructions              #    1.25  insns per cycle        
     7,407,104,528      branches                  #  776.333 M/sec                  
        61,182,769      branch-misses             #    0.83% of all branches        

       9.545122122 seconds time elapsed

Now to get the best of the engine, we load the same domains on SSL traffic for evaluate the impact. So 31000 HTTP domains and 31000 SSL domains in total

.. code:: python

   st.set_domain_name_manager(dm, "HTTPProtocol")
   st.set_domain_name_manager(dm, "SSLProtocol")

.. code:: bash

   Performance counter stats for 'python performance_test03.py':

       9274.894621      task-clock (msec)         #    1.000 CPUs utilized          
                16      context-switches          #    0.002 K/sec                  
                 1      cpu-migrations            #    0.000 K/sec                  
            33,133      page-faults               #    0.004 M/sec                  
    29,522,783,298      cycles                    #    3.183 GHz                    
    36,991,425,763      instructions              #    1.25  insns per cycle        
     7,410,694,570      branches                  #  799.006 M/sec                  
        60,993,249      branch-misses             #    0.82% of all branches        

       9.276745373 seconds time elapsed


And another example by dumping the network flows into a file

.. code:: python

    d = datamng.databaseFileAdaptor("network_data.txt")

    st.set_tcp_database_adaptor(d, 32)

.. code:: bash

   Performance counter stats for 'python performance_test03.py':

      16746.828783      task-clock (msec)         #    1.000 CPUs utilized          
                49      context-switches          #    0.003 K/sec                  
                 1      cpu-migrations            #    0.000 K/sec                  
            33,105      page-faults               #    0.002 M/sec                  
    54,966,465,432      cycles                    #    3.282 GHz                    
    81,610,222,371      instructions              #    1.48  insns per cycle        
    17,235,263,248      branches                  # 1029.166 M/sec                  
       130,365,974      branch-misses             #    0.76% of all branches        

      16.752885421 seconds time elapsed

+-------------+----------+--------------+---------+
| Test        | Cycles   | Instructions | Seconds |
+=============+==========+==============+=========+
| Snort       | 589.679M |     247.581M |      27 |
+-------------+----------+--------------+---------+
| Suricata(9) | 175.477M |     221.833M |      24 |
+-------------+----------+--------------+---------+
| Suricata(1) | 129.790M |     219.021M |      29 |
+-------------+----------+--------------+---------+
| AIEngine    |  54.966M |      81.610M |      16 |
+-------------+----------+--------------+---------+

Test III
........

In this section we are going to perform the thrid pcap (https://www.unsw.adfa.edu.au/australian-centre-for-cyber-security/cybersecurity/ADFA-NB15-Datasets/)


Test III processing traffic
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Same principal as the previous test, execute the engines without any rules or logic on them.

Snort
*****

.. code:: bash

   Performance counter stats for './snort -c snort.conf -r /pcaps/unsw-nb15/data01to20.pcap':

      86914.808990      task-clock (msec)         #    0.910 CPUs utilized          
           138,275      context-switches          #    0.002 M/sec                  
               948      cpu-migrations            #    0.011 K/sec                  
            50,099      page-faults               #    0.576 K/sec                  
   251,636,428,273      cycles                    #    2.895 GHz                    
   453,613,730,484      instructions              #    1.80  insns per cycle        
   100,704,302,271      branches                  # 1158.655 M/sec                  
       558,476,468      branch-misses             #    0.55% of all branches        

      95.525008126 seconds time elapsed

Tshark
******

.. code:: bash

   Performance counter stats for 'tshark -q -z conv,tcp -r /pcaps/unsw-nb15/data01to20.pcap':

     333695.156327      task-clock (msec)         #    0.635 CPUs utilized          
            50,639      context-switches          #    0.152 K/sec                  
             3,375      cpu-migrations            #    0.010 K/sec                  
         5,925,066      page-faults               #    0.018 M/sec                  
   834,885,153,185      cycles                    #    2.502 GHz                    
 1,149,108,548,848      instructions              #    1.38  insns per cycle        
   254,411,260,711      branches                  #  762.406 M/sec                  
     2,151,378,679      branch-misses             #    0.85% of all branches        

     525.370093087 seconds time elapsed

Suricata
********

With 9 packet processing threads

.. code:: bash

   Performance counter stats for './suricata -c suricata.yaml -r /pcaps/unsw-nb15/data1to20.pcap':

     261302.223836      task-clock (msec)         #    3.104 CPUs utilized          
         6,226,747      context-switches          #    0.024 M/sec                  
           486,951      cpu-migrations            #    0.002 M/sec                  
            63,481      page-faults               #    0.243 K/sec                  
   697,919,292,857      cycles                    #    2.671 GHz                    
   679,542,481,774      instructions              #    0.97  insns per cycle        
   151,611,147,001      branches                  #  580.214 M/sec                  
     1,064,511,496      branch-misses             #    0.70% of all branches        

      84.170028967 seconds time elapsed

With one packet processing thread

.. code:: bash

   Performance counter stats for './suricata --runmode single -c suricata.yaml -r /pcaps/unsw-nb15/data01to20.pcap':

     169075.961915      task-clock (msec)         #    1.861 CPUs utilized          
           226,609      context-switches          #    0.001 M/sec                  
             2,556      cpu-migrations            #    0.015 K/sec                  
            55,262      page-faults               #    0.327 K/sec                  
   473,344,813,449      cycles                    #    2.800 GHz                    
   675,553,561,487      instructions              #    1.43  insns per cycle        
   154,707,646,368      branches                  #  915.019 M/sec                  
       879,446,264      branch-misses             #    0.57% of all branches        

      90.857043914 seconds time elapsed

nDPI
****

.. code:: bash

   Performance counter stats for './ndpiReader -i /pcaps/unsw-nb15/data1to20.pcap':

      54898.789864      task-clock (msec)         #    0.689 CPUs utilized          
           277,922      context-switches          #    0.005 M/sec                  
             2,906      cpu-migrations            #    0.053 K/sec                  
           147,137      page-faults               #    0.003 M/sec                  
   147,861,571,481      cycles                    #    2.693 GHz                    
   202,546,036,266      instructions              #    1.37  insns per cycle        
    44,467,872,766      branches                  #  809.997 M/sec                  
       750,583,194      branch-misses             #    1.69% of all branches        

      79.635983617 seconds time elapsed

AIengine
********

.. code:: bash

   Performance counter stats for './aiengine -i /pcaps/unsw-nb15/data1to20.pcap -o':

      52889.291515      task-clock (msec)         #    0.682 CPUs utilized          
           291,859      context-switches          #    0.006 M/sec                  
               263      cpu-migrations            #    0.005 K/sec                  
             4,556      page-faults               #    0.086 K/sec                  
   152,091,301,283      cycles                    #    2.876 GHz                    
   187,198,842,035      instructions              #    1.23  insns per cycle        
    35,479,562,958      branches                  #  670.827 M/sec                  
       343,255,003      branch-misses             #    0.97% of all branches        

      77.588734066 seconds time elapsed

+-------------+----------+--------------+---------+
| Test        | Cycles   | Instructions | Seconds |
+=============+==========+==============+=========+
| Snort       | 251.636M |     453.613M |      95 |
+-------------+----------+--------------+---------+
| Tshark      | 834.885M |   1.149.108M |     525 |
+-------------+----------+--------------+---------+
| Suricata(9) | 697.919M |     679.542M |      84 |
+-------------+---------+--------------+---------+
| Suricata(1) | 473.344M |     675.553M |      90 |
+-------------+----------+--------------+---------+
| nDPI        | 147.861M |     202.546M |      79 |
+-------------+----------+--------------+---------+
| AIEngine    | 155.091M |     187.198M |      77 |
+-------------+----------+--------------+---------+

Tests III with rules
~~~~~~~~~~~~~~~~~~~~

The rule that we are going to use consists on find the string "cmd.exe" on the payload of all the TCP traffic.

Snort
*****

.. code:: bash

   alert tcp any any -> any any (content:"cmd.exe"; msg:"Traffic with cmd.exe on it"; sid:1)

.. code:: bash

   Performance counter stats for './snort -c snort.conf -r /pcaps/unsw-nb15/data01to20.pcap':

     225765.946500      task-clock (msec)         #    0.996 CPUs utilized          
             1,733      context-switches          #    0.008 K/sec                  
                48      cpu-migrations            #    0.000 K/sec                  
            54,278      page-faults               #    0.240 K/sec                  
   720,007,227,594      cycles                    #    3.189 GHz                    
 1,103,738,685,874      instructions              #    1.53  insns per cycle        
   196,606,934,485      branches                  #  870.844 M/sec                  
       601,970,985      branch-misses             #    0.31% of all branches        

     226.572212238 seconds time elapsed

Suricata
********

.. code:: bash

   alert tcp any any -> any any (content:"cmd.exe"; msg:"Traffic with cmd.exe on it"; sid:1; rev:1;)

.. code:: bash 

   Performance counter stats for './suricata -c suricata.yaml -r /pcaps/unsw-nb15/data01to20.pcap':

     301154.696413      task-clock (msec)         #    3.713 CPUs utilized          
         4,537,778      context-switches          #    0.015 M/sec                  
           320,272      cpu-migrations            #    0.001 M/sec                  
            66,368      page-faults               #    0.220 K/sec                  
   821,011,727,536      cycles                    #    2.726 GHz                    
   946,616,986,437      instructions              #    1.15  insns per cycle        
   188,989,561,337      branches                  #  627.550 M/sec                  
     1,055,852,141      branch-misses             #    0.56% of all branches        

      81.118712890 seconds time elapsed

With one packet processing thread

.. code:: bash

   Performance counter stats for './suricata --runmode single -c suricata.yaml -r /pcaps/unsw-nb15/data01to20.pcap':

     271875.785172      task-clock (msec)         #    1.912 CPUs utilized          
            95,803      context-switches          #    0.352 K/sec                  
             2,719      cpu-migrations            #    0.010 K/sec                  
            33,904      page-faults               #    0.125 K/sec                  
   759,157,543,157      cycles                    #    2.792 GHz                    
 1,086,339,439,951      instructions              #    1.43  insns per cycle        
   229,084,627,493      branches                  #  842.608 M/sec                  
       925,328,883      branch-misses             #    0.40% of all branches        

     142.179972062 seconds time elapsed

AIEngine
********

.. code:: bash

   Performance counter stats for './aiengine -R -r cmd.exe -c tcp -i /pcaps/unsw-nb15/data01to20.pcap':

      70282.239717      task-clock (msec)         #    0.883 CPUs utilized          
           241,942      context-switches          #    0.003 M/sec                  
               165      cpu-migrations            #    0.002 K/sec                  
             2,941      page-faults               #    0.042 K/sec                  
   216,254,447,090      cycles                    #    3.077 GHz                    
   444,858,853,163      instructions              #    2.06  insns per cycle        
   126,309,632,622      branches                  # 1797.177 M/sec                  
       621,357,247      branch-misses             #    0.49% of all branches        

      79.592005714 seconds time elapsed

+-------------+----------+--------------+---------+
| Test        | Cycles   | Instructions | Seconds |
+=============+==========+==============+=========+
| Snort       | 720.007M |   1.103.738M |     226 |
+-------------+----------+--------------+---------+
| Suricata(9) | 821.011M |     946.616M |      81 |
+-------------+----------+--------------+---------+
| Suricata(1) | 759.157M |   1.086.339M |     142 |
+-------------+----------+--------------+---------+
| AIEngine    | 216.254M |     444.858M |      79 |
+-------------+----------+--------------+---------+

Snort
*****

A simliar rules as before but just trying to help a bit to Snort, by using the port 80.

.. code:: bash

   alert tcp any any -> any 80 (content:"cmd.exe"; msg:"Traffic with cmd.exe on it"; sid:1; rev:1;)

.. code:: bash

   Performance counter stats for './snort -c snort.conf -r /pcaps/unsw-nb15/data01to20.pcap':

     233814.499892      task-clock (msec)         #    0.997 CPUs utilized          
             1,974      context-switches          #    0.008 K/sec                  
                71      cpu-migrations            #    0.000 K/sec                  
            75,258      page-faults               #    0.322 K/sec                  
   730,206,436,752      cycles                    #    3.123 GHz                    
 1,108,972,710,085      instructions              #    1.52  insns per cycle        
   197,990,370,123      branches                  #  846.784 M/sec                  
       621,729,625      branch-misses             #    0.31% of all branches        

     234.553089223 seconds time elapsed

Suricata
********

Change the rule just for HTTP traffic

.. code:: bash

   alert http any any -> any any (content:"cmd.exe"; msg:"Traffic with cmd.exe on it"; sid:1; rev:1;)

With 9 processing packet threads

.. code:: bash

   Performance counter stats for './suricata -c suricata.yaml -r /pcaps/unsw-nb15/data01to20.pcap':

     310949.557111      task-clock (msec)         #    3.654 CPUs utilized          
         4,369,460      context-switches          #    0.014 M/sec                  
           309,491      cpu-migrations            #    0.995 K/sec                  
           115,015      page-faults               #    0.370 K/sec                  
   842,934,924,156      cycles                    #    2.711 GHz                    
   936,673,438,149      instructions              #    1.11  insns per cycle        
   186,578,870,068      branches                  #  600.029 M/sec                  
     1,096,367,594      branch-misses             #    0.59% of all branches        

      85.099727468 seconds time elapsed

With one processing packet thread

.. code:: bash

   Performance counter stats for './suricata --runmode single -c suricata.yaml -r /pcaps/unsw-nb15/data01to20.pcap':

     262133.901169      task-clock (msec)         #    1.912 CPUs utilized          
            97,239      context-switches          #    0.371 K/sec                  
             2,250      cpu-migrations            #    0.009 K/sec                  
            35,933      page-faults               #    0.137 K/sec                  
   745,042,801,437      cycles                    #    2.842 GHz                    
   <not supported>      stalled-cycles-frontend  
   <not supported>      stalled-cycles-backend   
 1,086,466,669,012      instructions              #    1.46  insns per cycle        
   229,149,279,857      branches                  #  874.169 M/sec                  
       911,847,887      branch-misses             #    0.40% of all branches        

     137.131416050 seconds time elapsed

AIEngine
********

The python code used is the same as the previous examples

.. code:: bash

   Performance counter stats for 'python performance_test01.py':

      54503.714975      task-clock (msec)         #    0.697 CPUs utilized          
           288,082      context-switches          #    0.005 M/sec                  
               329      cpu-migrations            #    0.006 K/sec                  
             6,364      page-faults               #    0.117 K/sec                  
   154,966,196,568      cycles                    #    2.843 GHz                    
   192,969,592,655      instructions              #    1.25  insns per cycle        
    37,489,548,718      branches                  #  687.835 M/sec                  
       356,301,399      branch-misses             #    0.95% of all branches        

      78.240997629 seconds time elapsed

+-------------+----------+--------------+---------+
| Test        | Cycles   | Instructions | Seconds |
+=============+==========+==============+=========+
| Snort       | 730.206M |   1.108.972M |     234 |
+-------------+----------+--------------+---------+
| Suricata(9) | 842.934M |     936.673M |      85 |
+-------------+----------+--------------+---------+
| Suricata(1) | 745.042M |   1.086.466M |     137 |
+-------------+----------+--------------+---------+
| AIEngine    | 154.966M |     192.969M |      78 |
+-------------+----------+--------------+---------+

Tests III with 31.000 rules
~~~~~~~~~~~~~~~~~~~~~~~~~~~

On this section we evalute aproximatelly 31.000 rules in order to compare the different systems.
We will execute a complex rule directly instead of test a basic one as did on previous tests

Be aware that the portion of HTTP on this pcap is different and the rules generated are for HTTP traffic basically.

Snort
*****

.. code:: bash

   alert tcp any any -> any 80 (content:"example.int"; pcre:"/^.*(exe|bat|png).*$/"; msg:"Traffic"; sid:1; rev:1;) 
   alert tcp any any -> any 80 (content:"lb.usemaxserver.de"; pcre:"/^.*(exe|bat|png).*$/"; msg:"Traffic"; sid:1; rev:1;) 
   ...

.. code:: bash

   Run time for packet processing was 97.10530 seconds
   Snort processed 70040016 packets.
   Snort ran for 0 days 0 hours 1 minutes 37 seconds
      Pkts/min:     70040016
      Pkts/sec:       722062

   ...

   Performance counter stats for './snort -c snort.conf -r /pcaps/unsw-nb15/data01to20.pcap':

     275602.707391      task-clock (msec)         #    0.977 CPUs utilized          
           122,205      context-switches          #    0.443 K/sec                  
               725      cpu-migrations            #    0.003 K/sec                  
           291,329      page-faults               #    0.001 M/sec                  
   806,000,523,786      cycles                    #    2.925 GHz                    
   607,657,647,258      instructions              #    0.75  insns per cycle        
   155,667,282,082      branches                  #  564.825 M/sec                  
       746,781,332      branch-misses             #    0.48% of all branches        

     281.992266096 seconds time elapsed

Suricata
********

.. code:: bash

   alert http any any -> any any (content:"example.int"; http_host; pcre:"/^.*(exe|bat|png).*$/"; msg:"Traffic"; sid:1; rev:1;)
   alert http any any -> any any (content:"lb.usemaxserver.de"; http_host; pcre:"/^.*(exe|bat|png).*$/"; msg:"Traffic"; sid:1; rev:1;)
   ...

With 9 processing packet threads

.. code:: bash

   Performance counter stats for './suricata -c suricata.yaml -r /pcaps/unsw-nb15/data01to20.pcap':

     289051.124529      task-clock (msec)         #    3.087 CPUs utilized          
         5,586,755      context-switches          #    0.019 M/sec                  
           405,829      cpu-migrations            #    0.001 M/sec                  
           262,568      page-faults               #    0.908 K/sec                  
   782,934,326,025      cycles                    #    2.709 GHz                    
   780,343,745,230      instructions              #    1.00  insns per cycle        
   181,493,507,222      branches                  #  627.894 M/sec                  
     1,109,012,398      branch-misses             #    0.61% of all branches        

      93.628073324 seconds time elapsed

Running suricata with one single thread

.. code:: bash

   Performance counter stats for './suricata --runmode single -c suricata.yaml -r /pcaps/unsw-nb15/data01to20.pcap':

     217371.464104      task-clock (msec)         #    1.844 CPUs utilized          
           142,173      context-switches          #    0.654 K/sec                  
             3,610      cpu-migrations            #    0.017 K/sec                  
           279,174      page-faults               #    0.001 M/sec                  
   605,693,480,167      cycles                    #    2.786 GHz                    
   822,772,075,520      instructions              #    1.36  insns per cycle        
   196,748,336,538      branches                  #  905.125 M/sec                  
       942,204,205      branch-misses             #    0.48% of all branches        

     117.861947290 seconds time elapsed

AIEngine
********

.. code:: python

   rm = pyaiengine.RegexManager()
   r = pyaiengine.Regex("on the uri", "^.*(exe|png|bat).*$")
   rm.add_regex(r)

   h = pyaiengine.DomainName("domain_0", ".example.int")
   h.callback = http_callback
   h.http_uri_regex_manager = rm
   dm.add_domain_name(h)
   ....

.. code:: bash

   Performance counter stats for 'python performance_test04_a.py':

      55188.986532      task-clock (msec)         #    0.706 CPUs utilized          
           286,183      context-switches          #    0.005 M/sec                  
               238      cpu-migrations            #    0.004 K/sec                  
            13,190      page-faults               #    0.239 K/sec                  
   157,284,750,539      cycles                    #    2.850 GHz                    
   195,485,944,354      instructions              #    1.24  insns per cycle        
    37,960,887,891      branches                  #  687.834 M/sec                  
       358,573,222      branch-misses             #    0.94% of all branches        

      78.148122032 seconds time elapsed

+-------------+----------+--------------+---------+
| Test        | Cycles   | Instructions | Seconds |
+=============+==========+==============+=========+
| Snort       | 806.000M |     607.657M |     281 |
+-------------+----------+--------------+---------+
| Suricata(9) | 782.934M |     780.343M |      93 |
+-------------+----------+--------------+---------+
| Suricata(1) | 605.693M |     822.772M |     117 |
+-------------+----------+--------------+---------+
| AIEngine    | 157.284M |     195.485M |      78 |
+-------------+----------+--------------+---------+

Conclusions
...........

 - Not all the engines evaluated on these tests have the same functionality.
 - The traffic distribution have a big impact on the performance.
 - AIEngine shows a better performance in general with the given pcaps also by calling python code.
