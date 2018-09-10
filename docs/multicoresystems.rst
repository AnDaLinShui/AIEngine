Multicore stacks
~~~~~~~~~~~~~~~~

Depending on the requirements of your system/network sometimes we need to replicate the stacks in order to cope the network requirements in terms of capacity or just to split the functionality that we want to implement.

This task is very easy because we just need to create a simple script that accept as parameter a network mask and then spawn the process.

.. code:: python

  if __name__ == '__main__':
   
      st = pyaiengine.StackLan()

      with pyaiengine.PacketDispatcher("re0") as pd:
          pd.stack = st
          pd.pcap_filter = "net 192.168.0.0/24"
          pd.run()


Of may be you prefer a solution with threads

.. code:: python

  from multiprocessing import Pool

  def network_thread (netmask):

      st = pyaiengine.StackLan()

      with pyaiengine.PacketDispatcher("re0") as pd:
          pd.stack = st
          pd.pcap_filter = mask
          pd.run()

  if __name__ == '__main__':

      networks = ("net 192.169.0.0/16","net 10.1.0.0/16","net 169.12.0.0/16")

      pool = Pool(len(networks))

      p = pool.map_async(network_thread, networks)

      try:
          results = p.get(0xFFFF) 
      except KeyboardInterrupt:
          print("Exiting stacks")

      pool.close()
      pool.join()
