Database integration
~~~~~~~~~~~~~~~~~~~~

One of the main functions of the engine is the easy integration with databases. 

The interface is very easy, you just need to write a class with three methods on it.

- insert: This method is used for new TCP/UDP connections.
- update: This method will be called when a detection have been carrie out or every N packets.
- remove: This method is used when the network flow is timeout or finish. 

Lets see some examples of how works the database interface.

If you develop an adaptor that could be usefull just let me know and I will add it.

Python database adaptor for write the information on files:

.. code:: python

  class fileAdaptor (DatabaseAdaptor):
      def __init__(self, name):
          self.__f = open(name,"w")

      def __del__(self):
          self.__f.close()

      def update(self, key, data):
          self.__f.write("Update:[%s] %s\n" % (key, data))

      def insert(self, key):
        return

      def remove(self, key):
        return

Ruby database adaptor integrated with Redis:

.. code:: ruby

  class RedisAdaptor < DatabaseAdaptor 
    attr_reader :ftype

    def initialize(ftype)
      @ftype = ftype
      @conn = Redis.new
    end

    def insert(key)
      @conn.hset(@ftype, key, "{}")
    end

    def remove(key)
      @conn.hdel(@ftype, key)
    end

    def update(key, data)
      @conn.hset(@ftype, key, data)
    end
  end

Python database adaptor integrated with Redis:

.. code:: python

    import redis

    class redisAdaptor(pyaiengine.DatabaseAdaptor):
        def __init__(self):
            self.__r = None 

        def connect(self,connection_str):
            self.__r = redis.Redis(connection_str)      

        def update(self, key, data):
            self.__r.hset("udpflows", key, data)
    
        def insert(self, key):
            self.__r.hset("udpflows", key, "{}")

        def remove(self, key):
            self.__r.hdel("udpflows", key)


Cassandra Python adaptor.

.. code:: python

    import pycassa
    import json

    class cassandraAdaptor(pyaiengine.DatabaseAdaptor):
        """ This class inheritance of DatabaseAdaptor that contains
            the following methods:
            - insert, called on the first insertion of the network flow
            - update, called depending on the sample selected.
            - remove, called when the flow is destroy.
        """
        def __init__(self):
            self.__c = None
            self.__pool = None

        def connect(self, connection_str):
            self.__pool = pycassa.ConnectionPool(keyspace='demo', server_list=['127.0.0.1:9160'], prefill=False)
            self.__c = pycassa.ColumnFamily(self.__pool, 'flows')

        def update(self, key, data):
            obj = json.loads(data)

            bytes = obj["bytes"]
            l7 = obj["layer7"]
            l7info = obj.get("httphost", 0)
            if (l7info == 0):
                l7info = obj.get("sslphost", 0)
                if ( l7info > 0):
                    d["layer7info"] = l7info
            else:
                d["layer7info"] = l7info

            # Create a dict with all the values of the cassandra table
            d = {'bytes':bytes, 'layer7':l7}

            self.__c.insert(key, d)

        def insert(self, key):
            self.__c.insert(key, {'bytes':0})

        def remove(self, key):
            # We dont remove anything on this example
            pass

Python Hadoop with the PyTables(https://pytables.github.io/) interface.

.. code:: python

    import pyaiengine
    import tables 
    import json

    class hadoopFlow(tables.IsDescription):
        name = tables.StringCol(50, pos = 1)
        bytes = tables.Int32Col(pos = 2)
        l7 = tables.StringCol(32, pos = 3)
        layer7info = tables.StringCol(64, pos = 4)

    class hadoopAdaptor(pyaiengine.DatabaseAdaptor):
        def __init__(self):
            self.__file = None 
            self.__group = None
            self.__table = None

        def connect(self,connection_str):
            self.__file = tables.open_file(connection_str, mode="w")
            self.__group = self.__file.create_group(self.__file.root, "flows")
            self.__table_tcp = self.__file.create_table(self.__group, 'table_tcp', hadoopFlow, "Flow table",
            tables.Filters(0))
            self.__table_udp = self.__file.create_table(self.__group, 'table_udp', hadoopFlow, "Flow table",
            tables.Filters(0))

        def __handle_udp(self, key, obj):
            query = "name == b'%s'" % key
            for f in self.__table_udp.where(query):
                f['bytes'] = obj["bytes"]
                f['l7'] = obj["layer7"]
                l7info = obj.get("dnsdomain", 0)
                if (l7info > 0):
                    f['layer7info'] = l7info
   
                f.update()
    
        def update(self, key, data):
            try:
                obj = json.loads(data)   
            except:
                print "ERROR:", data
                return

            proto = int(key.split(":")[2])

            if (proto == 6):
                self.__handle_tcp(key, obj)
            else:
                self.__handle_udp(key, obj)
 
        def insert(self, key):
            proto = int(key.split(":")[2])

            if (proto == 6):
                t = self.__table_tcp
            else:
                t = self.__table_udp
 
            f = t.row

            f['name'] = key
            f['bytes'] = 0
            f.append()
            t.flush()

        def remove(self, key):
            # We dont remove anything on this example 
            pass

Python adaptor with integration with ElasticSearch engine and GeoIP:

.. code:: python

  class elasticSearchAdaptor (pyaiengine.DatabaseAdaptor):
      def __init__(self, name):
          self.__es = Elasticsearch()
          self.__gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
          self.__rep = ipReputationService()
          self.__name = name

    def __del__(self):
        pass

    def update(self, key, data):
        """ In this example we enrich the data by using thrid party services """
        d = json.loads(data)
        d["timestamp"] = datetime.now()
        ipdst = key.split(":")[3]

        """ Make a geoIP for get the country """
        country = self.__gi.country_name_by_addr(ipsrc)
        d["country"] = country

        """ Make a reputation of the IP """
        d["reputation"] = self.__rep.ip_reputation(ipdst)

        self.__es.index(index=self.__name, doc_type="networkdata", id=ipdst, body=d)

    def insert(self, key):
        pass

    def remove(self, key):
        pass

We create a new instance of a LAN network on the main

.. code:: python

    st = pyaiengine.StackLan()

Allocate the maximum number of UDP flows on the system

.. code:: python

    st.udp_flows = 163840

Create a new instance of the DatabaseAdaptor and plug it to the UDP part of the engine, so only UDP traffic will be process.

.. code:: python
       
    # Use your own adaptor (redisAdaptor, cassandraAdaptor, hadoopAdaptor)
    db = redisAdaptor()
    db.connect("localhost")

    """ The UDP traffic will be updated every 16 packets """ 
    st.set_udp_database_adaptor(db, 16)
     
Open the network device, attach the stack and let the engine run

.. code:: python
        
    with pyaiengine.PacketDispatcher("eth0") as pd:
        pd.stack = st 
        pd.run()

Now you can check the results on the redis/cassandra/hadoop database.
