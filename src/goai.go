package main

import "./goaiengine"
import "fmt"
import "testing"

func assert(t *testing.T, exp, got interface{}, equal bool) {
        t.Fatalf("Expecting '%v' got '%v'\n", exp, got)
}

func setupLan() (goaiengine.StackLan, goaiengine.PacketDispatcher) {

    s := goaiengine.NewStackLan()
    p := goaiengine.NewPacketDispatcher()

    p.SetStack(s)

    s.SetTotalTCPFlows(1024)
    s.SetTotalUDPFlows(512)

    return s, p
}

func setupMobile() (goaiengine.StackMobile, goaiengine.PacketDispatcher) {

    s := goaiengine.NewStackMobile()
    p := goaiengine.NewPacketDispatcher()

    p.SetStack(s)

    s.SetTotalTCPFlows(1024)
    s.SetTotalUDPFlows(512)

    return s, p
}

func setupLan6() (goaiengine.StackLanIPv6, goaiengine.PacketDispatcher) {

    s := goaiengine.NewStackLanIPv6()
    p := goaiengine.NewPacketDispatcher()

    p.SetStack(s)

    s.SetTotalTCPFlows(1024)
    s.SetTotalUDPFlows(512)

    return s, p
}

func setupVirtual() (goaiengine.StackVirtual, goaiengine.PacketDispatcher) {

    s := goaiengine.NewStackVirtual()
    p := goaiengine.NewPacketDispatcher()

    p.SetStack(s)

    s.SetTotalTCPFlows(1024)
    s.SetTotalUDPFlows(512)

    return s, p
}

func setupOpenFlow() (goaiengine.StackOpenFlow, goaiengine.PacketDispatcher) {

    s := goaiengine.NewStackOpenFlow()
    p := goaiengine.NewPacketDispatcher()

    p.SetStack(s)

    s.SetTotalTCPFlows(1024)
    s.SetTotalUDPFlows(512)

    return s, p
}

func setupMobile6() (goaiengine.StackMobileIPv6, goaiengine.PacketDispatcher) {

    s := goaiengine.NewStackMobileIPv6()
    p := goaiengine.NewPacketDispatcher()

    p.SetStack(s)

    s.SetTotalTCPFlows(1024)
    s.SetTotalUDPFlows(512)

    return s, p
}

func ExampleLan01() {
    // Basic example for processing a pcap file and shows the output
    s, p := setupLan()

    p.Open("../pcapfiles/flow_vlan_netbios.pcap")
    p.Run()
    p.Close()

    p.Statistics()
    s.ShowProtocolSummary()
}

func ExampleLan02() {
    // Basic example for processing a pcap file and use regex expressions 
    // Similar test case as test03 on pyai_test.py
    s, p := setupLan()

    s.EnableLinkLayerTagging("vlan")

    rm := goaiengine.NewRegexManager()
    r := goaiengine.NewRegex("netbios", "CACACACA")
    rm.AddRegex(r)
    
    s.SetUDPRegexManager(rm)
    s.EnableNIDSEngine(true)

    p.Open("../pcapfiles/flow_vlan_netbios.pcap")
    p.Run()
    p.Close()

    rm.Statistics()
}

type CallbackSSL struct{}

func (p *CallbackSSL) Call(f goaiengine.Flow) {
    fmt.Println("SSLFlow:", f.GetSrcAddrDotNotation(), f.GetSourcePort(), f.GetDstAddrDotNotation(), f.GetDestinationPort())
    // Output: golly
    s := f.GetSSLInfoObject()
    if (s != nil) {
	fmt.Println("SSL Serve Name", s.GetServerName())
    }
}

func ExampleLan03() {

    // Basic example for processing a pcap file and use domains
    // Similar test case as test06 on pyai_test.py
    s, p := setupLan()

    dm := goaiengine.NewDomainNameManager()
    d := goaiengine.NewDomainName("Glasses", ".drive.google.com")
    dm.AddDomainName(d)

    cb := goaiengine.NewDirectorGoaiCallback(&CallbackSSL{})
    d.SetCallback(cb)
    s.SetDomainNameManager(dm, "SSLProtocol")

    p.Open("../pcapfiles/sslflow.pcap")
    p.Run()
    p.Close()

    dm.Statistics()
}

type CallbackHTTP struct{}

func (p *CallbackHTTP) Call(f goaiengine.Flow) {
    fmt.Println("HTTPFlow:", f.GetSrcAddrDotNotation(), f.GetSourcePort(), f.GetDstAddrDotNotation(), f.GetDestinationPort())
    h := f.GetHTTPInfoObject()
    if (h != nil) {
	fmt.Println("HTTP Host Name", h.GetHostName())
    }
}

type CallbackHTTPUri struct{}

func (p *CallbackHTTPUri) Call(f goaiengine.Flow) {
    fmt.Println("HTTPFlow:", f.GetSrcAddrDotNotation(), f.GetSourcePort(), f.GetDstAddrDotNotation(), f.GetDestinationPort())
    h := f.GetHTTPInfoObject()
    if (h != nil) {
	fmt.Println("HTTP Uri", h.GetUri())
    }
}

func ExampleLan04() {

    // Similar as test22 on pyai_test.py
    // Verify the functionality of the HTTPUriSets with the callbacks 
    s, p := setupLan()

    uset := goaiengine.NewHTTPUriSet()

    cb_uri := goaiengine.NewDirectorGoaiCallback(&CallbackHTTPUri{})
    uset.AddURI("/js/scrolldock/scrolldock.css?v=20121120a")
    uset.SetCallback(cb_uri)

    d := goaiengine.NewDomainName("Wired domain", ".wired.com")

    dm := goaiengine.NewDomainNameManager()
    cb_http := goaiengine.NewDirectorGoaiCallback(&CallbackHTTP{})
    d.SetCallback(cb_http)
    dm.AddDomainName(d)

    // connect the uriset to the domain
    d.SetHTTPUriSet(uset)

    s.SetDomainNameManager(dm, "HTTPProtocol")

    p.Open("../pcapfiles/two_http_flows_noending.pcap")
    p.Run()
    p.Close()

    dm.Statistics()
}


func ExampleLan05() {

    // By setting the timeout to 1 sec we should see the insert, update and remove
    // messages of the DatabaseAdaptor
    s, p := setupLan()

    s.SetFlowsTimeout(1) 

    db := goaiengine.NewDirectorDatabaseAdaptor(&DatabaseAdaptorExample{})

    s.SetUDPDatabaseAdaptor(db, 16)

    s.EnableLinkLayerTagging("vlan")

    p.Open("../pcapfiles/flow_vlan_netbios.pcap")
    p.Run()
    p.Close()
    
    cc := s.GetCounters("UDP")
    fmt.Println("Total UDP Bytes ", cc.Get("bytes"), " packets ", cc.Get("packets"))
}

type CallbackRegex struct{}

func (p *CallbackRegex) Call(f goaiengine.Flow) {
    fmt.Println("Flow:", f.GetSrcAddrDotNotation(), f.GetSourcePort(), f.GetDstAddrDotNotation(), f.GetDestinationPort())
    s := f.GetRegex()
    if (s != nil) {
        fmt.Println("Regex Name", s.GetName())
    }
}

func ExampleMobile01() {

    // Basic example with a regex expression
    s, p := setupMobile()

    rm := goaiengine.NewRegexManager()
    r := goaiengine.NewRegex("Example", "BRap")
    rm.AddRegex(r)
    
    cb := goaiengine.NewDirectorGoaiCallback(&CallbackRegex{})
    r.SetCallback(cb)

    s.SetTCPRegexManager(rm)

    p.Open("../pcapfiles/gprs_ftp.pcap")
    p.Run()
    p.Close()

    rm.Statistics()
    s.ShowProtocolSummary()
}

type CallbackDNS struct{}

func (p *CallbackDNS) Call(f goaiengine.Flow) {
    fmt.Println("Flow:", f.GetSrcAddrDotNotation(), f.GetSourcePort(), f.GetDstAddrDotNotation(), f.GetDestinationPort())
    d := f.GetDNSInfoObject()
    if (d != nil) {
        fmt.Println("Domain Name", d.GetDomainName())
    }
}

func ExampleLanIPv601() {
    // Similar functionality with test07 
    s, p := setupLan6()

    dm := goaiengine.NewDomainNameManager()
    d := goaiengine.NewDomainName("Google test domain", ".google.com")
    dm.AddDomainName(d)

    cb := goaiengine.NewDirectorGoaiCallback(&CallbackDNS{})
    d.SetCallback(cb)

    s.SetDomainNameManager(dm, "DNS")

    p.Open("../pcapfiles/ipv6_google_dns.pcap")
    p.Run()
    p.Close()

    dm.Statistics()
    s.ShowProtocolSummary()
   
    // How to get counter information 
    cc := s.GetCounters("DNS")
    fmt.Println("Total allow queries", cc.Get("allow queries"))
    fmt.Println("Total banned queries", cc.Get("banned queries"))
    fmt.Println("Total queries", cc.Get("queries"))
    fmt.Println("Total responses", cc.Get("responses"))
}

type DatabaseAdaptorExample struct{}

func (p *DatabaseAdaptorExample) Insert(key string) {
    fmt.Println("Flow insert:", key)
}
func (p *DatabaseAdaptorExample) Update(key string, data string) {
    fmt.Println("Flow update:", key, data)
}
func (p *DatabaseAdaptorExample) Remove(key string) {
    fmt.Println("Flow remove:", key)
}

func ExampleLanIPv602() {
    // Similar functionality with test05
    s, p := setupLan6()

    db := goaiengine.NewDirectorDatabaseAdaptor(&DatabaseAdaptorExample{})

    s.SetUDPDatabaseAdaptor(db, 16)

    p.Open("../pcapfiles/ipv6_google_dns.pcap")
    p.Run()
    p.Close()

    s.ShowProtocolSummary()
}

type CallbackIPSet struct{}

func (p *CallbackIPSet) Call(f goaiengine.Flow) {
    fmt.Println("Flow:", f.GetSrcAddrDotNotation(), f.GetSourcePort(), f.GetDstAddrDotNotation(), f.GetDestinationPort())
}

func ExampleLanIPv603() {
    // Similar functionality with test03
    s, p := setupLan6()

    i := goaiengine.NewIPSet()
    i.AddIPAddress("dc20:c7f:2012:11::2")

    cb := goaiengine.NewDirectorGoaiCallback(&CallbackIPSet{})
    i.SetCallback(cb)

    ip := goaiengine.NewIPSetManager()
    ip.AddIPSet(i)

    s.SetTCPIPSetManager(ip)

    p.Open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")
    p.Run()
    p.Close()

    ip.Statistics()
}

func ExampleVirtual01() {
    // Basic example for processing a pcap file and shows the output
    s, p := setupVirtual()

    rm := goaiengine.NewRegexManager()
    r := goaiengine.NewRegex("Bin directory", "^SSH-2.0.*$")
    rm.AddRegex(r)

    s.SetTCPRegexManager(rm)

    p.Open("../pcapfiles/gre_ssh.pcap")
    p.Run()
    p.Close()

    rm.Statistics()
}

type CallbackLabel struct{}

func (p *CallbackLabel) Call(f goaiengine.Flow) {
    fmt.Println("Flow:", f.GetSrcAddrDotNotation(), f.GetSourcePort(), f.GetDstAddrDotNotation(), f.GetDestinationPort())
    f.SetLabel("Some lovely label")
}

func ExampleOpenFlow01() {
    // Use a regular expression and a DatabaseAdaptor
    s, p := setupOpenFlow()

    rm := goaiengine.NewRegexManager()
    r := goaiengine.NewRegex("Bin directory", "^\x26\x01.*$")
    rm.AddRegex(r)

    cb := goaiengine.NewDirectorGoaiCallback(&CallbackLabel{})
    r.SetCallback(cb)

    s.SetTCPRegexManager(rm)

    db := goaiengine.NewDirectorDatabaseAdaptor(&DatabaseAdaptorExample{})
    s.SetTCPDatabaseAdaptor(db, 1)

    p.Open("../pcapfiles/openflow.pcap")
    p.Run()
    p.Close()

    cc := s.GetCounters("TCPProtocol")
    fmt.Println("Total TCP bytes ", cc.Get("bytes"), " packets ", cc.Get("packets"))
}

func ExampleOpenFlow02() {

    s, p := setupOpenFlow()

    d := goaiengine.NewDomainName("Test domain", ".ubuntu.com")
    cb := goaiengine.NewDirectorGoaiCallback(&CallbackDNS{})
    d.SetCallback(cb)

    db := goaiengine.NewDirectorDatabaseAdaptor(&DatabaseAdaptorExample{})
    s.SetUDPDatabaseAdaptor(db, 1)

    dm := goaiengine.NewDomainNameManager()
    dm.AddDomainName(d)

    s.SetDomainNameManager(dm, "dns")

    p.Open("../pcapfiles/openflow_dns.pcap")
    p.Run()
    p.Close()
}

func ExampleMobileIPv601() {
    // Basic example for processing a pcap file and shows the output
    s, p := setupMobile6()

    rm := goaiengine.NewRegexManager()
    r := goaiengine.NewRegex("Something", "^REGISTER")
    rm.AddRegex(r)

    s.SetTCPRegexManager(rm)

    p.Open("../pcapfiles/gprs_ip6_tcp.pcap")
    p.Run()
    p.Close()

    rm.Statistics()
}

func main() {
    fmt.Println("Starting goaiengine examples")
    ExampleLan01()
    ExampleLan02()
    ExampleLan03()
    ExampleLan04()
    ExampleLan05()
    ExampleMobile01()
    ExampleLanIPv601()
    ExampleLanIPv602()
    ExampleLanIPv603()
    ExampleVirtual01()
    ExampleOpenFlow01()
    ExampleOpenFlow02()
    ExampleMobileIPv601()
}
