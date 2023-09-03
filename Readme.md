## IPfix packet decoder for Inline Jflow

This is a simple tool to decode IPFix flow packets. This is for functionality tests of juniper inline jflow 

### Config needed on Junos
```
set groups JFLOW chassis fpc 0 sampling-instance SAMPLE-1
set groups JFLOW services flow-monitoring version-ipfix template IPFIX_V4 flow-active-timeout 30
set groups JFLOW services flow-monitoring version-ipfix template IPFIX_V4 flow-inactive-timeout 40
set groups JFLOW services flow-monitoring version-ipfix template IPFIX_V4 template-id 1024
set groups JFLOW services flow-monitoring version-ipfix template IPFIX_V4 nexthop-learning enable
set groups JFLOW services flow-monitoring version-ipfix template IPFIX_V4 template-refresh-rate packets 1
set groups JFLOW services flow-monitoring version-ipfix template IPFIX_V4 template-refresh-rate seconds 10
set groups JFLOW services flow-monitoring version-ipfix template IPFIX_V4 ipv4-template
set groups JFLOW forwarding-options sampling instance SAMPLE-1 input rate 10
set groups JFLOW forwarding-options sampling instance SAMPLE-1 family inet output flow-server 50.1.1.1 port 2055
set groups JFLOW forwarding-options sampling instance SAMPLE-1 family inet output flow-server 50.1.1.1 version-ipfix template IPFIX_V4
set groups JFLOW forwarding-options sampling instance SAMPLE-1 family inet output inline-jflow source-address 50.1.1.254
set groups JFLOW forwarding-options sampling instance SAMPLE-1 family inet output inline-jflow flow-export-rate 1
set groups JFLOW firewall family inet filter FORWARD term 10 then sample
set apply-groups JFLOW
```

### Verification on Junos (MX/vMX)
This command only works on non AFT based devices
```
root@vmx1# run show services accounting flow inline-jflow fpc-slot 0
  Flow information
    FPC Slot: 0
    Flow Packets: 23, Flow Bytes: 1908
    Active Flows: 2, Total Flows: 10
    Flows Exported: 8, Flow Packets Exported: 8
    Flows Inactive Timed Out: 0, Flows Active Timed Out: 8
    Total Flow Insert Count: 2

    IPv4 Flows:
    IPv4 Flow Packets: 23, IPv4 Flow Bytes: 1908
    IPv4 Active Flows: 2, IPv4 Total Flows: 10
    IPv4 Flows Exported: 8, IPv4 Flow Packets exported: 8
    IPv4 Flows Inactive Timed Out: 0, IPv4 Flows Active Timed Out: 8
    IPv4 Flow Insert Count: 2
```

### Running the app

```
./ipfix-decoder -i eth2 -p 2055
```
