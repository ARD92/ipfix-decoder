/*
Author: Aravind Prabhakar
Version: v1.0
Description: Simple ipfix packet decoder for functionality tests

Current supported templates: Ipv4
*/

package main

import (
	"encoding/hex"
	"fmt"
	"github.com/akamensky/argparse"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

// packet handling variables
var (
	snapshotLen int32 = 1024
	promiscuous bool  = false
	err         error
	timeout     time.Duration = 5 * time.Second
	handle      *pcap.Handle
	template    IpfixTempData
)

// Inline jflow Ipfix template data
type IpfixTempData struct {
	Timestamp     string
	ObservationId string
	Version       string
	FlowsetId     string
	Flowlen       string
	Length        string
	TemplateId    string
	FieldCount    string
	Flowseq       string
}

// Inline jflow data packet
type IpfixData struct {
	SourceIP          string
	DestIP            string
	Protocol          string
	IpTos             string
	SourcePort        string
	DestPort          string
	IcmpType          string
	InputSnmp         string
	SrcVlan           string
	SrcMask           string
	DstMask           string
	SrcAs             string
	DstAs             string
	IpNextHop         string
	TcpFlags          string
	OutSnmp           string
	IpTTLMin          string
	IpTTLMax          string
	FlowendReason     string
	IpVersion         string
	BGPNextHop        string
	Direction         string
	Dot1qVlanId       string
	Dot1qCustVlanId   string
	Ipv4Id            string
	Bytes             string
	Pkts              string
	FlowStartMilliSec string
	FlowEndMilliSec   string
}

// outer IP
type Ipv4Flow struct {
	Srcmac   net.HardwareAddr
	Dstmac   net.HardwareAddr
	SrcIp    net.IP
	DstIp    net.IP
	SrcPort  layers.UDPPort
	DstPort  layers.UDPPort
	Protocol layers.IPProtocol
}

// Parse IPv4 bytes and return string value in dotted decimal
func parseIpv4Bytes(input []byte) string {
	var val [4]string
	for i := 0; i < len(input); i++ {
		hexval := hex.EncodeToString(input[i : i+1])
		dval, _ := strconv.ParseInt(hexval, 16, 64)
		val[i] = strconv.FormatInt(dval, 10)
	}
	return val[0] + "." + val[1] + "." + val[2] + "." + val[3]
}

// Decode port bytes and return an int64 value
func parsePortBytes(input []byte) int64 {
	hexval := hex.EncodeToString(input)
	dval, _ := strconv.ParseInt(hexval, 16, 64)
	return dval
}

// Decode IPv4 pkt
func decodeIpv4(payload []byte) (gopacket.Packet, Ipv4Flow) {
	var v4flow Ipv4Flow
	packet := gopacket.NewPacket(payload, layers.LayerTypeEthernet, gopacket.Default)
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		v4flow.Srcmac = eth.SrcMAC
		v4flow.Dstmac = eth.DstMAC
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ipacket, _ := ipLayer.(*layers.IPv4)
		v4flow.SrcIp = ipacket.SrcIP
		v4flow.DstIp = ipacket.DstIP
		v4flow.Protocol = ipacket.Protocol
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		v4flow.SrcPort = udp.SrcPort
		v4flow.DstPort = udp.DstPort
	}
	return packet, v4flow
}

// Decode IPfix packet
func decodeIpfix(payload []byte) {
	var iflow IpfixData
	iFixVersion := payload[0:2]
	if hex.EncodeToString(iFixVersion) == "000a" {
		log.Println("Decoding IPFIX packet...")
		//fmt.Println(hex.EncodeToString(payload))
		iFixFlowSetId := hex.EncodeToString(payload[16:18])
		//fmt.Println(iFixFlowSetId)
		if iFixFlowSetId == "0002" {
			log.Println(" received template packet ....\n")
			fmt.Println(" received template packet ....\n")
			template.Version = hex.EncodeToString(iFixVersion)
			template.Length = hex.EncodeToString(payload[2:4])
			template.Timestamp = hex.EncodeToString(payload[4:8])
			template.Flowseq = hex.EncodeToString(payload[8:12])
			template.ObservationId = hex.EncodeToString(payload[12:16])
			template.FlowsetId = hex.EncodeToString(payload[16:18])
			template.Flowlen = hex.EncodeToString(payload[18:20])
			template.TemplateId = hex.EncodeToString(payload[20:22])
			template.FieldCount = hex.EncodeToString(payload[22:24])
			log.Println("template hex bytes: ", template)
		} else if iFixFlowSetId == template.TemplateId {
			log.Println("Decoding inline jflow flow packet... \n")
			fmt.Println(iFixFlowSetId)
			fmt.Println(payload)
			iflow.SourceIP = hex.EncodeToString(payload[24:28])
			iflow.DestIP = hex.EncodeToString(payload[28:32])
			iflow.IpTos = hex.EncodeToString(payload[32:36])
			iflow.Protocol = hex.EncodeToString(payload[36:40])
			iflow.SourcePort = hex.EncodeToString(payload[40:44])
			iflow.DestPort = hex.EncodeToString(payload[44:48])
			iflow.IcmpType = hex.EncodeToString(payload[48:52])
			iflow.InputSnmp = hex.EncodeToString(payload[52:56])
			iflow.SrcVlan = hex.EncodeToString(payload[56:60])
			iflow.SrcMask = hex.EncodeToString(payload[60:64])
			iflow.DstMask = hex.EncodeToString(payload[64:68])
			iflow.SrcAs = hex.EncodeToString(payload[68:72])
			iflow.SrcAs = hex.EncodeToString(payload[72:76])
			iflow.IpNextHop = hex.EncodeToString(payload[76:80])
			iflow.TcpFlags = hex.EncodeToString(payload[80:84])
			iflow.OutSnmp = hex.EncodeToString(payload[84:88])
			iflow.IpTTLMin = hex.EncodeToString(payload[88:92])
			iflow.IpTTLMax = hex.EncodeToString(payload[92:96])
			iflow.FlowendReason = hex.EncodeToString(payload[96:100])
			iflow.IpVersion = hex.EncodeToString(payload[100:104])
			iflow.BGPNextHop = hex.EncodeToString(payload[104:108])
			iflow.Direction = hex.EncodeToString(payload[108:112])
			iflow.Dot1qVlanId = hex.EncodeToString(payload[112:116])
			iflow.Dot1qCustVlanId = hex.EncodeToString(payload[116:120])
			iflow.Ipv4Id = hex.EncodeToString(payload[120:124])
			iflow.Bytes = hex.EncodeToString(payload[124:128])
			iflow.Pkts = hex.EncodeToString(payload[128:132])
			iflow.FlowStartMilliSec = hex.EncodeToString(payload[132:136])
			iflow.FlowEndMilliSec = hex.EncodeToString(payload[136:140])
			log.Println("flow data hexbytes: ", iflow)
			fmt.Println("======== Flow data ============\n")
			fmt.Println(iflow)
		} else {
			fmt.Println("Unable to decode Ipfix Packet... \n")
			fmt.Println(iFixFlowSetId)
			fmt.Println(payload)
			log.Println("Unable to decode Ipfix Packet... \n")
		}
	} else {
		log.Println("Not an IPFIX packet ... \n")
		fmt.Println("Not an IPFIX packet ... \n")
	}
}

// Decode incoming IP pkt
func decodePacket(packet gopacket.Packet) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	var uDestPort layers.UDPPort
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		uDestPort = udp.DstPort
	}
	if uDestPort == 2055 {
		log.Println("received ipfix packet...")
		appLayer := packet.ApplicationLayer()
		if appLayer != nil {
			payload := appLayer.Payload()
			decodeIpfix(payload)
		}
	}
}

func main() {
	logs, logerr := os.OpenFile("ipfix-decoder.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if logerr != nil {
		log.Fatalf("Error opening file: %v", logerr)
	}
	defer logs.Close()
	log.SetOutput(logs)
	parser := argparse.NewParser("Required-args", "\n============\nimon-ipfix-decoder\n============")
	device := parser.String("i", "intf", &argparse.Options{Required: true, Help: "interface to bind to "})
	//cport := parser.String("p", "port", &argparse.Options{Required: true, Help: "port number over which ipfix packets arrive "})
	//port, _  := strconv.Atoi(*cport)

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	} else {
		handle, err = pcap.OpenLive(*device, snapshotLen, promiscuous, timeout)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			go decodePacket(packet)
		}
	}
}
