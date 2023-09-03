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
	Protocol          int64
	IpTos             int64
	SourcePort        int64
	DestPort          int64
	IcmpType          int64
	InputSnmp         int64
	SrcVlan           int64
	SrcMask           int64
	DstMask           int64
	SrcAs             int64
	DstAs             int64
	IpNextHop         string
	TcpFlags          int64
	OutSnmp           int64
	IpTTLMin          int64
	IpTTLMax          int64
	FlowendReason     int64
	IpVersion         int64
	BGPNextHop        string
	Direction         int64
	Dot1qVlanId       int64
	Dot1qCustVlanId   int64
	Ipv4Id            int64
	Bytes             int64
	Pkts              int64
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
			fmt.Println("Decoding inline jflow flow packet... \n")
			fmt.Println(iFixFlowSetId)
			//fmt.Println(payload)
			iflow.SourceIP = parseIpv4Bytes(payload[20:24])
			iflow.DestIP = parseIpv4Bytes(payload[24:28])
			iflow.IpTos = parsePortBytes(payload[28:29])
			iflow.Protocol = parsePortBytes(payload[29:30])
			iflow.SourcePort = parsePortBytes(payload[30:32])
			iflow.DestPort = parsePortBytes(payload[32:34])
			iflow.IcmpType = parsePortBytes(payload[34:36])
			iflow.InputSnmp = parsePortBytes(payload[36:40])
			iflow.SrcVlan = parsePortBytes(payload[40:42])
			iflow.SrcMask = parsePortBytes(payload[42:43])
			iflow.DstMask = parsePortBytes(payload[43:44])
			iflow.SrcAs = parsePortBytes(payload[44:48])
			iflow.DstAs = parsePortBytes(payload[48:52])
			iflow.IpNextHop = parseIpv4Bytes(payload[52:56])
			iflow.TcpFlags = parsePortBytes(payload[56:57])
			iflow.OutSnmp = parsePortBytes(payload[57:61])
			iflow.IpTTLMin = parsePortBytes(payload[61:62])
			iflow.IpTTLMax = parsePortBytes(payload[62:63])
			iflow.FlowendReason = parsePortBytes(payload[63:64])
			iflow.IpVersion = parsePortBytes(payload[64:65])
			iflow.BGPNextHop = parseIpv4Bytes(payload[65:69])
			iflow.Direction = parsePortBytes(payload[69:70])
			iflow.Dot1qVlanId = parsePortBytes(payload[70:72])
			iflow.Dot1qCustVlanId = parsePortBytes(payload[72:74])
			iflow.Ipv4Id = parsePortBytes(payload[74:78])
			iflow.Bytes = parsePortBytes(payload[78:86])
			iflow.Pkts = parsePortBytes(payload[86:92])
			//iflow.FlowStartMilliSec = hex.EncodeToString(payload[132:136])
			//iflow.FlowEndMilliSec = hex.EncodeToString(payload[136:140])
			log.Println("flow data hexbytes: ", iflow)
			fmt.Println("======== Flow data ============\n")
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
