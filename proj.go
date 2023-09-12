package main

import (
	"bytes"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	snapshot_len    int32 = 1024
	promiscuous     bool  = false
	err             error
	timeout         time.Duration = 30 * time.Second
	handle          *pcap.Handle
	pac_counter     int32 = 0
	character_indx  int   = 0
	character       byte
	username_string bytes.Buffer
	query_string    bytes.Buffer
	filter          string = "tcp and port 1521"
)

func main() {
	devices := Scan_AllDevices()
	// Open device
	handle := Open_Device(devices[0].Name)
	defer handle.Close()
	// Set filter
	handle.SetBPFFilter(filter)
	// Use the handle as a packet source to process all packets
	fmt.Println("Snifing is starting")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		character_indx = 0
		Check_username_pack(packet)
		Print_OCI_pack(packet)
	}
}

func Scan_AllDevices() []pcap.Interface {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	return devices
}

func Open_Device(Dvice_name string) *pcap.Handle {
	handle, err = pcap.OpenLive(Dvice_name, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	return handle
}

func Packet_isTNS(packet gopacket.Packet) (result bool) {
	if len(packet.Layers()) == 4 {
		return true
	}
	return false
}

func Username_exist(packet gopacket.Packet) (result bool) {
	if len(packet.Layers()[3].LayerContents()) > 10 &&
		packet.Layers()[3].LayerContents()[10] == 0x03 &&
		packet.Layers()[3].LayerContents()[11] == 0x76 {
		return true
	}
	return false
}

func Standard_character(character byte) (result bool) {
	if character > 31 && character < 127 {
		return true
	}
	return false
}

func OCIQuery_exist(packet gopacket.Packet) (result bool) {
	if len(packet.Layers()[3].LayerContents()) > 12 &&
		((packet.Layers()[3].LayerContents()[10] == 3 &&
			packet.Layers()[3].LayerContents()[11] == 94) ||
			(packet.Layers()[3].LayerContents()[10] == 17 &&
				packet.Layers()[3].LayerContents()[11] == 105)) {
		return true
	}
	return false
}

func longest_valid_substring(packet gopacket.Packet) (result bytes.Buffer) {
	character_indx = 0
	var cur_vsubstring bytes.Buffer
	var longest_vsubstring bytes.Buffer
	for character_indx < len(packet.Layers()[3].LayerContents()) {
		character = packet.Layers()[3].LayerContents()[character_indx]
		if Standard_character(character) {
			cur_vsubstring.WriteByte(character)
			if cur_vsubstring.Len() > longest_vsubstring.Len() {
				longest_vsubstring = cur_vsubstring
			}
		} else {
			cur_vsubstring.Reset()
		}
		character_indx++
	}
	return longest_vsubstring
}

func Get_username(packet gopacket.Packet) (result bytes.Buffer) {
	character_indx = 12
	character = packet.Layers()[3].LayerContents()[character_indx]
	for Standard_character(character) == false || string(character) == "!" {
		character_indx++
		character = packet.Layers()[3].LayerContents()[character_indx]
	}
	for Standard_character(character) {
		username_string.WriteByte(character)
		character_indx++
		character = packet.Layers()[3].LayerContents()[character_indx]
	}
	return username_string
}

func Check_username_pack(packet gopacket.Packet) {
	if Packet_isTNS(packet) && Username_exist(packet) {
		pac_counter += 1
		username_string = Get_username(packet)
		fmt.Println("###########################################")
		fmt.Println("Packet with username founded :", pac_counter)
		fmt.Println(packet.Layers()[3].LayerContents())
		fmt.Println("username founded :", username_string.String())
		fmt.Println("###########################################")
		username_string.Reset()
	}

}

func Print_OCI_pack(packet gopacket.Packet) {
	if Packet_isTNS(packet) && OCIQuery_exist(packet) {
		query_string = longest_valid_substring(packet)
		if query_string.Len() > 25 {
			pac_counter += 1
			fmt.Println("###########################################")
			fmt.Println("Packet with query founded :", pac_counter)
			fmt.Println(packet.Layers()[3].LayerContents())
			fmt.Println("Query founded :", query_string.String())
			fmt.Println("###########################################")
			query_string.Reset()
		}
	}
}
