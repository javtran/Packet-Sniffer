import pcapy
import sys

'''
Instructions:
Find devices for capturing packets
	- You can make user select the devices

Set filtering correctly

Sniffing HTTP Request/Response
'''

# keep count of the number of request/response
count = 0

'''
Handles each packets that we receive. Parses through each layer
to get the source port/address and destination port/address. Exits (don't print) if the header is incomplete. 
Prints the packet if we get a response/request through identify()
''' 
def packet_handling(header, packet):
	
	# Parse ethernet frame (first 14 bytes)
	ethernet_len = 14
	
	# unpacking for Ethernet (not needed)
	# 	destination MAC (6 bytes)
	#  	source MAC (6 bytes)
	#	ether type (2 bytes)
	
	# get first 20 known bytes for ip header
	ip = packet[ethernet_len: 20 + ethernet_len]
		
	# unpacking for IP
	# 	version/header length (1 byte) 	-> ip[0]
	#	type of service (1 byte) 		-> ip[1]
	#	total length (2 bytes) 			-> ip[2:4]
	#	identification (2 bytes) 		-> ip[4:6]
	#	fragment offset (2 bytes)		-> ip[6:8]
	#	time to live (1 byte)			-> ip[8]
	#	protocol (1 byte)				-> ip[9]
	#	header checksum (2 bytes)		-> ip[10:12]
	#	source address (4 bytes)		-> ip[12:16]
	#	destination address (4 bytes)	-> ip[16:20]
	
	
	# header length is last 4 bits, so mask only last 4
	ip_HL = ip[0] & 0xF
	
	# length of IP header 
	ip_len = ip_HL * 4
	
	# in case the ip has invalid size, we exit
	if ip_len < 20:
		return
		
	# get the source and destination address
	source_address = convert_address(ip[12:16])
	destination_address = convert_address(ip[16:20])

	# start index for tcp
	index_tcp = ethernet_len + ip_len
	tcp = packet[index_tcp:index_tcp + 20]
		
	# unpacking for TCP:
	# 	source port (2 bytes)			-> tcp[0:2]
	#	destination port (2 bytes)		-> tcp[2:4]
	#	sequence number (4 bytes)		-> tcp[4:8]
	#	acknowledgement number (4 bytes)-> tcp[8:12]
	#	offset/reserved (1 byte)		-> tcp[12]
	#	TCP Flags (1 byte)				-> tcp[13]
	#	Window (2 bytes)				-> tcp[14:16]
	#	checksum (2 bytes)				-> tcp[16:18]
	#	urgent pointer (2 bytes)		-> tcp[18:20]
	
	# get source/destination port
	source_port = int.from_bytes(tcp[0:2], "big")
	destination_port = int.from_bytes(tcp[2:4], "big")
	
	# offset is first 4 bits, we don't need reserved
	tcp_offset = tcp[12] >> 4 
	tcp_len = tcp_offset * 4
	
	# in case tcp has invalid size
	if tcp_len < 20:
		return
		
	#start index for payload
	index_payload = ethernet_len + ip_len + tcp_len
	
	# get size of payload
	payload_size = len(packet) - index_payload
	payload = packet[index_payload:]
	
	# we only want to print packets with payload
	if payload_size > 0:
		# identifies what kind of packet (response or request)
		# also returns empty string for anything else
		identification = identify(payload)
		
		# only print packets that are response or request
		if identification != "":
			# increase count of successful packet prints
			global count
			count += 1
			print("{} {}:{} {}:{} HTTP {}\r\n{}\r\n\r\n".format(count, source_address, source_port, destination_address,
			 destination_port, identification, decode_print(payload)))
	return
	
# takes in address in bytes form and convert to correct address format
def convert_address(address):
	# decodes each byte and join them by '.'
	converted = '.'.join(str(b) for b in address)
	return(converted)

#identifies the packet by checking the first line
# if the first 4 bytes is 'HTTP' then we have response 
# if 'HTTP' appears anywhere in the first line thats not the first 4 bytes then we know its a request
# anything else means that the packet is not needed
def identify(payload):
	# response if first 4 bytes is 'HTTP'
	if bytes('HTTP','UTF-8') in payload[:4]:
		return "Response"
		
	for i in range(len(payload)):
		# only checks the first line for 'HTTP'
		if bytes("\r\n",'UTF-8') == payload[i:i + 2]:
			# request if 'HTTP' appears in the first line but not first 4 bytes
			if bytes('HTTP','UTF-8') in payload[:i]:
				return "Request"
			else:
				break
	# returns empty string to indicate useless header packets
	return ""


# takes in identified payload an sets up a string for printing
def decode_print(payload):
	for i in range(len(payload)):
		# decode anything thats before '\r\n\r\n' or the entity body
		if "\r\n\r\n" == str(payload[i:i + 4], 'UTF-8'):
			return str(payload[:i], 'UTF-8')
	
def main(argv):
	# obtain the list of available network device
	devices = pcapy.findalldevs()
	if devices is None:
		print("No devices are found")
		sys.exit()
	
	# prints list of devices 
	print("list of devices:")
	for i in range(len(devices)):
		print("{}. {}".format(i + 1, devices[i]))
	
	# user selects the device
	while True:
		device = input("Select a device: ")
		if device in devices:
			break
		else:
			print(" '{}' is an invalid device. Select a valid device from the list".format(device))
			continue
	print("User selected device: {}".format(device))
	
	
	# obtain packet capture handle from device
	# maximum size of IP packet is 65,535
	p = pcapy.open_live(device, 65535, 1, 1000)

	# set the filter
	if p.setfilter("tcp port 80") != 0:
		pcapy.PcapError(p)
	
	# starts the loop
	p.loop(-1, packet_handling);
	
	return
	
	
	
if __name__ == "__main__":
	main(sys.argv)
