import socket
import struct


def mac(raw_data):
    byte_str = map('{:02x}'.format, raw_data)
    mac_address = ':'.join(byte_str).upper()
    return mac_address


def ip(raw_data):
    return '.'.join(map(str, raw_data))


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print('Starting...\n')
    try:
        while True:
            raw_data, address = conn.recvfrom(65535)

            # extract ethernet info
            destination_mac, source_mac, protocol = struct.unpack('! 6s 6s H', raw_data[:14])
            ip_data = raw_data[14:]

            # print ethernet info
            print('\t\t**************')
            print('Packet Information:')
            print(f'Source MAC Address: {mac(source_mac)}\nDestination MAC Address: {mac(destination_mac)}')

            # extract the ip info
            version_header_length = ip_data[0]
            version = version_header_length >> 4
            header_length = (version_header_length & 15) * 4
            ttl, protocol, source_ip, destination_ip = struct.unpack('! 8x B B 2x 4s 4s', ip_data[:20])
            source_ip = ip(source_ip)
            destination_ip = ip(destination_ip)
            protocol_data = ip_data[header_length:]

            # print ip info
            print(f'Source IP Address: {source_ip}\nDestination IP Address: {destination_ip}\nTTL: {ttl}')

            if protocol == 6 or protocol == 17:
                # extract port info for tcp and udp
                source_port, destination_port = struct.unpack('! H H', protocol_data[:4])
                print(f'Source Port: {source_port}\nDestination Port: {destination_port}')
    except KeyboardInterrupt:
        print('\t\t**************')
        print('Exiting...')


main()
