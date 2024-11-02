from scapy.all import sniff, wrpcap
import argparse
import sys

def packet_handler(packet):
    print(packet.summary())

def start_sniffing(interface, packet_count, protocol, output_file):
    try:
        print(f"Startar sniffning på {interface}...")
        if protocol:
            packets = sniff(iface=interface, count=packet_count, filter=protocol, prn=packet_handler)
        else:
            packets = sniff(iface=interface, count=packet_count, prn=packet_handler)

        print(f"Sniffning klar. Fångade {len(packets)} paket.")

        if output_file:
            wrpcap(output_file, packets)
            print(f"Paket sparade till {output_file}.")
    except Exception as e:
        print(f"Ett fel uppstod: {e}")
        sys.exit(1)

def list_interfaces():
    from scapy.all import get_if_list
    interfaces = get_if_list()
    print("Tillgängliga nätverksgränssnitt:")
    for iface in interfaces:
        print(f"- {iface}")

def parse_arguments():
    parser = argparse.ArgumentParser(description='Packet Sniffer med Scapy.')
    parser.add_argument('-i', '--interface', help='Nätverksgränssnitt att lyssna på.')
    parser.add_argument('-c', '--count', type=int, default=0, help='Antal paket att fånga (0 för obegränsat).')
    parser.add_argument('-p', '--protocol', choices=['tcp', 'udp', 'icmp', 'arp'], help='Protokoll att filtrera på.')
    parser.add_argument('-o', '--output', help='Filnamn för att spara fångade paket (PCAP-format).')
    parser.add_argument('--list', action='store_true', help='Lista tillgängliga nätverksgränssnitt.')
    return parser.parse_args()

def main():
    args = parse_arguments()

    if args.list:
        list_interfaces()
        sys.exit(0)

    if not args.interface:
        print("Du måste ange ett nätverksgränssnitt att lyssna på. Använd --list för att visa tillgängliga gränssnitt.")
        sys.exit(1)

    # Validera nätverksgränssnitt
    from scapy.all import get_if_list
    if args.interface not in get_if_list():
        print(f"Nätverksgränssnittet '{args.interface}' hittades inte.")
        sys.exit(1)

    # Bygg filtersträng
    protocol_filter = args.protocol

    start_sniffing(args.interface, args.count, protocol_filter, args.output)

if __name__ == '__main__':
    main()
