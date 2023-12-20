import socket
import scapy.all as scapy
import argparse


def parse_arguments():
    parser = argparse.ArgumentParser(description="Usage for network scan: python netcrown.py -ip [IP Address]")
    parser.add_argument("-ip", "--ipaddress", dest="ip", help="Please enter IP address")
    parser.add_argument("-i", "--interface", dest="interface", help="Network interface")
    parser.add_argument("-p", "--ports", dest="ports",
                        help="Specify the ports to scan (e.g., 21, 1-100)")

    args = parser.parse_args()
    ip = args.ip
    interface = args.interface
    if not ip:
        print("Please enter an IP address to run the script!")
    if not interface:
        print("You can also run by specifying the interface")
    return args


def scanner(ip, interface, ports):
    packet = scapy.ARP(pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
    header = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    full_packet = header / packet
    answered_list = scapy.srp(full_packet, timeout=1, iface=interface, verbose=False)[0]

    client_list = []
    open_ports = []
    is_port_scanned = False

    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)

        # Port scanning
        if ports:
            if ports.lower() == "all":
                for port in range(1, 65536):
                    if port_scan(client_dict["ip"], port):
                        open_ports.append({"ip": client_dict["ip"], "port": port,
                                           "banner": get_banner(client_dict["ip"], port)})
            elif ports.lower() == "common":
                for port in range(1, 1025):
                    if port_scan(client_dict["ip"], port):
                        open_ports.append({"ip": client_dict["ip"], "port": port,
                                           "banner": get_banner(client_dict["ip"], port)})
            else:
                port_range = ports.split("-")
                start_port = int(port_range[0])
                end_port = int(port_range[1]) if len(port_range) > 1 else start_port

                for port in range(start_port, end_port + 1):
                    if port_scan(client_dict["ip"], port):
                        open_ports.append({"ip": client_dict["ip"], "port": port,
                                           "banner": get_banner(client_dict["ip"], port)})
                is_port_scanned = True
        else:
            is_port_scanned = False

    return client_list, open_ports, is_port_scanned


def port_scan(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0


def get_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((ip, port))
        banner = sock.recv(1024)
        banner_str = banner.decode('latin-1')
        banner_utf8 = banner_str.encode('utf-8', 'ignore').decode('utf-8', 'ignore')
        return banner_utf8
    except socket.timeout:
        return "unknown (Timeout)"
    except (socket.error, ConnectionError) as e:
        return "unknown"
    finally:
        sock.close()


def show_results(client_results, open_port_results, is_port_scanned):
    print("IP Address\t\tMAC Address")
    print("---------------------------------")
    for client in client_results:
        print(client["ip"] + "\t\t" + client["mac"])

    if open_port_results:
        print("\nOpen Ports and Services")
        print("----------------------------")
        for entry in open_port_results:
            print("IP:", entry["ip"], "Port:", entry["port"], "Banner:", entry.get("banner", "Unknown"))

    elif is_port_scanned == True:
        print("\nNo open ports")


if __name__ == "__main__":
    options = parse_arguments()
    client_results, open_port_results, is_port_scanned = scanner(options.ip, options.interface, options.ports)
    show_results(client_results, open_port_results, is_port_scanned)
