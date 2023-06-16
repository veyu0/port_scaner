import json
from pprint import pprint
import asyncio
import nmap


open_ports = []
closed_ports = []


def read_data_ip():
    with open('ips.txt', 'r') as file:
        ips = file.readlines()
        return list(ips)


def read_data_port():
    with open('ports.txt', 'r') as p:
        ports = p.readlines()
        return list(ports)


async def scanning():
    ips = read_data_ip()
    ports = read_data_port()

    for ip in ips:
        for port in ports:
            ip_address = ip.replace('\n', '')
            port_str = port.replace('\n', '')
            print(f'{ip_address} - {port_str}')

            nm = nmap.PortScanner()

            try:
                result = nm.scan(ip_address, port_str)

                port_status = (result['scan'][ip_address]['tcp'][port_str]['state'])
                print(f"Port {port_str} is {port_status}")
                open_ports.append({ip_address: port_str})

            except Exception as ex:
                print(f"Cannot scan port {port_str}.")
                closed_ports.append({ip_address: port_str})

    with open('opened_ports.json', 'w', encoding='utf-8') as file:
        json.dump(open_ports, file, indent=4)

    with open('closed_ports.json', 'w', encoding='utf-8') as file:
        json.dump(closed_ports, file, indent=4)


if __name__ == "__main__":
    asyncio.run(scanning())

    with open('opened_ports.json', 'r') as file:
        o_data = json.load(file)

    with open('closed_ports.json', 'r') as file:
        c_data = json.load(file)

    pprint(f'OPENED PORTS - {o_data}')
    pprint(f'CLOSED PORTS - {c_data}')
