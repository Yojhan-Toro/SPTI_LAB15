import xml.etree.ElementTree as ET
import subprocess
import argparse
import json


def parse_nmap_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    hosts_data = []

    for host in root.findall("host"):
        # Solo hosts activos
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        # IP
        address = host.find("address")
        ip = address.get("addr") if address is not None else None

        # Hostname
        hostname = None
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        # Puertos abiertos
        open_ports = []
        ports = host.find("ports")

        if ports is not None:
            for port in ports.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue

                port_id = int(port.get("portid"))

                service = port.find("service")
                service_name = service.get("name") if service is not None else None
                version = service.get("version") if service is not None else None

                open_ports.append({
                    "port": port_id,
                    "service": service_name,
                    "version": version
                })

        hosts_data.append({
            "ip": ip,
            "hostname": hostname,
            "open_ports": open_ports
        })

    return hosts_data


def get_ssh_key_type(ip, timeout=3):
    try:
        result = subprocess.run(
            ["ssh-keyscan", "-T", str(timeout), ip],
            capture_output=True,
            text=True
        )

        output = result.stdout.strip()

        if not output:
            return None

        # Ejemplo: "192.168.1.10 ssh-ed25519 AAAAC3..."
        first_line = output.splitlines()[0]
        parts = first_line.split()

        if len(parts) >= 2:
            return parts[1]

    except Exception:
        return None

    return None


def enrich_hosts_with_ssh(hosts):
    for host in hosts:
        for port in host["open_ports"]:
            if port["port"] == 22:
                key_type = get_ssh_key_type(host["ip"])
                host["ssh_host_key_type"] = key_type
                break


def main():
    parser = argparse.ArgumentParser(description="Parse Nmap XML and enrich with SSH key type")
    parser.add_argument("--input", required=True, help="Input XML file")
    parser.add_argument("--output", required=True, help="Output JSON file")

    args = parser.parse_args()

    hosts = parse_nmap_xml(args.input)
    enrich_hosts_with_ssh(hosts)

    with open(args.output, "w") as f:
        json.dump(hosts, f, indent=2)

    print(f"[+] Results written to {args.output}")


if __name__ == "__main__":
    main()
