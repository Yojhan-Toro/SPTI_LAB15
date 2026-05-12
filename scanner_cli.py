import argparse
import asyncio
import json
import time
from datetime import datetime

def parse_ports(port_str):
    ports = set()

    for part in port_str.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    return sorted(ports)

async def scan_port(host, port, timeout, sem):
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return port
        except:
            return None

async def run_scan(args):
    ports = parse_ports(args.ports)
    sem = asyncio.Semaphore(args.rate)

    start = time.perf_counter()

    tasks = [scan_port(args.target, p, args.timeout, sem) for p in ports]
    results = await asyncio.gather(*tasks)

    open_ports = [p for p in results if p is not None]

    elapsed = time.perf_counter() - start

    output = {
        "target": args.target,
        "scan_time_seconds": round(elapsed, 2),
        "timestamp": datetime.utcnow().isoformat(),
        "open_ports": open_ports
    }

    if args.output == "stdout":
        print(json.dumps(output, indent=2))
    else:
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2)

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("target")
    parser.add_argument("--ports", default="1-1024")
    parser.add_argument("--rate", type=int, default=200)
    parser.add_argument("--timeout", type=float, default=0.5)
    parser.add_argument("--output", default="stdout")

    args = parser.parse_args()

    asyncio.run(run_scan(args))

if __name__ == "__main__":
    main()

