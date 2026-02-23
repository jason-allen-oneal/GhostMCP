import xml.etree.ElementTree as ET
import json
from typing import Any, Dict

def parse_nmap_xml(xml_content: str) -> Dict[str, Any]:
    """Parse Nmap XML output into a structured dictionary."""
    if not xml_content.strip():
        return {}
    
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return {"error": "Invalid XML output from nmap"}

    results = {
        "summary": {},
        "hosts": []
    }

    # Summary info
    runstats = root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            results["summary"]["elapsed"] = finished.get("elapsed")
            results["summary"]["summary_text"] = finished.get("summary")
        
        hosts_stats = runstats.find("hosts")
        if hosts_stats is not None:
            results["summary"]["up"] = hosts_stats.get("up")
            results["summary"]["total"] = hosts_stats.get("total")

    # Host details
    for host in root.findall("host"):
        host_data = {
            "addresses": [],
            "hostnames": [],
            "ports": []
        }
        
        # Status
        status = host.find("status")
        if status is not None:
            host_data["status"] = status.get("state")

        # Addresses
        for addr in host.findall("address"):
            host_data["addresses"].append({
                "addr": addr.get("addr"),
                "type": addr.get("addrtype")
            })

        # Hostnames
        hostnames = host.find("hostnames")
        if hostnames is not None:
            for hname in hostnames.findall("hostname"):
                host_data["hostnames"].append({
                    "name": hname.get("name"),
                    "type": hname.get("type")
                })

        # Ports
        ports_node = host.find("ports")
        if ports_node is not None:
            for port in ports_node.findall("port"):
                port_info = {
                    "id": port.get("portid"),
                    "protocol": port.get("protocol")
                }
                
                state = port.find("state")
                if state is not None:
                    port_info["state"] = state.get("state")
                
                service = port.find("service")
                if service is not None:
                    port_info["service"] = {
                        "name": service.get("name"),
                        "product": service.get("product"),
                        "version": service.get("version"),
                        "extrainfo": service.get("extrainfo")
                    }
                
                host_data["ports"].append(port_info)

        results["hosts"].append(host_data)

    return results
