from dataclasses import dataclass, field
from typing import List, Dict, Optional

@dataclass
class Server:
    server_name: str
    ip: str = ""
    port: str = ""

@dataclass
class SGMonitor:
    monitor_name: str
    mon_state: str = ""
    state: str = ""

@dataclass
class Response:
    monitor_name: str
    last_response: str

@dataclass
class ServiceGroup:
    name: str
    servers: List['Server'] = field(default_factory=list)
    monitors: List[SGMonitor] = field(default_factory=list)

@dataclass
class VipCertkey:
    certkeyname: str
    snicert: str = "False"

@dataclass
class VIP:
    vip_name: str
    vip_ip: str
    vip_port: str
    vip_lbmethod: str = "LEASTCONNECTION"
    vip_service_type: str = ""
    adc_ip: str = ""
    vip_servers: List[Server] = field(default_factory=list)
    vip_monitors: List[SGMonitor] = field(default_factory=list)
    bound_certkeys: List[VipCertkey] = field(default_factory=list)
