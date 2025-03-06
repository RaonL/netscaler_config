from typing import List, Dict, Optional, Tuple
from models.data_models import Server, ServiceGroup, SGMonitor, VIP, VipCertkey

class NetScalerParser:
    def __init__(self):
        self.config = {}
        self.servers = {}
        self.service_groups = {}
    
    def parse_nsconfig(self, line: str) -> str:
        """Extract the IP Address from ns config line."""
        parts = line.split()
        if "-IPAddress" in parts:
            return parts[parts.index("-IPAddress") + 1]
        raise ValueError("IP not found in line")

    def parse_server(self, line: str) -> Server:
        """Parse server line and return Server object."""
        parts = line.split()
        return Server(server_name=parts[2], ip=parts[3])

    def parse_service_group(self, line: str) -> ServiceGroup:
        """Parse service group line."""
        parts = line.split()
        return ServiceGroup(name=parts[2])

    def parse_lbvs(self, line: str, ns_ip: str) -> VIP:
        """Parse lb vserver line."""
        parts = line.split()
        lb_method = "LEASTCONNECTION"
        if "-lbMethod" in parts:
            lb_method = parts[parts.index("-lbMethod") + 1]

        return VIP(
            vip_name=parts[3],
            vip_service_type=parts[4],
            vip_ip=parts[5],
            vip_port=parts[6],
            vip_lbmethod=lb_method,
            adc_ip=ns_ip
        )

    def parse_bind_service_group(self, line: str):
        """Bind service group to server or monitor."""
        parts = line.split()
        sg_name = parts[2]

        # -monitorName 옵션 처리
        if "-monitorName" in parts:
            monitor_idx = parts.index("-monitorName") + 1
            if monitor_idx < len(parts):
                self.service_groups[sg_name].monitors.append(
                    SGMonitor(monitor_name=parts[monitor_idx])
                )
        elif len(parts) > 3 and parts[3] in self.servers:
            # 서버 바인딩 처리
            server = self.servers[parts[3]]
            self.service_groups[sg_name].servers.append(server)

    def parse_ssl(self, line: str):
        """Parse SSL bindings."""
        parts = line.split()
        # bind ssl vserver <vserver> -certkeyName <certkey> ...
        cert_info = VipCertkey(
            certkeyname=parts[5],
            snicert="False" if len(parts) == 6 else "True"  # 길이에 따라 SNI 여부 구분
        )
        if parts[3] in self.config:
            self.config[parts[3]].bound_certkeys.append(cert_info)

    def parse_netscaler_config(self, lines: List[str]) -> Dict[str, VIP]:
        """Main parsing function."""
        # 혹시 재파싱 시 중복 방지를 위해 초기화
        self.config = {}
        self.servers = {}
        self.service_groups = {}

        ns_ip = ""
        todo = []

        for line in lines:
            parts = line.split()
            if not parts:  # 빈 줄 처리
                continue
                
            try:
                if line.startswith("set ns config"):
                    ns_ip = self.parse_nsconfig(line)
                elif line.startswith("add server"):
                    server = self.parse_server(line)
                    self.servers[server.server_name] = server
                elif line.startswith("add serviceGroup"):
                    sg = self.parse_service_group(line)
                    self.service_groups[sg.name] = sg
                elif line.startswith("add lb vserver"):
                    lbvs = self.parse_lbvs(line, ns_ip)
                    self.config[lbvs.vip_name] = lbvs
                elif line.startswith("bind serviceGroup"):
                    self.parse_bind_service_group(line)
                elif line.startswith("bind ssl vserver"):
                    self.parse_ssl(line)
                elif line.startswith("bind lb vserver"):
                    # bind lb vserver <lbvserver> <serviceGroupName> ...
                    todo.append(line)
            except (IndexError, ValueError) as e:
                # 오류 발생 시 로깅하거나 처리할 수 있음
                print(f"Error parsing line: {line}. Error: {e}")
                continue

        # Post-processing for 'bind lb vserver'
        for line in todo:
            parts = line.split()
            if len(parts) >= 5 and parts[4] in self.service_groups:
                vip = self.config.get(parts[3])
                if vip:
                    vip.vip_servers = self.service_groups[parts[4]].servers
                    vip.vip_monitors = self.service_groups[parts[4]].monitors

        return self.config
