import streamlit as st
from dataclasses import dataclass, field
from typing import List, Dict
import re

# =========================
# 1) 데이터 구조 정의
# =========================

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
    servers: List[Server] = field(default_factory=list)
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

@dataclass
class VLAN:
    vlan_id: str
    interfaces: List[str] = field(default_factory=list)
    ip_bindings: List[str] = field(default_factory=list)

@dataclass
class Route:
    network: str
    netmask: str
    gateway: str
    distance: str = "0"
    cost: str = "0"

@dataclass
class ACL:
    acl_name: str
    acl_type: str   # simple, extended, simple6, extended6
    action: str     # ALLOW, BRIDGE, DENY
    source_ip: str = ""
    dest_ip: str = ""
    protocol: str = ""
    source_port: str = ""
    dest_port: str = ""

@dataclass
class Gateway:
    name: str
    vserver_type: str
    ip: str
    port: str
    authentication: str = ""
    ssl_profile: str = ""
    bound_certkeys: List[VipCertkey] = field(default_factory=list)

# --- Responder Policies (유지) ---
@dataclass
class ResponderPolicy:
    name: str
    rule: str
    action: str

# --- Rewrite Policies (유지) ---
@dataclass
class RewritePolicy:
    name: str
    rule: str
    action: str

# =========================
# 2) 파서 클래스
# =========================

class NetScalerParser:
    def __init__(self):
        # 파싱 결과 저장소
        self.config: Dict[str, VIP] = {}
        self.servers: Dict[str, Server] = {}
        self.service_groups: Dict[str, ServiceGroup] = {}
        self.vlans: Dict[str, VLAN] = {}
        self.routes: List[Route] = []
        self.acls: List[ACL] = []
        self.gateways: Dict[str, Gateway] = {}

        # **Responder Actions, Rewrite Actions, vserver_bindings 제거**
        # self.responder_actions: List[ResponderAction] = []
        self.responder_policies: Dict[str, ResponderPolicy] = {}
        # self.rewrite_actions: List[RewriteAction] = []
        self.rewrite_policies: Dict[str, RewritePolicy] = {}

        self.ns_ip = ""
        # vserver_bindings 제거

    def parse_nsconfig(self, line: str) -> str:
        parts = line.split()
        if "-IPAddress" in parts:
            return parts[parts.index("-IPAddress") + 1]
        raise ValueError("IP not found in line")

    def parse_server(self, line: str) -> Server:
        parts = line.split()
        return Server(server_name=parts[2], ip=parts[3])

    def parse_service_group(self, line: str) -> ServiceGroup:
        parts = line.split()
        return ServiceGroup(name=parts[2])

    def parse_lbvs(self, line: str, ns_ip: str) -> VIP:
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
        parts = line.split()
        sg_name = parts[2]
        if "-monitorName" in parts:
            monitor_idx = parts.index("-monitorName") + 1
            if monitor_idx < len(parts):
                self.service_groups[sg_name].monitors.append(
                    SGMonitor(monitor_name=parts[monitor_idx])
                )
        elif len(parts) > 3 and parts[3] in self.servers:
            server = self.servers[parts[3]]
            self.service_groups[sg_name].servers.append(server)

    def parse_ssl(self, line: str):
        # bind ssl vserver <vserver> -certkeyName <certkey> ...
        parts = line.split()
        cert_info = VipCertkey(
            certkeyname=parts[5],
            snicert="False" if len(parts) == 6 else "True"
        )
        if parts[3] in self.config:
            self.config[parts[3]].bound_certkeys.append(cert_info)
        elif parts[3] in self.gateways:
            self.gateways[parts[3]].bound_certkeys.append(cert_info)

    def parse_vlan(self, line: str) -> VLAN:
        parts = line.split()
        vlan_id = parts[2]
        return VLAN(vlan_id=vlan_id)

    def parse_bind_vlan(self, line: str):
        parts = line.split()
        vlan_id = parts[2]
        if vlan_id in self.vlans:
            if "-ifnum" in parts:
                idx = parts.index("-ifnum") + 1
                if idx < len(parts):
                    self.vlans[vlan_id].interfaces.append(parts[idx])
            if "-IPAddress" in parts:
                idx = parts.index("-IPAddress") + 1
                if idx < len(parts) and idx + 1 < len(parts):
                    ip = parts[idx]
                    netmask = parts[idx + 1]
                    self.vlans[vlan_id].ip_bindings.append(f"{ip}/{netmask}")

    def parse_route(self, line: str) -> Route:
        parts = line.split()
        if len(parts) == 5:
            network = parts[2]
            netmask = parts[3]
            gateway = parts[4]
        else:
            network = parts[3]
            netmask = parts[4]
            gateway = parts[5]
        route = Route(network=network, netmask=netmask, gateway=gateway)
        if "-distance" in parts:
            idx = parts.index("-distance") + 1
            if idx < len(parts):
                route.distance = parts[idx]
        if "-cost" in parts:
            idx = parts.index("-cost") + 1
            if idx < len(parts):
                route.cost = parts[idx]
        return route

    def parse_acl(self, line: str) -> ACL:
        parts = line.split()
        acl_name = parts[3]
        action = parts[4].upper()
        acl = ACL(acl_name=acl_name, acl_type="extended", action=action)
        i = 5
        while i < len(parts):
            token = parts[i]
            if token.startswith("-"):
                if i + 1 < len(parts) and parts[i + 1] == "=":
                    value = parts[i + 2] if i + 2 < len(parts) else ""
                    i += 3
                else:
                    value = parts[i + 1] if i + 1 < len(parts) else ""
                    i += 2
                if token == "-srcIP":
                    acl.source_ip = value
                elif token == "-destIP":
                    acl.dest_ip = value
                elif token == "-protocol":
                    acl.protocol = value
                elif token == "-srcPort":
                    acl.source_port = value
                elif token == "-destPort":
                    acl.dest_port = value
            else:
                i += 1
        return acl

    def parse_gateway(self, line: str) -> Gateway:
        parts = line.split()
        name = parts[3]
        vserver_type = parts[4]
        ip = parts[5]
        port = parts[6]
        gateway = Gateway(name=name, vserver_type=vserver_type, ip=ip, port=port)
        if "-authenticationDomain" in parts:
            idx = parts.index("-authenticationDomain") + 1
            if idx < len(parts):
                gateway.authentication = parts[idx]
        return gateway

    # Responder Policies만 유지 (Responder Actions 제거)

    def parse_responder_policy(self, line: str):
        prefix = "add responder policy "
        if not line.startswith(prefix):
            raise ValueError("Line does not start with 'add responder policy'")
        line2 = line[len(prefix):].strip()
        first_space_idx = line2.find(' ')
        if first_space_idx < 0:
            raise ValueError("No space after policyName")
        policy_name = line2[:first_space_idx]
        remainder = line2[first_space_idx + 1:].strip()
        try:
            rule_part, action = remainder.rsplit(' ', 1)
        except ValueError:
            raise ValueError("Could not split rule and action")
        self.responder_policies[policy_name] = ResponderPolicy(
            name=policy_name,
            rule=rule_part,
            action=action
        )

    # Rewrite Policies만 유지 (Rewrite Actions 제거)

    def parse_rewrite_policy(self, line: str):
        prefix = "add rewrite policy "
        if not line.startswith(prefix):
            raise ValueError("Line does not start with 'add rewrite policy'")
        line2 = line[len(prefix):].strip()
        first_space_idx = line2.find(' ')
        if first_space_idx < 0:
            raise ValueError("No space after policyName")
        policy_name = line2[:first_space_idx]
        remainder = line2[first_space_idx + 1:].strip()
        try:
            rule_part, action = remainder.rsplit(' ', 1)
        except ValueError:
            raise ValueError("Could not split rule and action")
        self.rewrite_policies[policy_name] = RewritePolicy(
            name=policy_name,
            rule=rule_part,
            action=action
        )

    # bind lb vserver, bind vpn vserver -> service group만 후처리
    # Responder/Rewrite 정책 바인딩 로직 제거

    def parse_netscaler_config(self, lines: List[str]) -> Dict:
        # 초기화
        self.config.clear()
        self.servers.clear()
        self.service_groups.clear()
        self.vlans.clear()
        self.routes.clear()
        self.acls.clear()
        self.gateways.clear()
        self.responder_policies.clear()
        self.rewrite_policies.clear()
        self.ns_ip = ""

        todo_lb_bind = []
        for line in lines:
            l = line.strip()
            if not l:
                continue
            try:
                if l.startswith("set ns config"):
                    self.ns_ip = self.parse_nsconfig(l)
                elif l.startswith("add server"):
                    sv = self.parse_server(l)
                    self.servers[sv.server_name] = sv
                elif l.startswith("add serviceGroup"):
                    sg = self.parse_service_group(l)
                    self.service_groups[sg.name] = sg
                elif l.startswith("add lb vserver"):
                    lbvs = self.parse_lbvs(l, self.ns_ip)
                    self.config[lbvs.vip_name] = lbvs
                elif l.startswith("bind serviceGroup"):
                    self.parse_bind_service_group(l)
                elif l.startswith("bind ssl vserver"):
                    self.parse_ssl(l)
                elif l.startswith("bind lb vserver") or l.startswith("bind vpn vserver"):
                    # serviceGroup 바인딩을 위한 후처리
                    todo_lb_bind.append(l)
                elif l.startswith("add vlan"):
                    vlan = self.parse_vlan(l)
                    self.vlans[vlan.vlan_id] = vlan
                elif l.startswith("bind vlan"):
                    self.parse_bind_vlan(l)
                elif l.startswith("add route"):
                    route = self.parse_route(l)
                    self.routes.append(route)
                elif l.startswith("add ns acl"):
                    acl_obj = self.parse_acl(l)
                    self.acls.append(acl_obj)
                elif l.startswith("add vpn vserver"):
                    gw = self.parse_gateway(l)
                    self.gateways[gw.name] = gw
                elif l.startswith("add responder policy"):
                    self.parse_responder_policy(l)
                elif l.startswith("add rewrite policy"):
                    self.parse_rewrite_policy(l)
                # Responder Actions, Rewrite Actions, vserver_bindings 제거
            except (IndexError, ValueError) as e:
                st.error(f"Error parsing line: {l}\nError: {e}")
                continue

        # bind lb vserver <vserverName> <serviceGroupName> ...
        for line in todo_lb_bind:
            parts = line.split()
            if len(parts) >= 5 and parts[4] in self.service_groups:
                vip = self.config.get(parts[3])
                if vip:
                    vip.vip_servers = self.service_groups[parts[4]].servers
                    vip.vip_monitors = self.service_groups[parts[4]].monitors

        # 최종 결과 (Responder Policies, Rewrite Policies만 남김)
        return {
            "vips": self.config,
            "vlans": self.vlans,
            "routes": self.routes,
            "acls": self.acls,
            "gateways": self.gateways,
            "responder_policies": list(self.responder_policies.values()),
            "rewrite_policies": list(self.rewrite_policies.values()),
        }

# =========================
# 3) 표시 함수
# =========================

def display_vip_info(vip: VIP):
    st.write(f"**VIP Name**: {vip.vip_name}")
    st.write(f"**IP 주소**: {vip.vip_ip}")
    st.write(f"**Port**: {vip.vip_port}")
    st.write(f"**Service Type**: {vip.vip_service_type}")
    st.write(f"**Load Balancing Method**: {vip.vip_lbmethod}")
    st.write(f"**ADC IP**: {vip.adc_ip}")

    st.write("**Servers**:")
    if vip.vip_servers:
        for server in vip.vip_servers:
            st.write(f"- {server.server_name} ({server.ip}:{server.port or 'N/A'})")
    else:
        st.write("  (바인딩된 서버 없음)")

    st.write("**Monitors**:")
    if vip.vip_monitors:
        for monitor in vip.vip_monitors:
            st.write(f"- {monitor.monitor_name}")
    else:
        st.write("  (바인딩된 모니터 없음)")

    st.write("**Certificates**:")
    shown_any_cert = False
    if vip.bound_certkeys:
        for cert in vip.bound_certkeys:
            # ECC Curve (P_256 등) 스킵 예시 => 필요 시 유지/삭제
            if cert.certkeyname in ["P_256", "P_384", "P_224", "P_521"]:
                continue
            st.write(f"- {cert.certkeyname} (SNI: {cert.snicert})")
            shown_any_cert = True
    if not shown_any_cert:
        st.write("  (바인딩된 인증서 없음 또는 ECC Curve만 존재)")

def display_vlan_info(vlan: VLAN):
    st.write(f"**VLAN ID**: {vlan.vlan_id}")
    st.write("**Interfaces**:")
    if vlan.interfaces:
        for interface in vlan.interfaces:
            st.write(f"- {interface}")
    else:
        st.write("  (바인딩된 인터페이스 없음)")

    st.write("**IP Bindings**:")
    if vlan.ip_bindings:
        for binding in vlan.ip_bindings:
            st.write(f"- {binding}")
    else:
        st.write("  (바인딩된 IP 없음)")

def display_route_info(route: Route):
    st.write(f"**Network**: {route.network}/{route.netmask}")
    st.write(f"**Gateway**: {route.gateway}")
    st.write(f"**Distance**: {route.distance}")
    st.write(f"**Cost**: {route.cost}")

def display_acl_info(acl: ACL):
    st.write(f"**Name**: {acl.acl_name}")
    st.write(f"**Type**: {acl.acl_type}")
    st.write(f"**Action**: {acl.action}")
    if acl.source_ip:
        st.write(f"**Source IP**: {acl.source_ip}")
    if acl.dest_ip:
        st.write(f"**Destination IP**: {acl.dest_ip}")
    if acl.protocol:
        st.write(f"**Protocol**: {acl.protocol}")
    if acl.source_port:
        st.write(f"**Source Port**: {acl.source_port}")
    if acl.dest_port:
        st.write(f"**Destination Port**: {acl.dest_port}")

def display_gateway_info(gateway: Gateway):
    st.write(f"**Name**: {gateway.name}")
    st.write(f"**Type**: {gateway.vserver_type}")
    st.write(f"**IP**: {gateway.ip}")
    st.write(f"**Port**: {gateway.port}")
    if gateway.authentication:
        st.write(f"**Authentication Domain**: {gateway.authentication}")
    if gateway.ssl_profile:
        st.write(f"**SSL Profile**: {gateway.ssl_profile}")
    st.write("**Certificates**:")
    if gateway.bound_certkeys:
        for cert in gateway.bound_certkeys:
            # ECC Curve 스킵할지 여부 => 필요 시 동일 처리
            st.write(f"- {cert.certkeyname} (SNI: {cert.snicert})")
    else:
        st.write("  (바인딩된 인증서 없음)")

def display_responder_policy(rp: ResponderPolicy):
    st.write(f"**Responder Policy Name**: {rp.name}")
    st.write("**Rule**:")
    st.code(rp.rule, language="text")
    st.write(f"**Action**: {rp.action}")

def display_rewrite_policy(rwp: RewritePolicy):
    st.write(f"**Rewrite Policy Name**: {rwp.name}")
    st.write("**Rule**:")
    st.code(rwp.rule, language="text")
    st.write(f"**Action**: {rwp.action}")


# =========================
# 4) 메인 앱 (가독성 개선 + 특정 항목 제거)
# =========================

def main():
    st.title("NetScaler 구성 분석기(가독성 개선) - Responder/Rewrite 'Actions' 및 바인딩 정책 제거")

    uploaded_file = st.file_uploader("NetScaler config 파일을 업로드하세요", type=["txt", "conf"])
    if uploaded_file is not None:
        content = uploaded_file.read().decode("utf-8")
        lines = content.splitlines()

        parser = NetScalerParser()
        result = parser.parse_netscaler_config(lines)

        # 1) VIP
        vip_list = list(result["vips"].values())
        count_vip = len(vip_list)
        st.subheader(f"Load Balancing VServers (VIP) [총 {count_vip}개]")
        if count_vip == 0:
            st.write("등록된 LB VServer가 없습니다.")
        else:
            for i, vip in enumerate(vip_list, start=1):
                with st.expander(f"{i}. {vip.vip_name}"):
                    display_vip_info(vip)

        # 2) VLAN
        vlan_list = list(result["vlans"].values())
        count_vlan = len(vlan_list)
        st.subheader(f"VLAN [총 {count_vlan}개]")
        if count_vlan == 0:
            st.write("등록된 VLAN이 없습니다.")
        else:
            for i, vlan in enumerate(vlan_list, start=1):
                with st.expander(f"{i}. VLAN ID: {vlan.vlan_id}"):
                    display_vlan_info(vlan)

        # 3) Routes
        route_list = result["routes"]
        count_route = len(route_list)
        st.subheader(f"경로 [총 {count_route}개]")
        if count_route == 0:
            st.write("등록된 경로가 없습니다.")
        else:
            for i, route in enumerate(route_list, start=1):
                with st.expander(f"{i}. Route: {route.network}/{route.netmask}"):
                    display_route_info(route)

        # 4) ACL
        acl_list = result["acls"]
        count_acl = len(acl_list)
        st.subheader(f"ACL [총 {count_acl}개]")
        if count_acl == 0:
            st.write("등록된 ACL이 없습니다.")
        else:
            for i, acl_obj in enumerate(acl_list, start=1):
                with st.expander(f"{i}. ACL: {acl_obj.acl_name}"):
                    display_acl_info(acl_obj)

        # 5) Gateway
        gw_list = list(result["gateways"].values())
        count_gw = len(gw_list)
        st.subheader(f"게이트웨이(VPN VServer) [총 {count_gw}개]")
        if count_gw == 0:
            st.write("등록된 게이트웨이가 없습니다.")
        else:
            for i, gw in enumerate(gw_list, start=1):
                with st.expander(f"{i}. Gateway: {gw.name}"):
                    display_gateway_info(gw)

        # 6) Responder Policies
        rp_list = result["responder_policies"]
        count_rp = len(rp_list)
        st.subheader(f"응답자 정책 (Responder Policies) [총 {count_rp}개]")
        if count_rp == 0:
            st.write("등록된 Responder Policy가 없습니다.")
        else:
            for i, rp in enumerate(rp_list, start=1):
                with st.expander(f"{i}. {rp.name}"):
                    display_responder_policy(rp)

        # 7) Rewrite Policies
        rwp_list = result["rewrite_policies"]
        count_rwp = len(rwp_list)
        st.subheader(f"리라이트 정책 (Rewrite Policies) [총 {count_rwp}개]")
        if count_rwp == 0:
            st.write("등록된 Rewrite Policy가 없습니다.")
        else:
            for i, rwp in enumerate(rwp_list, start=1):
                with st.expander(f"{i}. {rwp.name}"):
                    display_rewrite_policy(rwp)

        # Responder Actions / Rewrite Actions / vServer 바인딩된 Responder/Rewrite => 전부 제거

if __name__ == "__main__":
    main()
