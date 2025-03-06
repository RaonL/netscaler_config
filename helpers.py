import streamlit as st
from models.data_models import VIP

def display_vip_info(vip: VIP):
    """VIP 정보를 Streamlit에 표시하는 함수"""
    st.write(f"**IP 주소**: {vip.vip_ip}")
    st.write(f"**Port**: {vip.vip_port}")
    st.write(f"**Service Type**: {vip.vip_service_type}")
    st.write(f"**Load Balancing Method**: {vip.vip_lbmethod}")
    st.write(f"**ADC IP**: {vip.adc_ip}")

    # 서버 정보
    st.write("**Servers**:")
    if vip.vip_servers:
        for server in vip.vip_servers:
            st.write(f"- {server.server_name} ({server.ip}:{server.port or 'N/A'})")
    else:
        st.write("  (바인딩된 서버 없음)")

    # 모니터 정보
    st.write("**Monitors**:")
    if vip.vip_monitors:
        for monitor in vip.vip_monitors:
            st.write(f"- {monitor.monitor_name}")
    else:
        st.write("  (바인딩된 모니터 없음)")

    # 인증서 정보
    st.write("**Certificates**:")
    if vip.bound_certkeys:
        for cert in vip.bound_certkeys:
            st.write(f"- {cert.certkeyname} (SNI: {cert.snicert})")
    else:
        st.write("  (바인딩된 인증서 없음)")
