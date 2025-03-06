import streamlit as st
from parsers.ns_parser import NetScalerParser
from utils.helpers import display_vip_info

def main():
    st.title("NetScaler Config Analyzer")
    st.markdown("업로드한 NetScaler 설정 파일을 파싱하여 VIP/서버/모니터/인증서 정보를 시각화합니다.")

    uploaded_file = st.file_uploader("NetScaler config 파일을 업로드하세요", type=["txt", "conf"])
    
    if uploaded_file is not None:
        # 파일 내용 읽어서 파싱
        try:
            lines = uploaded_file.read().decode("utf-8").splitlines()
            parser = NetScalerParser()
            parsed_config = parser.parse_netscaler_config(lines)

            # 결과가 있는 경우 VIP 목록 출력
            if parsed_config:
                st.subheader("분석 결과: VIP 목록")
                
                # 검색 기능 추가
                search_term = st.text_input("VIP 이름 검색", "")
                
                # VIP 목록 필터링 및 정렬
                filtered_vips = {
                    k: v for k, v in parsed_config.items() 
                    if search_term.lower() in k.lower()
                }
                
                sorted_vips = dict(sorted(filtered_vips.items()))
                
                # VIP 정보 표시
                for vip_name, vip in sorted_vips.items():
                    with st.expander(f"VIP: {vip_name}", expanded=False):
                        display_vip_info(vip)
            else:
                st.warning("파싱 결과가 없습니다. 파일 형식을 다시 확인해주세요.")
                
        except Exception as e:
            st.error(f"파일 처리 중 오류가 발생했습니다: {str(e)}")

if __name__ == "__main__":
    main()
