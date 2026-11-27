import os
from datetime import datetime, timezone

import httpx
import streamlit as st

from ui.review import review_controls


STATUS = {
    "pending": ("Chờ duyệt", "orange"),
    "approved": ("Đã duyệt", "blue"),
    "running": ("Đang xác minh", "blue"),
    "verified": ("Đã xác minh", "green"),
    "recovered": ("Đã phục hồi", "green"),
    "failed": ("Thất bại", "red"),
    "escalated": ("Cần xử lý thủ công", "red"),
    "rolled_back": ("Đã rollback", "violet"),
    "rejected": ("Đã từ chối", "gray"),
    "expired": ("Hết hạn", "gray"),
    "missing": ("Thiếu dữ liệu", "gray"),
    "open": ("Mới", "blue"),
    "need_human": ("Cần xem xét", "orange"),
    "diagnosed": ("Đã chẩn đoán", "green"),
}
SEVERITY = {"high": "Cao", "medium": "Trung bình"}
RUNBOOK_NAMES = {"RB01": "Khôi phục DNS", "RB02": "Khôi phục portal", "RB03": "Cách ly nguồn lab"}
REASONS = {"dns_failure": "DNS lỗi trong khi portal theo IP còn hoạt động",
           "web_down": "DNS còn hoạt động nhưng portal theo IP lỗi",
           "ids_test": "Suricata nhận sự kiện kiểm thử khớp nguồn trong lab",
           "missing_evidence": "Chưa thu thập đủ bằng chứng"}
DIAGNOSTIC_GUIDANCE = {
    "expected_deny": "Guest bị chặn theo policy. Giữ nguyên quyền truy cập hiện tại.",
    "gateway_unreachable": "Đối chiếu VLAN access, trunk và bảng MAC với topology chuẩn.",
    "dhcp_failure": "Kiểm tra DHCP, trạng thái lease và các bước discover, offer, request, ack.",
    "packet_loss": "So sánh tỷ lệ mất gói từ nguồn bị ảnh hưởng với canary độc lập.",
}


def utc_label(value):
    return datetime.fromisoformat(value).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def show_topology(graph):
    st.header("Topology")
    st.caption(f'{graph["lab"]} · SW → trunk 802.1Q → GW → WAN {graph["wan"]}')
    with st.grid("auto", min_column_width=126, gap="small"):
        for host in graph["hosts"]:
            with st.container(border=True):
                st.markdown(f'**{host["name"]}**')
                st.write(f'VLAN {host["vlan"]} · `{host["gateway"]}`')


def incident_table(rows):
    with st.sidebar:
        status = st.selectbox("Trạng thái", ["priority", "all", *STATUS], key="status_filter",
                              format_func=lambda key: {"priority": "Cần xử lý trước", "all": "Tất cả"}.get(
                                  key, STATUS.get(key, (key,))[0]))
        severity = st.selectbox("Mức độ", ["all", *SEVERITY], key="severity_filter",
                                format_func=lambda key: SEVERITY.get(key, "Tất cả"))
        st.button("Làm mới dữ liệu", key="refresh", icon=":material/refresh:")
    st.header("Incidents")
    visible = [row for row in rows if (status in {"all", "priority"} or row["status"] == status)
               and (severity == "all" or row["severity"] == severity)]
    if status == "all":
        visible.sort(key=lambda row: row["timestamp"], reverse=True)
    if not visible:
        st.info("Không có incident trong bộ lọc hiện tại.")
        return None
    st.dataframe([{"ID": row["id"], "Thời gian UTC": utc_label(row["timestamp"]),
                   "Nguồn": f'{row["source_node"]} / {row["origin"]}',
                   "Trạng thái": STATUS[row["status"]][0], "Mức độ": SEVERITY[row["severity"]]}
                  for row in visible], hide_index=True, height="auto", lazy=False, alt="Danh sách incident",
                 column_config={"ID": st.column_config.TextColumn(width="medium")})
    return st.selectbox("Incident đang xem", [row["id"] for row in visible], key="selected_incident")


def evidence_view(detail):
    st.header("Bằng chứng")
    evidence = detail["evidence"]
    if evidence:
        st.dataframe([{"UTC": utc_label(row["timestamp"]), "Nguồn": row["source_node"],
                       "Loại": row["probe"].upper(), "Đích": row["target"],
                       "Quan sát": row["reason"]} for row in evidence],
                     hide_index=True, height="auto", lazy=False, alt="Timeline bằng chứng probe và EVE")
        with st.expander("Probe và EVE gốc"):
            st.json(evidence, expanded=False)
    else:
        st.warning("Thiếu dữ liệu probe hoặc EVE cho incident này.")


def show_result(approval, audit):
    result = approval.get("result") if approval else None
    if result:
        columns = [("Trước", "before"), ("Sau", "after"), ("Hết hạn", "expiry"), ("Rollback", "rollback")]
        states = {label: result[key] for label, key in columns if key in result}
        if states:
            with st.expander("Snapshot thực tế trước và sau", expanded=True):
                st.json(states, expanded=1)
        if result.get("rollback_status") == "verified":
            st.badge("Đã xác minh rollback", color="violet")
        stages = {"postcheck": "Sau thay đổi", "expiry_probes": "Sau hết hạn", "rollback_probes": "Sau rollback"}
        samples = [{"Giai đoạn": label, "UTC": utc_label(row["timestamp"]),
                    "Probe": row["probe_id"], "Kết quả": row["status"]}
                   for group, label in stages.items() for row in result.get(group, [])]
        if samples:
            with st.expander("Mẫu xác minh và canary"):
                st.dataframe(samples, hide_index=True, alt="Kết quả probe và canary")
        if result.get("error"):
            st.warning(result["error"])
    if audit:
        with st.expander("Audit"):
            st.dataframe([{"UTC": utc_label(row["utc"]), "Actor": row["actor"], "Sự kiện": row["event"]}
                          for row in audit], hide_index=True, alt="Audit thao tác")
            st.json(audit, expanded=False)


def proposal_view(detail):
    st.header("Đề xuất và xác minh")
    approval, proposal = detail["approval"], detail["proposal"]
    label, color = STATUS[detail["incident"]["status"]]
    st.badge(label, color=color)
    agent = detail["agent"]
    decision = (agent or {}).get("decision") or {}
    if not proposal:
        if agent and agent["error"]:
            st.info(REASONS.get(agent["error"], agent["error"]))
        if guidance := DIAGNOSTIC_GUIDANCE.get(decision.get("hypothesis")):
            st.text(guidance)
        completed = agent and agent["phase"] in {"propose", "diagnosed", "need_human"}
        if st.button("Phân tích incident", key="investigate", disabled=bool(completed)):
            return "investigate"
        review_controls(None, None, detail["evidence"])
        return None
    plan = proposal["plan"]
    with st.container(border=True):
        st.subheader(f'{plan["runbook_id"]} · {RUNBOOK_NAMES[plan["runbook_id"]]}')
        st.caption(f'Phiên bản {plan["runbook_version"]} · Đích `{plan["target"]}`')
        if decision:
            st.write(REASONS.get(decision["hypothesis"], decision["hypothesis"]))
        change = proposal["change"]
        st.table([{"Tài nguyên": change["resource"], "Trước": change["before"], "Sau": change["after"]}],
                 hide_index=True, alt="Thay đổi dự kiến trước và sau")
        st.write(proposal["impact"])
        st.markdown(f'**Xác minh**  \n{proposal["verify"]}')
        st.markdown(f'**Rollback**  \n{proposal["rollback"]}')
        st.caption(f'Approval {proposal["approval_ttl_seconds"] // 60} phút · '
                   f'Hết hạn {utc_label(approval["expires_at"])} UTC')
        with st.expander("Hash và điều kiện trước khi chạy"):
            st.code(proposal["plan_hash"], language=None)
            st.write(proposal["precheck"])
    action = review_controls(proposal, approval, detail["evidence"])
    show_result(approval, detail["audit"])
    return action


def request(client, method, path, **options):
    response = client.request(method, path, **options)
    response.raise_for_status()
    return response.json()


def render(client):
    st.title("CondoNet · Bàn xử lý sự cố")
    try:
        show_topology(request(client, "GET", "/topology"))
        selected = incident_table(request(client, "GET", "/incidents"))
        if selected is None:
            return
        endpoint = f"/incidents/{selected}"
        detail = request(client, "GET", endpoint)
        evidence_view(detail)
        action = proposal_view(detail)
        if action == "investigate":
            with st.spinner("Đang phân tích bằng chứng"):
                request(client, "POST", f"{endpoint}/investigate", timeout=180)
            st.rerun()
        if action in {"approve", "reject"}:
            request(client, "POST", f"{endpoint}/{action}", json={"plan_hash": detail["proposal"]["plan_hash"]})
            st.rerun()
    except httpx.HTTPStatusError as error:
        st.error(f"API trả mã {error.response.status_code}. Làm mới dữ liệu trước khi thử lại.")
    except httpx.RequestError:
        st.error("Không kết nối được FastAPI trên VM. Kiểm tra dịch vụ và làm mới dữ liệu.")


def main():
    st.set_page_config(page_title="CondoNet · Incidents", page_icon=":material/hub:", layout="wide")
    port = int(os.environ.get("CONDONET_API_PORT", "8080"))
    token = os.environ.get("CONDONET_OPERATOR_TOKEN", "")
    with httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False, timeout=8,
                      headers={"Authorization": f"Bearer {token}"} if token else {}) as client:
        render(client)


if __name__ == "__main__":
    main()
