import streamlit as st

from runner.plans import review_blockers


def review_controls(proposal, approval, evidence, now=None):
    blockers = review_blockers(proposal, approval, evidence, now)
    if blockers and (not approval or approval.get("status") in {"pending", "approved"}):
        st.warning(" · ".join(blockers))
    with st.container(horizontal=True, gap="small"):
        approve = st.button("Duyệt và chạy", key="approve", type="primary", disabled=bool(blockers))
        reject = st.button("Từ chối", key="reject",
                           disabled=not approval or approval.get("status") != "pending")
    if approve:
        return "approve"
    if reject:
        return "reject"
    return None
