import os
from threading import Thread

import httpx
from fastapi.testclient import TestClient
from streamlit.testing.v1 import AppTest

from app.api import ApiSettings, create_app
from app.approvals import ApprovalStore
from runner.action_socket import ActionServer
from runner.policy import RunnerPolicy
from test_incident_api import ObservedModel, seed_incidents


HEADERS = {"Authorization": "Bearer fixture"}


def render_app(client):
    from ui.app import render

    render(client)


def app_session(client):
    return AppTest.from_function(render_app, args=(client,), default_timeout=10).run()


def settings(tmp_path):
    return ApiSettings(tmp_path / "a.sqlite", tmp_path / "a.sock", "operator",
                       "fixture", tmp_path / "incidents.sqlite")


def test_ui_handles_empty_state_and_api_error(tmp_path):
    with TestClient(create_app(settings(tmp_path)), headers=HEADERS) as api:
        screen = app_session(api)
        assert not screen.exception and any("Không có incident" in row.value for row in screen.info)

    def offline(request):
        raise httpx.ConnectError("offline", request=request)

    with httpx.Client(base_url="http://localhost", transport=httpx.MockTransport(offline)) as client:
        screen = app_session(client)
        assert not screen.exception and "Không kết nối được" in screen.error[0].value


def test_review_clicks_read_backend_state_and_dispatch_once(tmp_path):
    config = settings(tmp_path)
    incident = seed_incidents(config.incident_db)
    approvals = ApprovalStore(config.approval_db)
    with TestClient(create_app(config, ObservedModel()), headers=HEADERS) as api:
        url = f"/incidents/{incident.id}"
        ticket = api.post(f"{url}/investigate").json()["approval"]
        dispatched = []

        def verify(claimed):
            dispatched.append(claimed.id)
            approvals.finish(claimed, "verified", {})

        with ActionServer(config.action_socket, approvals, RunnerPolicy(config.lab), verify, os.getuid()) as server:
            worker = Thread(target=server.serve_forever)
            worker.start()
            try:
                screen = app_session(api)
                assert not screen.exception
                assert [element.value for element in screen.header] == [
                    "Topology", "Incidents", "Bằng chứng", "Đề xuất và xác minh"]
                assert any("DNS còn hoạt động" in element.value for element in screen.markdown)
                assert not screen.button(key="approve").disabled
                screen.button(key="approve").click().run()
                assert not screen.exception
                assert api.get(f"{url}/action").json()["approval"]["status"] == "verified"
                assert api.post(f"{url}/approve", json={"plan_hash": ticket["plan_hash"]}).is_success
                assert dispatched == [ticket["id"]]
            finally:
                server.shutdown()
                worker.join()


def test_ui_rejects_without_dispatching(tmp_path):
    config = settings(tmp_path)
    incident = seed_incidents(config.incident_db)
    with TestClient(create_app(config, ObservedModel()), headers=HEADERS) as api:
        assert api.post(f"/incidents/{incident.id}/investigate").is_success
        screen = app_session(api)
        screen.button(key="reject").click().run()
        assert not screen.exception
        assert screen.button(key="approve").disabled
        action = api.get(f"/incidents/{incident.id}/action").json()
        assert action["approval"]["status"] == "rejected"
        assert [row["event"] for row in action["audit"]] == ["pending", "rejected"]
