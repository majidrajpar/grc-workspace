import re
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from grc_app.clock import notice_window
from grc_app.db import DEMO_ADMIN_EMAIL, DEMO_ADMIN_PASSWORD, DEMO_MEMBER_EMAIL, DEMO_MEMBER_PASSWORD
from grc_app.main import create_app


def token(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match
    return match.group(1)


def login(client: TestClient, email: str, password: str) -> None:
    page = client.get("/login")
    response = client.post(
        "/login",
        data={"csrf_token": token(page.text), "email": email, "password": password},
    )
    assert response.status_code == 200
    assert "Open tasks" in response.text


@pytest.fixture
def client(tmp_path: pytest.TempPathFactory) -> TestClient:
    app = create_app(tmp_path / "grc.sqlite")  # type: ignore[operator]
    with TestClient(app) as test_client:
        yield test_client


def test_dashboard_shows_what_needs_attention(client: TestClient) -> None:
    login(client, DEMO_ADMIN_EMAIL, DEMO_ADMIN_PASSWORD)
    fresh = client.get("/")
    assert "Needs attention" in fresh.text
    assert "Cybersecurity risk methodology" in fresh.text
    assert "Nothing needs attention." not in fresh.text

    assets = client.get("/assets/new")
    created_asset = client.post(
        "/assets/new",
        data={
            "csrf_token": token(assets.text),
            "name": "Billing process",
            "kind": "process",
            "description": "Monthly billing.",
        },
    )
    asset_id = re.search(r'href="/assets/(\d+)"', created_asset.text).group(1)
    risks = client.get("/risks/new")
    client.post(
        "/risks/new",
        data={
            "csrf_token": token(risks.text),
            "title": "Unowned billing change",
            "asset_id": asset_id,
            "threat": "A billing change ships without review.",
            "trigger": "change",
            "response": "mitigate",
            "treatment": "Name an owner before release.",
            "residual_summary": "Owner still missing.",
            "appetite_note": "Outside appetite until accepted.",
            "owner_acceptance": "Pending the finance lead.",
            "owner_role": "Finance lead",
        },
    )
    tasks = client.get("/tasks/new")
    client.post(
        "/tasks/new",
        data={
            "csrf_token": token(tasks.text),
            "title": "File the old treatment plan",
            "owner": "Security lead",
            "due_on": "2020-01-02",
            "closes_gap": "The plan was never filed.",
        },
    )
    discovered = datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M")
    incidents = client.get("/incidents/new")
    client.post(
        "/incidents/new",
        data={
            "csrf_token": token(incidents.text),
            "title": "Open mailbox forward",
            "summary": "A mailbox is still forwarding.",
            "response_authority": "Security lead",
            "response_and_recovery": "Forward still in place.",
            "lessons_learned": "Check forwards the same day.",
            "may_harm": "yes",
            "discovered_at": discovered,
            "circumstances": "External auto-forward found today.",
            "data_categories": "employee contact details",
            "approximate_record_count": "3",
            "risks": "Contact details can be read outside the company.",
            "measures": "Review is underway.",
            "data_subjects_notified": "unknown",
            "controller_contact": "privacy@example.com",
            "dpo_contact": "dpo@example.com",
            "advice_to_subjects": "Watch for unusual mail.",
        },
    )

    board = client.get("/")
    assert "File the old treatment plan" in board.text
    assert "Unowned billing change" in board.text
    assert "Open mailbox forward" in board.text
    assert "Inside the 72-hour notice window" in board.text
    assert "Overdue tasks" in board.text


def test_forms_have_no_draft_control(client: TestClient) -> None:
    login(client, DEMO_ADMIN_EMAIL, DEMO_ADMIN_PASSWORD)
    page = client.get("/policies/new")
    assert "Fill draft" not in page.text
    assert "Draft with AI" not in page.text
    missing = client.post("/ai/policy", data={"prompt": "Write a policy."})
    assert missing.status_code == 404


def test_about_page_names_the_author(client: TestClient) -> None:
    page = client.get("/about")
    assert page.status_code == 200
    assert "Majid Mumtaz" in page.text
    assert "Director of Internal Audit and Risk Advisory." in page.text
    assert "https://www.linkedin.com/in/majid-m-4b097118/" in page.text
    assert "https://github.com/majidrajpar" in page.text
    login(client, DEMO_ADMIN_EMAIL, DEMO_ADMIN_PASSWORD)
    assert 'href="/about"' in client.get("/").text


def test_notice_window_closes_after_72_hours() -> None:
    start = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert notice_window(start, start + timedelta(hours=72)) == "Inside the 72-hour notice window"
    assert notice_window(start, start + timedelta(hours=72, seconds=1)) == "Past the 72-hour notice window"


def test_registers_roles_and_export(client: TestClient) -> None:
    anonymous = client.get("/policies")
    assert "Sign in" in anonymous.text

    login(client, DEMO_ADMIN_EMAIL, DEMO_ADMIN_PASSWORD)
    home = client.get("/")
    csrf = token(home.text)
    renamed = client.post("/organization", data={"csrf_token": csrf, "name": "Example Co"})
    assert "Example Co" in renamed.text

    policies = client.get("/policies/new")
    saved = client.post(
        "/policies/new",
        data={
            "csrf_token": token(policies.text),
            "title": "Acceptable use",
            "purpose": "Tell staff how systems may be used.",
            "statements": "Use company accounts for company work.",
            "audience": "All staff",
            "framework_refs": "nca-ecc",
        },
    )
    assert "Acceptable use" in saved.text

    missing = client.post(
        "/policies/new",
        data={"csrf_token": token(client.get("/policies/new").text), "title": "", "purpose": "", "statements": "", "audience": ""},
    )
    assert missing.status_code == 400
    assert "Title is required." in missing.text

    assets = client.get("/assets/new")
    client.post(
        "/assets/new",
        data={
            "csrf_token": token(assets.text),
            "name": "Payroll service",
            "kind": "third_party",
            "description": "Hosted payroll.",
        },
    )
    risks = client.get("/risks/new")
    asset_id = re.search(r'value="(\d+)"[^>]*>Payroll service', risks.text).group(1)
    risk = client.post(
        "/risks/new",
        data={
            "csrf_token": token(risks.text),
            "title": "Shared payroll account",
            "asset_id": asset_id,
            "threat": "A supplier account is misused.",
            "trigger": "outsourcing",
            "response": "mitigate",
            "treatment": "Require named accounts before the contract.",
            "residual_summary": "The supplier may still share a password.",
            "appetite_note": "Outside appetite until the review is accepted.",
            "owner_role": "Finance lead",
            "owner_acceptance": "The finance lead accepts the residual risk after the review.",
            "accepted": "yes",
        },
    )
    assert "Shared payroll account" in risk.text

    controls = client.get("/controls")
    control_path = re.search(r'href="(/controls/\d+)"', controls.text).group(1)
    control = client.get(control_path)
    client.post(
        control_path,
        data={
            "csrf_token": token(control.text),
            "applicable": "yes",
            "status": "partial",
            "evidence_needed": "Current risk register",
            "gap": "The register has no treatment plan.",
        },
    )
    evidence = client.post(
        f"{control_path}/evidence",
        data={"csrf_token": token(client.get(control_path).text), "note": "Register export from October."},
        files={"file": ("register.txt", b"treatment missing", "text/plain")},
    )
    download = re.search(r'href="(/evidence/\d+)"', evidence.text)
    assert download
    assert client.get(download.group(1)).content == b"treatment missing"

    tasks = client.get("/tasks/new")
    client.post(
        "/tasks/new",
        data={
            "csrf_token": token(tasks.text),
            "title": "Add treatment plans",
            "owner": "Security lead",
            "due_on": "2026-10-18",
            "closes_gap": "NCA ECC 1-5-2 treatment plan is missing.",
        },
    )

    incidents = client.get("/incidents/new")
    created = client.post(
        "/incidents/new",
        data={
            "csrf_token": token(incidents.text),
            "title": "Mailbox exposure",
            "summary": "A shared mailbox was forwarded outside the company.",
            "response_authority": "Security lead",
            "response_and_recovery": "The forward was removed.",
            "lessons_learned": "Shared mailboxes need an owner.",
            "may_harm": "yes",
            "discovered_at": "2020-01-01T08:00",
            "circumstances": "External auto-forward.",
            "data_categories": "employee contact details",
            "approximate_record_count": "12",
            "risks": "Contact details could be read outside the company.",
            "measures": "Forward removed.",
            "data_subjects_notified": "no",
            "controller_contact": "privacy@example.com",
            "dpo_contact": "dpo@example.com",
            "advice_to_subjects": "Watch for unusual mail.",
        },
    )
    incident_path = re.search(r'href="(/incidents/\d+)"', created.text).group(1)
    detail = client.get(incident_path)
    assert "Past the 72-hour notice window" in detail.text

    blocked = client.post(
        "/suppliers/new",
        data={
            "csrf_token": token(client.get("/suppliers/new").text),
            "name": "Payroll Co",
            "service": "Payroll",
            "findings": "No named accounts.",
            "decision": "stop",
            "questionnaire_basis": "sama-csf",
        },
    )
    assert blocked.status_code == 400
    assert "before the contract" in blocked.text

    supplier = client.post(
        "/suppliers/new",
        data={
            "csrf_token": token(client.get("/suppliers/new").text),
            "name": "Payroll Co",
            "service": "Payroll",
            "reviewed_before_contract": "yes",
            "findings": "No named accounts.",
            "decision": "proceed_with_conditions",
            "questionnaire_basis": "sama-csf",
        },
    )
    assert "Payroll Co" in supplier.text

    report = client.get("/reports")
    assert "Example Co" in report.text
    assert "Acceptable use" in report.text
    csv = client.get("/reports.csv")
    assert "Acceptable use" in csv.text
    assert "Payroll Co" in csv.text

    client.post("/logout", data={"csrf_token": token(client.get("/").text)})
    login(client, DEMO_MEMBER_EMAIL, DEMO_MEMBER_PASSWORD)
    forbidden = client.get("/people")
    assert forbidden.status_code == 403
    policy_page = client.get("/policies")
    policy_id = re.search(r'href="/policies/(\d+)"', policy_page.text).group(1)
    denied = client.post(
        f"/policies/{policy_id}/delete",
        data={"csrf_token": token(client.get("/account").text)},
    )
    assert denied.status_code == 403
