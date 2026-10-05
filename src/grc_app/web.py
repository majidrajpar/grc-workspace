"""Pages for the single-organization GRC workspace."""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import date, datetime
from pathlib import Path

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from grc_app.choices import (
    FrameworkId,
    ImplementationStatus,
    RiskResponse,
    RiskTrigger,
    SupplierDecision,
)
from grc_app.clock import notice_window
from grc_app.db import (
    counts,
    dump_json,
    hash_password,
    load_json,
    now_iso,
    organization_name,
    password_matches,
)

router = APIRouter()
TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
TEMPLATES.env.auto_reload = True
MAX_UPLOAD_BYTES = 10 * 1024 * 1024

FRAMEWORKS = [
    (FrameworkId.NCA_ECC.value, "NCA ECC"),
    (FrameworkId.SAMA_CSF.value, "SAMA CSF"),
    (FrameworkId.KSA_PDPL.value, "Saudi PDPL"),
]
ASSET_KINDS = [
    ("asset", "Asset"),
    ("third_party", "Third party"),
    ("business_unit", "Business unit"),
    ("process", "Process"),
]
TRIGGERS = [(item.value, item.value.replace("_", " ")) for item in RiskTrigger]
RESPONSES = [(item.value, item.value) for item in RiskResponse]
STATUSES = [(item.value, item.value.replace("_", " ")) for item in ImplementationStatus]
DECISIONS = [(item.value, item.value.replace("_", " ")) for item in SupplierDecision]
NOTIFY_CHOICES = [("yes", "Yes"), ("no", "No"), ("unknown", "Not recorded")]


class LoginRequired(Exception):
    pass


class Forbidden(Exception):
    pass


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        from secrets import token_urlsafe

        token = token_urlsafe(32)
        request.session["csrf"] = token
    return token


def check_csrf(request: Request, form: object) -> None:
    sent = str(form.get("csrf_token") or "")  # type: ignore[attr-defined]
    if not sent or sent != request.session.get("csrf"):
        raise HTTPException(status_code=400, detail="This form expired. Reload the page and try again.")


def flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def render(request: Request, name: str, status_code: int = 200, **context: object) -> Response:
    context.setdefault("csrf", csrf_token(request))
    context.setdefault("user", context.get("user"))
    context.setdefault("frameworks", FRAMEWORKS)
    if request.method == "GET":
        context["flash"] = request.session.pop("flash", None)
    else:
        context.setdefault("flash", None)
    return TEMPLATES.TemplateResponse(request, name, context, status_code=status_code)


def require_user(request: Request, conn: sqlite3.Connection) -> sqlite3.Row:
    user_id = request.session.get("user_id")
    if not user_id:
        raise LoginRequired
    user = conn.execute("select * from users where id = ?", (user_id,)).fetchone()
    if user is None:
        request.session.clear()
        raise LoginRequired
    return user


def require_admin(user: sqlite3.Row) -> None:
    if user["role"] != "admin":
        raise Forbidden


def open_conn(request: Request) -> sqlite3.Connection:
    from grc_app.db import connect

    return connect(request.app.state.db_path)


def evidence_dir(request: Request) -> Path:
    path = Path(request.app.state.db_path).parent / "evidence"
    path.mkdir(parents=True, exist_ok=True)
    return path


def text(form: object, name: str) -> str:
    return str(form.get(name) or "").strip()  # type: ignore[attr-defined]


def lines(form: object, name: str) -> list[str]:
    return [line.strip() for line in text(form, name).splitlines() if line.strip()]


def checked_values(form: object, name: str) -> list[str]:
    values = form.getlist(name)  # type: ignore[attr-defined]
    return [str(value) for value in values]


def one_of(value: str, allowed: list[tuple[str, str]], label: str, errors: list[str]) -> str:
    keys = {item[0] for item in allowed}
    if value not in keys:
        errors.append(f"{label} is required.")
        return allowed[0][0]
    return value


def parse_when(value: str, errors: list[str]) -> str | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        errors.append("Awareness time must be a date and time.")
        return None
    return parsed.replace(microsecond=0).isoformat(timespec="minutes")


def redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


@router.get("/about")
def about(request: Request) -> Response:
    conn = open_conn(request)
    try:
        user = None
        user_id = request.session.get("user_id")
        if user_id:
            user = conn.execute("select * from users where id = ?", (user_id,)).fetchone()
        return render(request, "about.html", user=user)
    finally:
        conn.close()


@router.get("/login")
def login_page(request: Request) -> Response:
    if request.session.get("user_id"):
        return redirect("/")
    return render(request, "login.html", errors=[])


@router.post("/login")
async def login_submit(request: Request) -> Response:
    form = await request.form()
    check_csrf(request, form)
    email = text(form, "email").lower()
    password = str(form.get("password") or "")
    conn = open_conn(request)
    try:
        user = conn.execute("select * from users where email = ?", (email,)).fetchone()
        if user is None or not password_matches(password, user["salt"], user["password_hash"]):
            return render(
                request,
                "login.html",
                status_code=400,
                errors=["Email or password does not match a person in this workspace."],
            )
        request.session["user_id"] = user["id"]
        return redirect("/")
    finally:
        conn.close()


@router.post("/logout")
async def logout(request: Request) -> Response:
    form = await request.form()
    check_csrf(request, form)
    request.session.clear()
    return redirect("/login")


@router.get("/")
def home(request: Request) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        return render(
            request,
            "home.html",
            user=user,
            organization=organization_name(conn),
            counts=counts(conn),
            attention=_attention(conn),
        )
    finally:
        conn.close()


def _attention(conn: sqlite3.Connection) -> dict[str, list[object]]:
    today = datetime.now().astimezone().date().isoformat()
    labels = dict(FRAMEWORKS)
    overdue = conn.execute(
        """
        select id, title, owner, due_on from tasks
        where done = 0 and due_on is not null and due_on != '' and due_on < ?
        order by due_on, id
        """,
        (today,),
    ).fetchall()
    open_tasks = conn.execute(
        """
        select id, title, owner, due_on from tasks
        where done = 0 and (due_on is null or due_on = '' or due_on >= ?)
        order by due_on is null, due_on, id
        """,
        (today,),
    ).fetchall()
    risks = conn.execute(
        """
        select id, title, owner_role from risks
        where accepted = 0
        order by updated_at desc, id desc
        """
    ).fetchall()
    controls = [
        {
            "id": row["id"],
            "title": row["title"],
            "framework": labels.get(row["framework"], row["framework"]),
            "control_id": row["control_id"],
            "status": row["status"].replace("_", " "),
        }
        for row in conn.execute(
            """
            select id, framework, control_id, title, status from controls
            where applicable = 1 and status in ('not_started', 'partial')
            order by framework, control_id
            """
        )
    ]
    breaches: list[dict[str, object]] = []
    for row in conn.execute(
        """
        select id, title, discovered_at, may_harm from incidents
        where may_harm = 1 and discovered_at is not null and discovered_at != ''
        order by discovered_at, id
        """
    ):
        clock = _clock_for(row["discovered_at"], row["may_harm"])
        if clock == "Inside the 72-hour notice window":
            breaches.append({"id": row["id"], "title": row["title"], "clock": clock})
    return {
        "overdue": overdue,
        "open_tasks": open_tasks,
        "risks": risks,
        "controls": controls,
        "breaches": breaches,
    }


@router.post("/organization")
async def rename_organization(request: Request) -> Response:
    form = await request.form()
    check_csrf(request, form)
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        require_admin(user)
        name = text(form, "name")
        if not name:
            flash(request, "Organization name is required.")
            return redirect("/")
        conn.execute("update organization set name = ? where id = 1", (name,))
        conn.commit()
        flash(request, "Organization name saved.")
        return redirect("/")
    finally:
        conn.close()


@router.get("/policies")
def policy_list(request: Request) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        rows = conn.execute("select * from policies order by updated_at desc, id desc").fetchall()
        return render(request, "policies.html", user=user, policies=rows)
    finally:
        conn.close()


@router.get("/policies/new")
def policy_new(request: Request) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        return render(request, "policy_form.html", user=user, policy=None, errors=[])
    finally:
        conn.close()


@router.post("/policies/new")
async def policy_create(request: Request) -> Response:
    return await _save_policy(request, None)


@router.get("/policies/{policy_id:int}")
def policy_edit(request: Request, policy_id: int) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        policy = conn.execute("select * from policies where id = ?", (policy_id,)).fetchone()
        if policy is None:
            raise HTTPException(status_code=404)
        return render(request, "policy_form.html", user=user, policy=_policy_view(policy), errors=[])
    finally:
        conn.close()


@router.post("/policies/{policy_id:int}")
async def policy_update(request: Request, policy_id: int) -> Response:
    return await _save_policy(request, policy_id)


async def _save_policy(request: Request, policy_id: int | None) -> Response:
    form = await request.form()
    check_csrf(request, form)
    errors: list[str] = []
    title = text(form, "title")
    purpose = text(form, "purpose")
    audience = text(form, "audience")
    statements = lines(form, "statements")
    refs = [value for value in checked_values(form, "framework_refs") if value in {item[0] for item in FRAMEWORKS}]
    if not title:
        errors.append("Title is required.")
    if not purpose:
        errors.append("Purpose is required.")
    if not audience:
        errors.append("Audience is required.")
    if not statements:
        errors.append("Add at least one statement.")
    payload = {
        "id": policy_id,
        "title": title,
        "purpose": purpose,
        "audience": audience,
        "statements": statements,
        "framework_refs": refs,
    }
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        if errors:
            return render(request, "policy_form.html", status_code=400, user=user, policy=payload, errors=errors)
        values = (title, purpose, dump_json(statements), audience, dump_json(refs), now_iso())
        if policy_id is None:
            conn.execute(
                """
                insert into policies (title, purpose, statements, audience, framework_refs, updated_at)
                values (?, ?, ?, ?, ?, ?)
                """,
                values,
            )
        else:
            existing = conn.execute("select id from policies where id = ?", (policy_id,)).fetchone()
            if existing is None:
                raise HTTPException(status_code=404)
            conn.execute(
                """
                update policies
                set title = ?, purpose = ?, statements = ?, audience = ?, framework_refs = ?, updated_at = ?
                where id = ?
                """,
                (*values, policy_id),
            )
        conn.commit()
        flash(request, "Policy saved.")
        return redirect("/policies")
    finally:
        conn.close()


def _policy_view(row: sqlite3.Row) -> dict[str, object]:
    return {
        "id": row["id"],
        "title": row["title"],
        "purpose": row["purpose"],
        "audience": row["audience"],
        "statements": load_json(row["statements"]),
        "framework_refs": load_json(row["framework_refs"]),
    }


@router.post("/policies/{policy_id:int}/delete")
async def policy_delete(request: Request, policy_id: int) -> Response:
    return await _delete(request, "policies", policy_id, "/policies", "Policy deleted.")


@router.get("/assets")
def asset_list(request: Request) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        rows = conn.execute("select * from assets order by name").fetchall()
        return render(request, "assets.html", user=user, assets=rows, kinds=dict(ASSET_KINDS))
    finally:
        conn.close()


@router.get("/assets/new")
def asset_new(request: Request) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        return render(request, "asset_form.html", user=user, asset=None, errors=[], kinds=ASSET_KINDS)
    finally:
        conn.close()


@router.post("/assets/new")
async def asset_create(request: Request) -> Response:
    return await _save_asset(request, None)


@router.get("/assets/{asset_id:int}")
def asset_edit(request: Request, asset_id: int) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        asset = conn.execute("select * from assets where id = ?", (asset_id,)).fetchone()
        if asset is None:
            raise HTTPException(status_code=404)
        return render(request, "asset_form.html", user=user, asset=asset, errors=[], kinds=ASSET_KINDS)
    finally:
        conn.close()


@router.post("/assets/{asset_id:int}")
async def asset_update(request: Request, asset_id: int) -> Response:
    return await _save_asset(request, asset_id)


async def _save_asset(request: Request, asset_id: int | None) -> Response:
    form = await request.form()
    check_csrf(request, form)
    errors: list[str] = []
    name = text(form, "name")
    kind = one_of(text(form, "kind"), ASSET_KINDS, "Kind", errors)
    description = text(form, "description")
    if not name:
        errors.append("Name is required.")
    payload = {"id": asset_id, "name": name, "kind": kind, "description": description}
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        if errors:
            return render(
                request, "asset_form.html", status_code=400, user=user, asset=payload, errors=errors, kinds=ASSET_KINDS
            )
        if asset_id is None:
            conn.execute(
                "insert into assets (name, kind, description) values (?, ?, ?)",
                (name, kind, description),
            )
        else:
            if conn.execute("select id from assets where id = ?", (asset_id,)).fetchone() is None:
                raise HTTPException(status_code=404)
            conn.execute(
                "update assets set name = ?, kind = ?, description = ? where id = ?",
                (name, kind, description, asset_id),
            )
        conn.commit()
        flash(request, "Asset saved.")
        return redirect("/assets")
    finally:
        conn.close()


@router.post("/assets/{asset_id:int}/delete")
async def asset_delete(request: Request, asset_id: int) -> Response:
    form = await request.form()
    check_csrf(request, form)
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        require_admin(user)
        in_use = conn.execute("select id from risks where asset_id = ?", (asset_id,)).fetchone()
        if in_use is not None:
            flash(request, "This asset is the context for a risk. Reassign that risk before deleting it.")
            return redirect("/assets")
        conn.execute("delete from assets where id = ?", (asset_id,))
        conn.commit()
        flash(request, "Asset deleted.")
        return redirect("/assets")
    finally:
        conn.close()


@router.get("/risks")
def risk_list(request: Request) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        rows = conn.execute(
            """
            select risks.*, assets.name as asset_name
            from risks join assets on assets.id = risks.asset_id
            order by risks.updated_at desc
            """
        ).fetchall()
        return render(request, "risks.html", user=user, risks=rows)
    finally:
        conn.close()


@router.get("/risks/new")
def risk_new(request: Request) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        assets = conn.execute("select id, name from assets order by name").fetchall()
        return render(request, "risk_form.html", user=user, risk=None, assets=assets, errors=[])
    finally:
        conn.close()


@router.post("/risks/new")
async def risk_create(request: Request) -> Response:
    return await _save_risk(request, None)


@router.get("/risks/{risk_id:int}")
def risk_edit(request: Request, risk_id: int) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        risk = conn.execute("select * from risks where id = ?", (risk_id,)).fetchone()
        if risk is None:
            raise HTTPException(status_code=404)
        assets = conn.execute("select id, name from assets order by name").fetchall()
        return render(request, "risk_form.html", user=user, risk=risk, assets=assets, errors=[])
    finally:
        conn.close()


@router.post("/risks/{risk_id:int}")
async def risk_update(request: Request, risk_id: int) -> Response:
    return await _save_risk(request, risk_id)


async def _save_risk(request: Request, risk_id: int | None) -> Response:
    form = await request.form()
    check_csrf(request, form)
    errors: list[str] = []
    title = text(form, "title")
    threat = text(form, "threat")
    treatment = text(form, "treatment")
    residual = text(form, "residual_summary")
    appetite = text(form, "appetite_note")
    acceptance = text(form, "owner_acceptance")
    owner_role = text(form, "owner_role")
    trigger = one_of(text(form, "trigger"), TRIGGERS, "Trigger", errors)
    response_name = one_of(text(form, "response"), RESPONSES, "Response", errors)
    asset_raw = text(form, "asset_id")
    accepted = 1 if form.get("accepted") == "yes" else 0
    if not title:
        errors.append("Title is required.")
    if not threat:
        errors.append("Threat is required.")
    if not treatment:
        errors.append("Treatment is required.")
    if not residual:
        errors.append("Residual risk is required.")
    if not appetite:
        errors.append("Appetite note is required.")
    if not acceptance:
        errors.append("Owner acceptance is required.")
    if not owner_role:
        errors.append("Owner role is required.")
    if not asset_raw.isdigit():
        errors.append("Choose the asset, supplier, business unit, or process this risk is about.")
        asset_id = 0
    else:
        asset_id = int(asset_raw)
    payload = {
        "id": risk_id,
        "title": title,
        "asset_id": asset_id,
        "threat": threat,
        "trigger": trigger,
        "response": response_name,
        "treatment": treatment,
        "residual_summary": residual,
        "appetite_note": appetite,
        "owner_acceptance": acceptance,
        "owner_role": owner_role,
        "accepted": accepted,
    }
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        assets = conn.execute("select id, name from assets order by name").fetchall()
        if asset_id and conn.execute("select id from assets where id = ?", (asset_id,)).fetchone() is None:
            errors.append("That asset is no longer in the workspace.")
        if errors:
            return render(
                request,
                "risk_form.html",
                status_code=400,
                user=user,
                risk=payload,
                assets=assets,
                errors=errors,
            )
        values = (
            title,
            asset_id,
            threat,
            trigger,
            response_name,
            treatment,
            residual,
            appetite,
            acceptance,
            owner_role,
            accepted,
            now_iso(),
        )
        if risk_id is None:
            conn.execute(
                """
                insert into risks (
                    title, asset_id, threat, trigger, response, treatment, residual_summary,
                    appetite_note, owner_acceptance, owner_role, accepted, updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
        else:
            if conn.execute("select id from risks where id = ?", (risk_id,)).fetchone() is None:
                raise HTTPException(status_code=404)
            conn.execute(
                """
                update risks set
                    title = ?, asset_id = ?, threat = ?, trigger = ?, response = ?, treatment = ?,
                    residual_summary = ?, appetite_note = ?, owner_acceptance = ?, owner_role = ?,
                    accepted = ?, updated_at = ?
                where id = ?
                """,
                (*values, risk_id),
            )
        conn.commit()
        flash(request, "Risk saved.")
        return redirect("/risks")
    finally:
        conn.close()


@router.post("/risks/{risk_id:int}/delete")
async def risk_delete(request: Request, risk_id: int) -> Response:
    return await _delete(request, "risks", risk_id, "/risks", "Risk deleted.")


@router.get("/controls")
def control_list(request: Request) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        rows = conn.execute(
            """
            select controls.*,
                (select count(*) from evidence where evidence.control_pk = controls.id) as evidence_count
            from controls order by framework, control_id
            """
        ).fetchall()
        return render(request, "controls.html", user=user, controls=rows, labels=dict(FRAMEWORKS))
    finally:
        conn.close()


@router.get("/controls/{control_id:int}")
def control_edit(request: Request, control_id: int) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        control = _control_or_404(conn, control_id)
        evidence = conn.execute(
            "select * from evidence where control_pk = ? order by id desc", (control_id,)
        ).fetchall()
        return render(
            request,
            "control_form.html",
            user=user,
            control=_control_view(control),
            evidence=evidence,
            errors=[],
        )
    finally:
        conn.close()


@router.post("/controls/{control_id:int}")
async def control_update(request: Request, control_id: int) -> Response:
    form = await request.form()
    check_csrf(request, form)
    errors: list[str] = []
    status = one_of(text(form, "status"), STATUSES, "Status", errors)
    gap = text(form, "gap")
    needed = lines(form, "evidence_needed")
    applicable = 1 if form.get("applicable") == "yes" else 0
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        control = _control_or_404(conn, control_id)
        view = _control_view(control)
        view.update(
            {
                "applicable": applicable,
                "status": status,
                "gap": gap,
                "evidence_needed": needed,
            }
        )
        if errors:
            evidence = conn.execute(
                "select * from evidence where control_pk = ? order by id desc", (control_id,)
            ).fetchall()
            return render(
                request,
                "control_form.html",
                status_code=400,
                user=user,
                control=view,
                evidence=evidence,
                errors=errors,
            )
        conn.execute(
            """
            update controls
            set applicable = ?, status = ?, evidence_needed = ?, gap = ?
            where id = ?
            """,
            (applicable, status, dump_json(needed), gap, control_id),
        )
        conn.commit()
        flash(request, "Control assessment saved.")
        return redirect("/controls")
    finally:
        conn.close()


@router.post("/controls/{control_id:int}/evidence")
async def evidence_create(request: Request, control_id: int) -> Response:
    form = await request.form()
    check_csrf(request, form)
    note = text(form, "note")
    errors: list[str] = []
    if not note:
        errors.append("Evidence needs a note describing what the file or statement shows.")
    upload = form.get("file")
    filename = ""
    payload = b""
    if upload is not None and getattr(upload, "filename", ""):
        filename = _safe_filename(str(upload.filename))
        payload = await upload.read()
        if len(payload) > MAX_UPLOAD_BYTES:
            errors.append("Evidence files must be 10 MB or smaller.")
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        control = _control_or_404(conn, control_id)
        if errors:
            evidence = conn.execute(
                "select * from evidence where control_pk = ? order by id desc", (control_id,)
            ).fetchall()
            return render(
                request,
                "control_form.html",
                status_code=400,
                user=user,
                control=_control_view(control),
                evidence=evidence,
                errors=errors,
            )
        stored_name = None
        if filename and payload:
            cursor = conn.execute(
                """
                insert into evidence (control_pk, note, filename, stored_name, created_at)
                values (?, ?, ?, '', ?)
                """,
                (control_id, note, filename, now_iso()),
            )
            evidence_id = cursor.lastrowid
            stored_name = f"{evidence_id}-{filename}"
            (evidence_dir(request) / stored_name).write_bytes(payload)
            conn.execute("update evidence set stored_name = ? where id = ?", (stored_name, evidence_id))
        else:
            conn.execute(
                """
                insert into evidence (control_pk, note, filename, stored_name, created_at)
                values (?, ?, null, null, ?)
                """,
                (control_id, note, now_iso()),
            )
        conn.commit()
        flash(request, "Evidence saved.")
        return redirect(f"/controls/{control_id}")
    finally:
        conn.close()


@router.get("/evidence/{evidence_id:int}")
def evidence_download(request: Request, evidence_id: int) -> Response:
    conn = open_conn(request)
    try:
        require_user(request, conn)
        row = conn.execute("select * from evidence where id = ?", (evidence_id,)).fetchone()
        if row is None or not row["stored_name"]:
            raise HTTPException(status_code=404)
        path = evidence_dir(request) / row["stored_name"]
        if not path.is_file():
            raise HTTPException(status_code=404)
        return FileResponse(path, filename=row["filename"] or row["stored_name"])
    finally:
        conn.close()


@router.post("/evidence/{evidence_id:int}/delete")
async def evidence_delete(request: Request, evidence_id: int) -> Response:
    form = await request.form()
    check_csrf(request, form)
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        require_admin(user)
        row = conn.execute("select * from evidence where id = ?", (evidence_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404)
        if row["stored_name"]:
            target = evidence_dir(request) / row["stored_name"]
            if target.is_file():
                target.unlink()
        conn.execute("delete from evidence where id = ?", (evidence_id,))
        conn.commit()
        flash(request, "Evidence deleted.")
        return redirect(f"/controls/{row['control_pk']}")
    finally:
        conn.close()


def _control_or_404(conn: sqlite3.Connection, control_id: int) -> sqlite3.Row:
    control = conn.execute("select * from controls where id = ?", (control_id,)).fetchone()
    if control is None:
        raise HTTPException(status_code=404)
    return control


def _control_view(row: sqlite3.Row) -> dict[str, object]:
    return {
        "id": row["id"],
        "framework": row["framework"],
        "control_id": row["control_id"],
        "title": row["title"],
        "tracks": row["tracks"],
        "applicable": row["applicable"],
        "status": row["status"],
        "gap": row["gap"],
        "evidence_needed": load_json(row["evidence_needed"]),
    }


def _safe_filename(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).name)
    return cleaned[:80] or "file"


@router.get("/tasks")
def task_list(request: Request) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        rows = conn.execute(
            "select * from tasks order by done, due_on is null, due_on, id desc"
        ).fetchall()
        return render(request, "tasks.html", user=user, tasks=rows)
    finally:
        conn.close()


@router.get("/tasks/new")
def task_new(request: Request) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        return render(request, "task_form.html", user=user, task=None, errors=[])
    finally:
        conn.close()


@router.post("/tasks/new")
async def task_create(request: Request) -> Response:
    return await _save_task(request, None)


@router.get("/tasks/{task_id:int}")
def task_edit(request: Request, task_id: int) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        task = conn.execute("select * from tasks where id = ?", (task_id,)).fetchone()
        if task is None:
            raise HTTPException(status_code=404)
        return render(request, "task_form.html", user=user, task=task, errors=[])
    finally:
        conn.close()


@router.post("/tasks/{task_id:int}")
async def task_update(request: Request, task_id: int) -> Response:
    return await _save_task(request, task_id)


async def _save_task(request: Request, task_id: int | None) -> Response:
    form = await request.form()
    check_csrf(request, form)
    errors: list[str] = []
    title = text(form, "title")
    owner = text(form, "owner")
    closes_gap = text(form, "closes_gap")
    due_on = text(form, "due_on")
    done = 1 if form.get("done") == "yes" else 0
    if not title:
        errors.append("Title is required.")
    if not owner:
        errors.append("Owner is required.")
    if not closes_gap:
        errors.append("Say which gap this task closes.")
    if due_on:
        try:
            date.fromisoformat(due_on)
        except ValueError:
            errors.append("Due date must be a calendar date.")
    else:
        due_on = ""
    payload = {
        "id": task_id,
        "title": title,
        "owner": owner,
        "due_on": due_on or None,
        "closes_gap": closes_gap,
        "done": done,
    }
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        if errors:
            return render(request, "task_form.html", status_code=400, user=user, task=payload, errors=errors)
        values = (title, owner, due_on or None, closes_gap, done, now_iso())
        if task_id is None:
            conn.execute(
                """
                insert into tasks (title, owner, due_on, closes_gap, done, updated_at)
                values (?, ?, ?, ?, ?, ?)
                """,
                values,
            )
        else:
            if conn.execute("select id from tasks where id = ?", (task_id,)).fetchone() is None:
                raise HTTPException(status_code=404)
            conn.execute(
                """
                update tasks set title = ?, owner = ?, due_on = ?, closes_gap = ?, done = ?, updated_at = ?
                where id = ?
                """,
                (*values, task_id),
            )
        conn.commit()
        flash(request, "Task saved.")
        return redirect("/tasks")
    finally:
        conn.close()


@router.post("/tasks/{task_id:int}/delete")
async def task_delete(request: Request, task_id: int) -> Response:
    return await _delete(request, "tasks", task_id, "/tasks", "Task deleted.")


@router.get("/incidents")
def incident_list(request: Request) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        rows = conn.execute("select * from incidents order by updated_at desc").fetchall()
        return render(request, "incidents.html", user=user, incidents=rows)
    finally:
        conn.close()


@router.get("/incidents/new")
def incident_new(request: Request) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        return render(request, "incident_form.html", user=user, incident=None, errors=[], clock=None)
    finally:
        conn.close()


@router.post("/incidents/new")
async def incident_create(request: Request) -> Response:
    return await _save_incident(request, None)


@router.get("/incidents/{incident_id:int}")
def incident_edit(request: Request, incident_id: int) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        incident = conn.execute("select * from incidents where id = ?", (incident_id,)).fetchone()
        if incident is None:
            raise HTTPException(status_code=404)
        return render(
            request,
            "incident_form.html",
            user=user,
            incident=_incident_view(incident),
            errors=[],
            clock=_clock_for(incident["discovered_at"], incident["may_harm"]),
        )
    finally:
        conn.close()


@router.post("/incidents/{incident_id:int}")
async def incident_update(request: Request, incident_id: int) -> Response:
    return await _save_incident(request, incident_id)


async def _save_incident(request: Request, incident_id: int | None) -> Response:
    form = await request.form()
    check_csrf(request, form)
    errors: list[str] = []
    title = text(form, "title")
    summary = text(form, "summary")
    authority = text(form, "response_authority")
    recovery = text(form, "response_and_recovery")
    lessons = text(form, "lessons_learned")
    may_harm = 1 if form.get("may_harm") == "yes" else 0
    discovered = parse_when(text(form, "discovered_at"), errors)
    categories = lines(form, "data_categories")
    count_raw = text(form, "approximate_record_count")
    count: int | None = None
    if count_raw:
        if not count_raw.isdigit():
            errors.append("Record count must be a whole number.")
        else:
            count = int(count_raw)
    notified = text(form, "data_subjects_notified") or "unknown"
    if notified not in {item[0] for item in NOTIFY_CHOICES}:
        errors.append("Say whether people were told.")
        notified = "unknown"
    if not title:
        errors.append("Title is required.")
    if not summary:
        errors.append("Summary is required.")
    if not authority:
        errors.append("Name who has authority to respond.")
    if not recovery:
        errors.append("Response and recovery are required.")
    if not lessons:
        errors.append("Lessons learned are required.")
    if may_harm:
        if not discovered:
            errors.append("A personal-data breach needs the time the team became aware.")
        if not categories:
            errors.append("List the personal-data categories.")
        if not text(form, "circumstances"):
            errors.append("Describe the circumstances.")
        if not text(form, "risks"):
            errors.append("Describe the risks to people.")
        if not text(form, "measures"):
            errors.append("Describe the measures taken.")
        if not text(form, "controller_contact"):
            errors.append("Controller contact is required for the authority notice.")
    payload = {
        "id": incident_id,
        "title": title,
        "summary": summary,
        "response_authority": authority,
        "response_and_recovery": recovery,
        "lessons_learned": lessons,
        "may_harm": may_harm,
        "discovered_at": discovered or "",
        "circumstances": text(form, "circumstances"),
        "data_categories": categories,
        "approximate_record_count": count,
        "risks": text(form, "risks"),
        "measures": text(form, "measures"),
        "data_subjects_notified": notified,
        "controller_contact": text(form, "controller_contact"),
        "dpo_contact": text(form, "dpo_contact"),
        "advice_to_subjects": text(form, "advice_to_subjects"),
    }
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        if errors:
            return render(
                request,
                "incident_form.html",
                status_code=400,
                user=user,
                incident=payload,
                errors=errors,
                clock=None,
            )
        values = (
            title,
            summary,
            authority,
            recovery,
            lessons,
            may_harm,
            discovered,
            payload["circumstances"],
            dump_json(categories),
            count,
            payload["risks"],
            payload["measures"],
            notified,
            payload["controller_contact"],
            payload["dpo_contact"],
            payload["advice_to_subjects"],
            now_iso(),
        )
        if incident_id is None:
            conn.execute(
                """
                insert into incidents (
                    title, summary, response_authority, response_and_recovery, lessons_learned,
                    may_harm, discovered_at, circumstances, data_categories, approximate_record_count,
                    risks, measures, data_subjects_notified, controller_contact, dpo_contact,
                    advice_to_subjects, updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
        else:
            if conn.execute("select id from incidents where id = ?", (incident_id,)).fetchone() is None:
                raise HTTPException(status_code=404)
            conn.execute(
                """
                update incidents set
                    title = ?, summary = ?, response_authority = ?, response_and_recovery = ?,
                    lessons_learned = ?, may_harm = ?, discovered_at = ?, circumstances = ?,
                    data_categories = ?, approximate_record_count = ?, risks = ?, measures = ?,
                    data_subjects_notified = ?, controller_contact = ?, dpo_contact = ?,
                    advice_to_subjects = ?, updated_at = ?
                where id = ?
                """,
                (*values, incident_id),
            )
        conn.commit()
        flash(request, "Incident saved.")
        return redirect("/incidents")
    finally:
        conn.close()


def _incident_view(row: sqlite3.Row) -> dict[str, object]:
    data = dict(row)
    data["data_categories"] = load_json(row["data_categories"])
    data["discovered_at"] = (row["discovered_at"] or "").replace(" ", "T")
    return data


def _clock_for(discovered_at: str | None, may_harm: int) -> str | None:
    if not may_harm or not discovered_at:
        return None
    parsed = datetime.fromisoformat(discovered_at)
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    return notice_window(parsed, datetime.now().astimezone())


@router.post("/incidents/{incident_id:int}/delete")
async def incident_delete(request: Request, incident_id: int) -> Response:
    return await _delete(request, "incidents", incident_id, "/incidents", "Incident deleted.")


@router.get("/suppliers")
def supplier_list(request: Request) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        rows = conn.execute("select * from suppliers order by name").fetchall()
        return render(request, "suppliers.html", user=user, suppliers=rows)
    finally:
        conn.close()


@router.get("/suppliers/new")
def supplier_new(request: Request) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        return render(request, "supplier_form.html", user=user, supplier=None, errors=[])
    finally:
        conn.close()


@router.post("/suppliers/new")
async def supplier_create(request: Request) -> Response:
    return await _save_supplier(request, None)


@router.get("/suppliers/{supplier_id:int}")
def supplier_edit(request: Request, supplier_id: int) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        supplier = conn.execute("select * from suppliers where id = ?", (supplier_id,)).fetchone()
        if supplier is None:
            raise HTTPException(status_code=404)
        return render(
            request, "supplier_form.html", user=user, supplier=_supplier_view(supplier), errors=[]
        )
    finally:
        conn.close()


@router.post("/suppliers/{supplier_id:int}")
async def supplier_update(request: Request, supplier_id: int) -> Response:
    return await _save_supplier(request, supplier_id)


async def _save_supplier(request: Request, supplier_id: int | None) -> Response:
    form = await request.form()
    check_csrf(request, form)
    errors: list[str] = []
    name = text(form, "name")
    service = text(form, "service")
    findings = lines(form, "findings")
    decision = one_of(text(form, "decision"), DECISIONS, "Decision", errors)
    basis = [value for value in checked_values(form, "questionnaire_basis") if value in {item[0] for item in FRAMEWORKS}]
    before = form.get("reviewed_before_contract") == "yes"
    if not name:
        errors.append("Supplier name is required.")
    if not service:
        errors.append("Service is required.")
    if not findings:
        errors.append("Record at least one finding.")
    if not basis:
        errors.append("Choose the questionnaire basis.")
    if not before:
        errors.append("This workspace only stores a supplier review done before the contract.")
    payload = {
        "id": supplier_id,
        "name": name,
        "service": service,
        "findings": findings,
        "decision": decision,
        "questionnaire_basis": basis,
        "reviewed_before_contract": 1 if before else 0,
    }
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        if errors:
            return render(
                request, "supplier_form.html", status_code=400, user=user, supplier=payload, errors=errors
            )
        values = (name, service, dump_json(basis), dump_json(findings), decision, now_iso())
        if supplier_id is None:
            conn.execute(
                """
                insert into suppliers (
                    name, service, reviewed_before_contract, questionnaire_basis, findings, decision, updated_at
                ) values (?, ?, 1, ?, ?, ?, ?)
                """,
                values,
            )
        else:
            if conn.execute("select id from suppliers where id = ?", (supplier_id,)).fetchone() is None:
                raise HTTPException(status_code=404)
            conn.execute(
                """
                update suppliers
                set name = ?, service = ?, questionnaire_basis = ?, findings = ?, decision = ?, updated_at = ?
                where id = ?
                """,
                (*values, supplier_id),
            )
        conn.commit()
        flash(request, "Supplier review saved.")
        return redirect("/suppliers")
    finally:
        conn.close()


def _supplier_view(row: sqlite3.Row) -> dict[str, object]:
    return {
        "id": row["id"],
        "name": row["name"],
        "service": row["service"],
        "findings": load_json(row["findings"]),
        "decision": row["decision"],
        "questionnaire_basis": load_json(row["questionnaire_basis"]),
        "reviewed_before_contract": row["reviewed_before_contract"],
    }


@router.post("/suppliers/{supplier_id:int}/delete")
async def supplier_delete(request: Request, supplier_id: int) -> Response:
    return await _delete(request, "suppliers", supplier_id, "/suppliers", "Supplier review deleted.")


@router.get("/reports")
def report_page(request: Request) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        return render(request, "report.html", user=user, report=_report(conn))
    finally:
        conn.close()


@router.get("/reports.csv")
def report_csv(request: Request) -> Response:
    conn = open_conn(request)
    try:
        require_user(request, conn)
        return Response(
            _report_csv(conn),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="grc-workspace.csv"'},
        )
    finally:
        conn.close()


def _report(conn: sqlite3.Connection) -> dict[str, object]:
    return {
        "organization": organization_name(conn),
        "policies": [
            _policy_view(row)
            for row in conn.execute("select * from policies order by title").fetchall()
        ],
        "assets": conn.execute("select * from assets order by name").fetchall(),
        "risks": conn.execute(
            """
            select risks.*, assets.name as asset_name
            from risks join assets on assets.id = risks.asset_id
            order by risks.title
            """
        ).fetchall(),
        "controls": [
            _control_view(row)
            for row in conn.execute("select * from controls order by framework, control_id").fetchall()
        ],
        "tasks": conn.execute("select * from tasks order by done, title").fetchall(),
        "incidents": [
            _incident_view(row)
            for row in conn.execute("select * from incidents order by title").fetchall()
        ],
        "suppliers": [
            _supplier_view(row)
            for row in conn.execute("select * from suppliers order by name").fetchall()
        ],
    }


def _csv_cell(value: object) -> str:
    text_value = "" if value is None else str(value)
    if any(character in text_value for character in ",\"\n"):
        return '"' + text_value.replace('"', '""') + '"'
    return text_value


def _report_csv(conn: sqlite3.Connection) -> str:
    report = _report(conn)
    lines_out = [f"organization,{_csv_cell(report['organization'])}", ""]
    lines_out.append("policies")
    lines_out.append("title,audience,purpose")
    for policy in report["policies"]:  # type: ignore[union-attr]
        lines_out.append(
            ",".join(_csv_cell(policy[key]) for key in ("title", "audience", "purpose"))
        )
    lines_out.extend(["", "risks", "title,asset,trigger,response,accepted"])
    for risk in report["risks"]:  # type: ignore[union-attr]
        lines_out.append(
            ",".join(
                _csv_cell(risk[key]) for key in ("title", "asset_name", "trigger", "response", "accepted")
            )
        )
    lines_out.extend(["", "controls", "framework,control_id,applicable,status,gap"])
    for control in report["controls"]:  # type: ignore[union-attr]
        lines_out.append(
            ",".join(
                _csv_cell(control[key])
                for key in ("framework", "control_id", "applicable", "status", "gap")
            )
        )
    lines_out.extend(["", "tasks", "title,owner,due_on,done,closes_gap"])
    for task in report["tasks"]:  # type: ignore[union-attr]
        lines_out.append(
            ",".join(_csv_cell(task[key]) for key in ("title", "owner", "due_on", "done", "closes_gap"))
        )
    lines_out.extend(["", "incidents", "title,response_authority,may_harm,discovered_at"])
    for incident in report["incidents"]:  # type: ignore[union-attr]
        lines_out.append(
            ",".join(
                _csv_cell(incident[key])
                for key in ("title", "response_authority", "may_harm", "discovered_at")
            )
        )
    lines_out.extend(["", "suppliers", "name,service,decision"])
    for supplier in report["suppliers"]:  # type: ignore[union-attr]
        lines_out.append(",".join(_csv_cell(supplier[key]) for key in ("name", "service", "decision")))
    return "\n".join(lines_out) + "\n"


@router.get("/people")
def people(request: Request) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        require_admin(user)
        rows = conn.execute("select id, email, name, role from users order by name").fetchall()
        return render(request, "people.html", user=user, people=rows, errors=[])
    finally:
        conn.close()


@router.post("/people")
async def people_create(request: Request) -> Response:
    form = await request.form()
    check_csrf(request, form)
    errors: list[str] = []
    email = text(form, "email").lower()
    name = text(form, "name")
    password = str(form.get("password") or "")
    role = text(form, "role")
    if "@" not in email:
        errors.append("Email is required.")
    if not name:
        errors.append("Name is required.")
    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    if role not in {"admin", "member"}:
        errors.append("Role is required.")
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        require_admin(user)
        if conn.execute("select id from users where email = ?", (email,)).fetchone() is not None:
            errors.append("That email is already in this workspace.")
        rows = conn.execute("select id, email, name, role from users order by name").fetchall()
        if errors:
            return render(request, "people.html", status_code=400, user=user, people=rows, errors=errors)
        salt, digest = hash_password(password)
        conn.execute(
            "insert into users (email, name, salt, password_hash, role) values (?, ?, ?, ?, ?)",
            (email, name, salt, digest, role),
        )
        conn.commit()
        flash(request, "Person added.")
        return redirect("/people")
    finally:
        conn.close()


@router.get("/account")
def account(request: Request) -> Response:
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        return render(request, "account.html", user=user, errors=[])
    finally:
        conn.close()


@router.post("/account")
async def account_update(request: Request) -> Response:
    form = await request.form()
    check_csrf(request, form)
    password = str(form.get("password") or "")
    errors: list[str] = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        if errors:
            return render(request, "account.html", status_code=400, user=user, errors=errors)
        salt, digest = hash_password(password)
        conn.execute(
            "update users set salt = ?, password_hash = ? where id = ?",
            (salt, digest, user["id"]),
        )
        conn.commit()
        flash(request, "Password changed.")
        return redirect("/account")
    finally:
        conn.close()


async def _delete(request: Request, table: str, row_id: int, dest: str, message: str) -> Response:
    if table not in {"policies", "risks", "tasks", "incidents", "suppliers"}:
        raise HTTPException(status_code=404)
    form = await request.form()
    check_csrf(request, form)
    conn = open_conn(request)
    try:
        user = require_user(request, conn)
        require_admin(user)
        conn.execute(f"delete from {table} where id = ?", (row_id,))
        conn.commit()
        flash(request, message)
        return redirect(dest)
    finally:
        conn.close()


def install_handlers(app: FastAPI) -> None:
    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, exc: LoginRequired) -> Response:
        del exc
        return redirect("/login")

    @app.exception_handler(Forbidden)
    async def _forbidden(request: Request, exc: Forbidden) -> Response:
        del exc
        conn = open_conn(request)
        try:
            user = None
            user_id = request.session.get("user_id")
            if user_id:
                user = conn.execute("select * from users where id = ?", (user_id,)).fetchone()
            return render(request, "forbidden.html", status_code=403, user=user)
        finally:
            conn.close()


def template_filters() -> None:
    def join_lines(value: object) -> str:
        if isinstance(value, list):
            return "\n".join(str(item) for item in value)
        return ""

    def parse_list(value: object) -> list[str]:
        if isinstance(value, list):
            return [str(item) for item in value]
        if isinstance(value, str) and value:
            try:
                return load_json(value)
            except json.JSONDecodeError:
                return []
        return []

    TEMPLATES.env.filters["join_lines"] = join_lines
    TEMPLATES.env.filters["parse_list"] = parse_list


template_filters()
