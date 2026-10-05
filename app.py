"""
Mock Leegality — a stand-in for Leegality's v3 Document Execution API.

It copies the request/response formats from Leegality's public docs
(https://knowledge.leegality.com/document-execution/api/document-execution-api)
so the Workato connector can be built and demoed without real API access.
Nothing here is legally binding: signing is simulated.

Endpoints (same paths as the real API, under /api/):
  POST /api/v3.0/sign/request             create eSigning request
  GET  /api/v3.3/document/details         document + invitee status
  GET  /api/v3.0/sign/request/list        list / search documents
  GET  /api/v3.3/document/fetchDocument   signed PDF / audit trail (temporary link)
Extra mock-only pages:
  GET  /sign/{token}      signing page the invitee opens (Sign / Reject)
  GET  /                  mock dashboard: documents, webhook log, settings
  GET  /health
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from html import escape
from typing import Optional

import httpx
from fastapi import FastAPI, Form, Header, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

# --------------------------------------------------------------------------- config
AUTH_TOKEN = os.getenv("MOCK_AUTH_TOKEN", "mock-auth-token")
PRIVATE_SALT = os.getenv("MOCK_PRIVATE_SALT", "mock-private-salt")
DB_PATH = os.getenv("MOCK_DB_PATH", "mock_leegality.db")
DEFAULT_WEBHOOK_URL = os.getenv("MOCK_WEBHOOK_URL", "")
CDN_TTL_SECONDS = int(os.getenv("MOCK_CDN_TTL_SECONDS", "15"))  # real Leegality: ~15 s
INVITE_VALID_DAYS = int(os.getenv("MOCK_INVITE_VALID_DAYS", "30"))
MAX_FILE_BYTES = 15 * 1024 * 1024  # 15 MB, as in the real API


def public_base(request: Request) -> str:
    # Render sets RENDER_EXTERNAL_URL; otherwise use PUBLIC_BASE_URL or the request host.
    url = os.getenv("PUBLIC_BASE_URL") or os.getenv("RENDER_EXTERNAL_URL") or str(request.base_url)
    return url.rstrip("/")


# --------------------------------------------------------------------------- storage
SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY, name TEXT, profile_id TEXT, irn TEXT, status TEXT,
  file_b64 TEXT, created_at TEXT, completed_at TEXT
);
CREATE TABLE IF NOT EXISTS invitees (
  token TEXT PRIMARY KEY, document_id TEXT, position INTEGER, name TEXT, email TEXT, phone TEXT,
  signed INTEGER DEFAULT 0, rejected INTEGER DEFAULT 0, rejection_message TEXT,
  sign_type TEXT, sign_date TEXT, expiry TEXT
);
CREATE TABLE IF NOT EXISTS cdn (
  token TEXT PRIMARY KEY, document_id TEXT, kind TEXT, expires REAL
);
CREATE TABLE IF NOT EXISTS webhooks (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, document_id TEXT, url TEXT,
  status_code INTEGER, error TEXT, payload TEXT
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
"""


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with db() as c:
        c.executescript(SCHEMA)


def get_setting(key: str, default: str = "") -> str:
    with db() as c:
        r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return r["value"] if r else default


def set_setting(key: str, value: str) -> None:
    with db() as c:
        c.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                  (key, value))


# --------------------------------------------------------------------------- helpers
def now() -> datetime:
    return datetime.now(timezone.utc)


def leegality_date(dt: Optional[str]) -> Optional[str]:
    """Leegality formats dates as DD-MM-YYYY HH:MM:SS."""
    if not dt:
        return None
    return datetime.fromisoformat(dt).strftime("%d-%m-%Y %H:%M:%S")


def new_document_id() -> str:
    # 26-char uppercase id, like the ULIDs Leegality returns (e.g. 01KJPV67NZQFX5P2JRTSPSFKYY)
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    return "".join(secrets.choice(alphabet) for _ in range(26))


def ok(data: dict, code: str = "success", message: str = "Success") -> JSONResponse:
    return JSONResponse({"status": 1, "messages": [{"code": code, "message": message}], "data": data})


def fail(code: str, message: str, http_status: int = 200) -> JSONResponse:
    # Real Leegality returns HTTP 200 with status 0 for validation/business errors.
    return JSONResponse({"status": 0, "messages": [{"code": code, "message": message}], "data": None},
                        status_code=http_status)


def check_auth(token: Optional[str]) -> Optional[JSONResponse]:
    if not token or not hmac.compare_digest(token, AUTH_TOKEN):
        return fail("auth.invalid", "Invalid or missing X-Auth-Token", http_status=401)
    return None


def compute_mac(document_id: str) -> str:
    return hmac.new(PRIVATE_SALT.encode(), document_id.encode(), hashlib.sha1).hexdigest()


def load_document(doc_id: str):
    with db() as c:
        d = c.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
        inv = c.execute("SELECT * FROM invitees WHERE document_id=? ORDER BY position", (doc_id,)).fetchall()
    return d, inv


def make_cdn_link(request: Request, doc_id: str, kind: str) -> str:
    token = secrets.token_urlsafe(24)
    with db() as c:
        c.execute("INSERT INTO cdn VALUES (?,?,?,?)", (token, doc_id, kind, time.time() + CDN_TTL_SECONDS))
    return f"{public_base(request)}/cdn/{token}"


# --------------------------------------------------------------------------- minimal PDF writer (no deps)
def simple_pdf(lines: list[str]) -> bytes:
    def esc(t: str) -> str:
        t = t.encode("latin-1", "replace").decode("latin-1")
        return t.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    ops, y = ["BT"], 800
    for i, line in enumerate(lines):
        size = 15 if i == 0 else 10
        ops.append(f"/F1 {size} Tf 1 0 0 1 50 {y} Tm ({esc(line[:110])}) Tj")
        y -= size + 8
    ops.append("ET")
    stream = "\n".join(ops).encode("latin-1")
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out, offs = bytearray(b"%PDF-1.4\n"), []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    for o in offs:
        out += f"{o:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def signed_document_pdf(d, inv) -> bytes:
    if d["file_b64"]:
        return base64.b64decode(d["file_b64"])  # mock: the uploaded PDF is returned as the "signed" copy
    return simple_pdf([f"Document: {d['name']}", f"Document ID: {d['id']}", "(Template-based mock document)"]
                      + [f"Signed by {i['name']} on {leegality_date(i['sign_date'])} via {i['sign_type']}"
                         for i in inv if i["signed"]])


def audit_trail_pdf(d, inv) -> bytes:
    lines = ["MOCK LEEGALITY AUDIT TRAIL - NOT LEGALLY VALID", f"Document: {d['name']}",
             f"Document ID: {d['id']}", f"IRN: {d['irn'] or '-'}",
             f"Created: {leegality_date(d['created_at'])}", f"Status: {d['status']}", ""]
    for i in inv:
        state = "SIGNED" if i["signed"] else "REJECTED" if i["rejected"] else "PENDING"
        lines.append(f"{i['name']} <{i['email'] or i['phone']}> - {state} "
                     f"{leegality_date(i['sign_date']) or ''} {i['sign_type'] or ''}")
    return simple_pdf(lines)


# --------------------------------------------------------------------------- webhooks
def send_webhook(request: Request, d, invitee, action: str) -> dict:
    url = get_setting("webhook_url", DEFAULT_WEBHOOK_URL)
    expiry = datetime.fromisoformat(invitee["expiry"]).strftime("%d-%m-%Y %H:%M:%S")
    payload = {
        "webhookType": "Success",
        "documentId": d["id"],
        "documentStatus": "Completed" if d["status"] == "COMPLETED" else "Sent",
        "irn": d["irn"],
        "mac": compute_mac(d["id"]),
        "messages": [],
        "verification": {"name": None, "smartName": None, "pincode": None, "state": None,
                         "title": None, "yob": None, "gender": None},
        "request": {
            "inviteeType": "Signer",
            "name": invitee["name"],
            "email": invitee["email"],
            "phone": invitee["phone"],
            "invitationUrl": f"{public_base(request)}/sign/{invitee['token']}",
            "active": action != "Rejected",
            "action": action,
            "error": None,
            "expired": False,
            "expiryDate": expiry,
            "rejectionMessage": invitee["rejection_message"] if action == "Rejected" else None,
            "signType": invitee["sign_type"],
        },
    }
    result = {"url": url, "status_code": None, "error": None}
    if not url:
        result["error"] = "No webhook URL configured (set it on the mock dashboard)"
    else:
        try:
            r = httpx.post(url, json=payload, timeout=15)
            result["status_code"] = r.status_code
        except httpx.HTTPError as e:
            result["error"] = str(e)
    with db() as c:
        c.execute("INSERT INTO webhooks(ts,document_id,url,status_code,error,payload) VALUES (?,?,?,?,?,?)",
                  (now().isoformat(), d["id"], url, result["status_code"], result["error"], json.dumps(payload)))
    return result


# --------------------------------------------------------------------------- app
@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Mock Leegality API", version="1.0", lifespan=lifespan)


@app.get("/health")
def health():
    return {"ok": True, "service": "mock-leegality"}


# ---- POST /api/v3.0/sign/request ---------------------------------------------
@app.post("/api/v3.0/sign/request")
async def create_sign_request(request: Request, x_auth_token: Optional[str] = Header(default=None)):
    if (err := check_auth(x_auth_token)):
        return err
    try:
        body = await request.json()
    except ValueError:
        return fail("request.invalid", "Body must be JSON")

    profile_id = (body.get("profileId") or "").strip()
    if not profile_id:
        return fail("profileId.required", "profileId (workflow ID) is required")
    invitees = body.get("invitees") or []
    if not invitees:
        return fail("invitees.required", "At least one invitee is required")
    for i, inv in enumerate(invitees):
        if not inv.get("name"):
            return fail("invitee.name.required", f"invitees[{i}].name is required")
        if not inv.get("email") and not inv.get("phone"):
            return fail("invitee.contact.required", f"invitees[{i}] needs an email or phone")

    file_obj = body.get("file") or {}
    file_b64 = file_obj.get("file")
    if file_b64:
        try:
            raw = base64.b64decode(file_b64, validate=True)
        except (ValueError, TypeError):
            return fail("file.invalid", "file.file must be Base64-encoded PDF")
        if len(raw) > MAX_FILE_BYTES:
            return fail("file.tooLarge", "File exceeds 15 MB")
        if not raw.startswith(b"%PDF"):
            return fail("file.notPdf", "file.file is not a PDF")
    if body.get("irn") and len(body["irn"]) > 255:
        return fail("irn.tooLong", "irn must be at most 255 characters")

    doc_id = new_document_id()
    created = now()
    expiry = created + timedelta(days=INVITE_VALID_DAYS)
    name = (file_obj.get("name") or f"Document {doc_id[-6:]}")[:255]
    base = public_base(request)
    out_invitees = []
    with db() as c:
        c.execute("INSERT INTO documents VALUES (?,?,?,?,?,?,?,?)",
                  (doc_id, name, profile_id, body.get("irn"), "SENT", file_b64, created.isoformat(), None))
        for pos, inv in enumerate(invitees):
            token = secrets.token_urlsafe(16)
            c.execute("INSERT INTO invitees(token,document_id,position,name,email,phone,expiry) VALUES (?,?,?,?,?,?,?)",
                      (token, doc_id, pos, inv["name"], inv.get("email"), inv.get("phone"), expiry.isoformat()))
            out_invitees.append({"name": inv["name"], "email": inv.get("email"), "phone": inv.get("phone"),
                                 "signUrl": f"{base}/sign/{token}", "active": True,
                                 "expiryDate": expiry.strftime("%Y-%m-%dT%H:%M:%SZ")})
    return ok({"documentId": doc_id, "irn": body.get("irn"), "invitees": out_invitees},
              code="simpleWorkFlow.success", message="Invitations sent successfully.")


# ---- GET /api/v3.3/document/details -------------------------------------------
@app.get("/api/v3.3/document/details")
def document_details(request: Request, documentId: str = "", file: bool = False, auditTrail: bool = False,
                     x_auth_token: Optional[str] = Header(default=None)):
    if (err := check_auth(x_auth_token)):
        return err
    d, inv = load_document(documentId)
    if not d:
        return fail("no.document.found", "No document found for the given documentId")
    completed = d["status"] == "COMPLETED"
    data = {
        "file": make_cdn_link(request, d["id"], "DOCUMENT") if file and completed else None,
        "auditTrail": make_cdn_link(request, d["id"], "AUDIT_TRAIL") if auditTrail and completed else None,
        "document": {"id": d["id"], "name": d["name"], "status": d["status"], "irn": d["irn"],
                     "creationDate": leegality_date(d["created_at"]),
                     "completionDate": leegality_date(d["completed_at"])},
        "invitations": [{
            "name": i["name"], "email": i["email"], "phone": i["phone"], "inviteeType": "SIGNER",
            "usedSignatureType": i["sign_type"],
            "invitationStatus": {"signed": bool(i["signed"]), "rejected": bool(i["rejected"]),
                                 "expired": datetime.fromisoformat(i["expiry"]) < now() and not i["signed"],
                                 "signDate": leegality_date(i["sign_date"])},
        } for i in inv],
    }
    return ok(data)


# ---- GET /api/v3.0/sign/request/list ------------------------------------------
@app.get("/api/v3.0/sign/request/list")
def list_documents(q: str = "", status: str = "", page_size: int = Query(20, alias="max"), offset: int = 0,
                   x_auth_token: Optional[str] = Header(default=None)):
    if (err := check_auth(x_auth_token)):
        return err
    limit = min(max(1, page_size), 40)
    sql, args = "SELECT * FROM documents WHERE 1=1", []
    if q:
        sql += " AND (lower(name)=lower(?) OR id=? OR irn=?)"
        args += [q, q, q]
    if status:
        sql += " AND status=?"
        args.append(status.upper())
    with db() as c:
        total = c.execute(sql.replace("SELECT *", "SELECT COUNT(*)"), args).fetchone()[0]
        rows = c.execute(sql + " ORDER BY created_at DESC LIMIT ? OFFSET ?", args + [limit, offset]).fetchall()
    return ok({"total": total, "documents": [
        {"documentId": r["id"], "name": r["name"], "irn": r["irn"], "status": r["status"],
         "folderId": None, "folderName": None} for r in rows]})


# ---- GET /api/v3.3/document/fetchDocument -------------------------------------
@app.get("/api/v3.3/document/fetchDocument")
def fetch_document(request: Request, documentId: str = "", documentDownloadType: str = "DOCUMENT",
                   index: int = 0, x_auth_token: Optional[str] = Header(default=None)):
    if (err := check_auth(x_auth_token)):
        return err
    kind = documentDownloadType.upper()
    if kind not in ("DOCUMENT", "AUDIT_TRAIL", "ATTACHMENT", "SUPPORTING_DOCUMENT"):
        return fail("documentDownloadType.invalid", "Unsupported documentDownloadType")
    d, _ = load_document(documentId)
    if not d or d["status"] != "COMPLETED":
        return fail("no.document.found", "Only completed documents can be fetched")
    if kind in ("ATTACHMENT", "SUPPORTING_DOCUMENT"):
        return fail("no.document.found", "Mock has no attachments or supporting documents")
    return ok({"file": make_cdn_link(request, d["id"], kind)})


# ---- temporary download links (like Leegality's CDN URLs) ---------------------
@app.get("/cdn/{token}")
def cdn(token: str):
    with db() as c:
        r = c.execute("SELECT * FROM cdn WHERE token=?", (token,)).fetchone()
    if not r or r["expires"] < time.time():
        return Response("Link expired or invalid", status_code=410)
    d, inv = load_document(r["document_id"])
    pdf = audit_trail_pdf(d, inv) if r["kind"] == "AUDIT_TRAIL" else signed_document_pdf(d, inv)
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'inline; filename="{d["id"]}_{r["kind"].lower()}.pdf"'})


# ---- signing page --------------------------------------------------------------
PAGE_CSS = """<style>
body{font-family:system-ui,sans-serif;max-width:640px;margin:32px auto;padding:0 16px;color:#1d1d1f;background:#fafafa}
.card{background:#fff;border:1px solid #ddd;border-radius:10px;padding:20px;margin:16px 0}
.banner{background:#fff4d6;border:1px solid #f0c36d;padding:8px 12px;border-radius:8px;font-size:14px}
button{font-size:15px;padding:10px 16px;border-radius:8px;border:0;cursor:pointer;margin-right:8px}
.sign{background:#4f46e5;color:#fff}.reject{background:#eee}
input,textarea,select{font-size:15px;padding:8px;border:1px solid #ccc;border-radius:6px;width:100%;box-sizing:border-box}
label{display:block;margin:12px 0 4px;font-weight:600}
table{border-collapse:collapse;width:100%;font-size:14px}td,th{border-bottom:1px solid #eee;padding:6px;text-align:left}
code{background:#f1f1f1;padding:1px 4px;border-radius:4px}
</style>"""


@app.get("/sign/{token}", response_class=HTMLResponse)
def sign_page(token: str):
    with db() as c:
        inv = c.execute("SELECT * FROM invitees WHERE token=?", (token,)).fetchone()
    if not inv:
        return HTMLResponse(PAGE_CSS + "<h2>Invalid signing link</h2>", status_code=404)
    d, _ = load_document(inv["document_id"])
    state = "signed" if inv["signed"] else "rejected" if inv["rejected"] else None
    body = f"""{PAGE_CSS}<title>Mock Leegality – Sign</title>
<div class="banner">MOCK LEEGALITY: test environment, signatures are <b>not</b> legally binding.</div>
<div class="card"><h2>{escape(d['name'])}</h2>
<p>Hello <b>{escape(inv['name'])}</b>, you have been invited to sign this document.</p>
<p>Document ID: <code>{d['id']}</code>{' · IRN: <code>' + escape(d['irn']) + '</code>' if d['irn'] else ''}</p>
{f'<p><a href="/preview/{token}" target="_blank">View document</a></p>' if d['file_b64'] else ''}</div>"""
    if state:
        body += f'<div class="card"><h3>You have already {state} this document.</h3></div>'
    else:
        body += f"""<div class="card"><form method="post" action="/sign/{token}">
<label>Signature type</label>
<select name="sign_type"><option value="AADHAAR">Aadhaar eSign (mock OTP)</option>
<option value="VIRTUAL">Virtual sign</option><option value="DSC">DSC (mock)</option></select>
<label>OTP (mock: enter any 6 digits)</label><input name="otp" maxlength="6" placeholder="123456">
<label>Rejection reason (only if rejecting)</label><textarea name="reason" rows="2"></textarea><br><br>
<button class="sign" name="action" value="Signed">Sign document</button>
<button class="reject" name="action" value="Rejected">Reject</button></form></div>"""
    return HTMLResponse(body)


@app.get("/preview/{token}")
def preview(token: str):
    with db() as c:
        inv = c.execute("SELECT * FROM invitees WHERE token=?", (token,)).fetchone()
    if not inv:
        return Response("Not found", status_code=404)
    d, _ = load_document(inv["document_id"])
    if not d["file_b64"]:
        return Response("No file", status_code=404)
    return Response(base64.b64decode(d["file_b64"]), media_type="application/pdf")


@app.post("/sign/{token}", response_class=HTMLResponse)
def sign_submit(request: Request, token: str, action: str = Form(...), sign_type: str = Form("AADHAAR"),
                otp: str = Form(""), reason: str = Form("")):
    with db() as c:
        inv = c.execute("SELECT * FROM invitees WHERE token=?", (token,)).fetchone()
    if not inv:
        return HTMLResponse(PAGE_CSS + "<h2>Invalid signing link</h2>", status_code=404)
    if inv["signed"] or inv["rejected"]:
        return RedirectResponse(f"/sign/{token}", status_code=303)
    if action == "Signed" and sign_type == "AADHAAR" and not (otp.isdigit() and len(otp) == 6):
        return HTMLResponse(PAGE_CSS + f'<div class="card"><h3>Enter a 6-digit OTP.</h3>'
                            f'<a href="/sign/{token}">Back</a></div>', status_code=400)
    ts = now().isoformat()
    with db() as c:
        if action == "Signed":
            c.execute("UPDATE invitees SET signed=1, sign_type=?, sign_date=? WHERE token=?", (sign_type, ts, token))
        else:
            c.execute("UPDATE invitees SET rejected=1, rejection_message=?, sign_date=? WHERE token=?",
                      (reason or "Rejected by signer", ts, token))
        doc_id = inv["document_id"]
        pending = c.execute("SELECT COUNT(*) FROM invitees WHERE document_id=? AND signed=0", (doc_id,)).fetchone()[0]
        if action == "Signed" and pending == 0:
            c.execute("UPDATE documents SET status='COMPLETED', completed_at=? WHERE id=?", (ts, doc_id))
    d, _ = load_document(doc_id)
    with db() as c:
        inv = c.execute("SELECT * FROM invitees WHERE token=?", (token,)).fetchone()
    result = send_webhook(request, d, inv, "Signed" if action == "Signed" else "Rejected")
    hook = (f"Webhook sent to <code>{escape(result['url'])}</code> → HTTP {result['status_code']}"
            if result["status_code"] else f"Webhook not delivered: {escape(result['error'] or '')}")
    word = "signed" if action == "Signed" else "rejected"
    return HTMLResponse(f"""{PAGE_CSS}<div class="banner">MOCK LEEGALITY</div>
<div class="card"><h2>Document {word} ✔</h2><p>Document status: <b>{d['status']}</b></p><p>{hook}</p></div>""")


# ---- mock dashboard ------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    with db() as c:
        docs = c.execute("SELECT * FROM documents ORDER BY created_at DESC LIMIT 50").fetchall()
        hooks = c.execute("SELECT * FROM webhooks ORDER BY id DESC LIMIT 20").fetchall()
    base = public_base(request)
    rows = "".join(f"<tr><td><code>{d['id']}</code></td><td>{escape(d['name'])}</td><td>{d['status']}</td>"
                   f"<td>{leegality_date(d['created_at'])}</td></tr>" for d in docs) or \
        "<tr><td colspan=4>No documents yet</td></tr>"
    hook_rows = "".join(f"<tr><td>{h['ts'][:19]}</td><td><code>{h['document_id']}</code></td>"
                        f"<td>{h['status_code'] or escape(h['error'] or '')}</td></tr>" for h in hooks) or \
        "<tr><td colspan=3>No webhooks sent yet</td></tr>"
    return HTMLResponse(f"""{PAGE_CSS}<title>Mock Leegality</title>
<h1>Mock Leegality</h1>
<div class="banner">Copy of Leegality's v3 API for testing. Nothing here is legally binding.</div>
<div class="card"><h3>Connection details for Workato</h3>
<p>Mock base URL: <code>{base}</code></p>
<p>Auth token: set with <code>MOCK_AUTH_TOKEN</code> (default <code>mock-auth-token</code>)</p>
<p>Private salt: set with <code>MOCK_PRIVATE_SALT</code> (default <code>mock-private-salt</code>)</p></div>
<div class="card"><h3>Webhook URL</h3>
<p>Where signing events are sent (like the webhook set on a real Leegality workflow).</p>
<form method="post" action="/settings">
<label>Webhook URL</label><input name="webhook_url" value="{escape(get_setting('webhook_url', DEFAULT_WEBHOOK_URL))}">
<label>Auth token (to confirm change)</label><input name="auth_token" type="password"><br><br>
<button class="sign">Save</button></form></div>
<div class="card"><h3>Documents</h3><table><tr><th>ID</th><th>Name</th><th>Status</th><th>Created</th></tr>{rows}</table></div>
<div class="card"><h3>Recent webhooks</h3><table><tr><th>Time (UTC)</th><th>Document</th><th>Result</th></tr>{hook_rows}</table></div>""")


@app.post("/settings")
def save_settings(webhook_url: str = Form(""), auth_token: str = Form("")):
    if not hmac.compare_digest(auth_token, AUTH_TOKEN):
        return HTMLResponse(PAGE_CSS + '<div class="card"><h3>Wrong auth token.</h3><a href="/">Back</a></div>',
                            status_code=401)
    set_setting("webhook_url", webhook_url.strip())
    return RedirectResponse("/", status_code=303)
