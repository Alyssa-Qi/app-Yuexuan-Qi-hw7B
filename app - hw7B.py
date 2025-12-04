# TelehealthServer (Merged) — Doctors, Payments, Patients + Auth Sessions
# Run: python app.py  (defaults to 127.0.0.1:8000)

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json, time, base64, os
from typing import Dict, Any, List, Tuple, Optional

HOST = "127.0.0.1"
PORT = 8000

# Feature flag to optionally seed demo data (default: False)
SEED_DEMO = os.getenv("SEED_DEMO", "false").lower() in ("1", "true", "yes")

# ============== Utils ==============

def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")

class HTTPError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message

def read_json_body(handler: BaseHTTPRequestHandler) -> Dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length == 0:
        return {}
    raw = handler.rfile.read(length)
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        raise HTTPError(400, "Invalid JSON body")

def get_query(request_path: str) -> Tuple[str, Dict[str, List[str]]]:
    parsed = urlparse(request_path)
    return parsed.path.rstrip("/") or "/", parse_qs(parsed.query)

def require_fields(data: Dict[str, Any], fields: List[str]):
    missing = [f for f in fields if f not in data or data[f] in (None, "", [])]
    if missing:
        raise HTTPError(400, f"Missing required fields: {', '.join(missing)}")

def gen_id(prefix: str, store: Dict[str, Dict[str, Any]]) -> str:
    n = len(store) + 1
    while True:
        _id = f"{prefix}{n}"
        if _id not in store:
            return _id
        n += 1

def parse_bool(q: Dict[str, List[str]], key: str, default=False) -> bool:
    v = q.get(key, [str(default).lower()])[0].lower()
    return v in ("1", "true", "yes", "y")

def paginate(items: List[Dict[str, Any]], q: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    try:
        page = int(q.get("page", ["1"])[0])
        limit = int(q.get("limit", ["50"])[0])
    except ValueError:
        page, limit = 1, 50
    if limit <= 0:
        return items
    start = (page - 1) * limit
    end = start + limit
    return items[start:end]

def sort_items(items: List[Dict[str, Any]], key: str, reverse: bool=False) -> List[Dict[str, Any]]:
    return sorted(items, key=lambda x: x.get(key), reverse=reverse)

def soft_filter(items: List[Dict[str, Any]], include_deleted: bool) -> List[Dict[str, Any]]:
    if include_deleted:
        return items
    return [x for x in items if not x.get("deleted")]

# ============== In-memory DBs ==============

DB = {
    "doctors": {},
    "patients": {},
    "payments": {},
    "sessions": {},  # sessionId -> {sessionId, userId, role, token, createdAt, deleted}
}

# Simple “User” directory for demo auth (email/password -> role, userId)
# In a real app, use proper user storage + password hashing.
USERS = {
    # email: {password, role, userId}
    "patient@example.com": {"password": "patientpass", "role": "Patient", "userId": "pat_user_1"},
    "doctor@example.com": {"password": "doctorpass", "role": "Doctor", "userId": "doc_user_1"},
    "admin@example.com":  {"password": "adminpass",  "role": "Admin",  "userId": "adm_user_1"},
}

def make_token(payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    suffix = base64.urlsafe_b64encode(os.urandom(12)).decode("ascii").rstrip("=")
    return f"{b64}.{suffix}"

def parse_auth_header(handler: BaseHTTPRequestHandler) -> Optional[Dict[str, Any]]:
    auth = handler.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    for sess in DB["sessions"].values():
        if not sess.get("deleted") and sess.get("token") == token:
            return {"sessionId": sess["sessionId"], "role": sess["role"], "userId": sess["userId"]}
    return None

def require_auth(handler: BaseHTTPRequestHandler, allowed_roles: List[str]) -> Dict[str, Any]:
    ctx = parse_auth_header(handler)
    if not ctx:
        raise HTTPError(401, 'Missing Authorization Header')
    if allowed_roles and ctx["role"] not in allowed_roles:
        raise HTTPError(403, "Forbidden")
    return ctx

# ============== Routes ==============

def route_auth(method: str, path: str, q, body, handler: BaseHTTPRequestHandler):
    # POST /auth/sessions – Create session (Public)
    if method == "POST" and path == "/auth/sessions":
        req = body or {}
        require_fields(req, ["email", "password"])
        u = USERS.get(req["email"])
        if not u or u["password"] != req["password"]:
            raise HTTPError(401, "Invalid credentials")
        sessionId = gen_id("sess_", DB["sessions"])
        token = make_token({"sessionId": sessionId, "role": u["role"], "userId": u["userId"], "iat": now_iso()})
        DB["sessions"][sessionId] = {
            "sessionId": sessionId,
            "userId": u["userId"],
            "role": u["role"],
            "token": token,
            "createdAt": now_iso(),
            "deleted": False,
        }
        return 201, {"sessionId": sessionId, "access_token": token, "role": u["role"]}

    # DELETE /auth/sessions/:sessionId – Logout [Doctor, Patient]
    if method == "DELETE" and path.startswith("/auth/sessions/") and path.count("/") == 3:
        _, _, _, sessionId = path.split("/")
        ctx = require_auth(handler, ["Doctor", "Patient"])
        sess = DB["sessions"].get(sessionId)
        if not sess or sess.get("deleted"):
            raise HTTPError(404, "Session not found")
        if ctx["sessionId"] != sessionId:
            raise HTTPError(403, "Forbidden")
        sess["deleted"] = True
        return 200, {"deleted": True, "sessionId": sessionId}

    raise HTTPError(404, "Auth route not found")

def route_doctors(method: str, path: str, q, body, handler: BaseHTTPRequestHandler):
    # POST /doctors – register a doctor [Public]
    if method == "POST" and path == "/doctors":
        req = body or {}
        require_fields(req, ["firstName", "lastName", "specialtyId", "tier", "email", "phone"])
        doc_id = gen_id("doc_", DB["doctors"])
        doc = {
            "doctorId": doc_id,
            "firstName": req["firstName"],
            "lastName": req["lastName"],
            "specialtyId": req["specialtyId"],
            "tier": req["tier"],
            "email": req["email"],
            "phone": req["phone"],
            "licenseNumber": req.get("licenseNumber"),
            "yearsOfExperience": req.get("yearsOfExperience", 0),
            "ratingAverage": req.get("ratingAverage", 0.0),
            "status": req.get("status", "Active"),
            "deleted": False,
            "createdDate": now_iso(),
            "updatedDate": now_iso(),
        }
        DB["doctors"][doc_id] = doc
        return 201, doc

    # GET /doctors – list [Admin, Doctor, Patient]
    if method == "GET" and path == "/doctors":
        require_auth(handler, ["Admin", "Doctor", "Patient"])
        include_deleted = parse_bool(q, "include_deleted", False)
        items = list(DB["doctors"].values())

        # Filters
        if "specialtyId" in q:
            sid = q["specialtyId"][0]
            items = [d for d in items if str(d.get("specialtyId")) == sid]
        if "status" in q:
            st = q["status"][0]
            items = [d for d in items if str(d.get("status")) == st]

        items = soft_filter(items, include_deleted)

        # Sorting
        sort_key = q.get("sort", ["ratingAverage"])[0]  # ratingAverage | yearsOfExperience
        reverse = q.get("order", ["desc"])[0].lower() == "desc"
        if sort_key in ("ratingAverage", "yearsOfExperience"):
            items = sort_items(items, sort_key, reverse)

        items = paginate(items, q)
        return 200, items

    # GET /doctors/:doctorId [Admin, Doctor, Patient]
    if method == "GET" and path.startswith("/doctors/") and path.count("/") == 2:
        require_auth(handler, ["Admin", "Doctor", "Patient"])
        doctorId = path.split("/")[2]
        doc = DB["doctors"].get(doctorId)
        if not doc or (doc.get("deleted") and not parse_bool(q, "include_deleted", False)):
            raise HTTPError(404, "Doctor not found")
        return 200, doc

    # PATCH /doctors/:doctorId [Admin, Doctor]
    if method == "PATCH" and path.startswith("/doctors/") and path.count("/") == 2:
        require_auth(handler, ["Admin", "Doctor"])
        doctorId = path.split("/")[2]
        doc = DB["doctors"].get(doctorId)
        if not doc or doc.get("deleted"):
            raise HTTPError(404, "Doctor not found")
        disallowed = {"doctorId", "createdDate", "ratingAverage"}
        for k, v in (body or {}).items():
            if k in disallowed:
                continue
            doc[k] = v
        doc["updatedDate"] = now_iso()
        return 200, doc

    # DELETE /doctors/:doctorId [Admin, Doctor]
    if method == "DELETE" and path.startswith("/doctors/") and path.count("/") == 2:
        require_auth(handler, ["Admin", "Doctor"])
        doctorId = path.split("/")[2]
        doc = DB["doctors"].get(doctorId)
        if not doc:
            raise HTTPError(404, "Doctor not found")
        doc["deleted"] = True
        doc["updatedDate"] = now_iso()
        return 200, {"deleted": True, "doctorId": doctorId}

    raise HTTPError(404, "Doctors route not found")

def route_patients(method: str, path: str, q, body, handler: BaseHTTPRequestHandler):
    # POST /patients – register [Public]
    if method == "POST" and path == "/patients":
        req = body or {}
        require_fields(req, ["firstName", "lastName", "dateOfBirth", "gender", "email", "phone", "registrationDate"])
        pid = gen_id("pat_", DB["patients"])
        DB["patients"][pid] = {
            "patientId": pid,
            "firstName": req["firstName"],
            "lastName": req["lastName"],
            "dateOfBirth": req["dateOfBirth"],
            "gender": req["gender"],
            "email": req["email"],
            "phone": req["phone"],
            "address": req.get("address"),
            "insuranceProvider": req.get("insuranceProvider"),
            "medicalHistory": req.get("medicalHistory"),
            "registrationDate": req["registrationDate"],
            "deleted": False,
            "createdDate": now_iso(),
            "updatedDate": now_iso(),
        }
        return 201, DB["patients"][pid]

    # GET /patients – list [Admin]
    if method == "GET" and path == "/patients":
        require_auth(handler, ["Admin"])
        include_deleted = parse_bool(q, "include_deleted", False)
        items = list(DB["patients"].values())

        # Filters
        if "gender" in q:
            g = q["gender"][0]
            items = [p for p in items if str(p.get("gender")) == g]
        if "insuranceProvider" in q:
            ip = q["insuranceProvider"][0]
            items = [p for p in items if str(p.get("insuranceProvider")) == ip]

        items = soft_filter(items, include_deleted)

        # Sorting
        sort_key = q.get("sort", ["lastName"])[0]
        reverse = q.get("order", ["asc"])[0].lower() == "desc"
        if sort_key in ("lastName", "registrationDate"):
            items = sort_items(items, sort_key, reverse)

        items = paginate(items, q)
        return 200, items

    # GET /patients/:patientId – [Admin, Patient]
    if method == "GET" and path.startswith("/patients/") and path.count("/") == 2:
        require_auth(handler, ["Admin", "Patient"])
        patientId = path.split("/")[2]
        p = DB["patients"].get(patientId)
        if not p or (p.get("deleted") and not parse_bool(q, "include_deleted", False)):
            raise HTTPError(404, "Patient not found")
        return 200, p

    # PATCH /patients/:patientId – [Patient]
    if method == "PATCH" and path.startswith("/patients/") and path.count("/") == 2:
        require_auth(handler, ["Patient"])
        patientId = path.split("/")[2]
        p = DB["patients"].get(patientId)
        if not p or p.get("deleted"):
            raise HTTPError(404, "Patient not found")
        disallowed = {"patientId", "createdDate", "registrationDate"}
        for k, v in (body or {}).items():
            if k in disallowed:
                continue
            p[k] = v
        p["updatedDate"] = now_iso()
        return 200, p

    # DELETE /patients/:patientId – [Admin, Patient]
    if method == "DELETE" and path.startswith("/patients/") and path.count("/") == 2:
        require_auth(handler, ["Admin", "Patient"])
        patientId = path.split("/")[2]
        p = DB["patients"].get(patientId)
        if not p:
            raise HTTPError(404, "Patient not found")
        p["deleted"] = True
        p["updatedDate"] = now_iso()
        return 200, {"deleted": True, "patientId": patientId}

    raise HTTPError(404, "Patients route not found")

def route_payments(method: str, path: str, q, body, handler: BaseHTTPRequestHandler):
    # POST /payments – create a new payment record [Patient]
    if method == "POST" and path == "/payments":
        # Only Patients can create payments (adjust roles if needed)
        require_auth(handler, ["Patient"])
        req = body or {}
        require_fields(req, ["consultationId", "patientId", "doctorId", "amount", "paymentDate", "status"])
        pay_id = gen_id("pay_", DB["payments"])
        payment = {
            "paymentId": pay_id,
            "consultationId": req["consultationId"],
            "patientId": req["patientId"],
            "doctorId": req["doctorId"],
            "amount": float(req["amount"]),
            "paymentDate": req["paymentDate"],  # ISO string
            "status": req["status"],  # e.g., Pending | Paid | Failed | Refunded
            "notes": req.get("notes"),
            "deleted": False,
            "createdDate": now_iso(),
            "updatedDate": now_iso(),
        }
        DB["payments"][pay_id] = payment
        return 201, payment

    # GET /payments – [Patient, Doctor, Admin]
    if method == "GET" and path == "/payments":
        require_auth(handler, ["Patient", "Doctor", "Admin"])
        include_deleted = parse_bool(q, "include_deleted", False)
        items = list(DB["payments"].values())

        # Filters
        if "doctorId" in q:
            did = q["doctorId"][0]
            items = [p for p in items if p.get("doctorId") == did]
        if "patientId" in q:
            pid = q["patientId"][0]
            items = [p for p in items if p.get("patientId") == pid]
        if "status" in q:
            st = q["status"][0]
            items = [p for p in items if p.get("status") == st]

        items = soft_filter(items, include_deleted)

        # Sorting
        sort_key = q.get("sort", ["paymentDate"])[0]  # paymentDate|amount
        reverse = q.get("order", ["desc"])[0].lower() == "desc"
        if sort_key in ("paymentDate", "amount"):
            items = sort_items(items, sort_key, reverse)

        items = paginate(items, q)
        return 200, items

    # GET /payments/:paymentId – [Patient, Doctor, Admin]
    if method == "GET" and path.startswith("/payments/") and path.count("/") == 2:
        require_auth(handler, ["Patient", "Doctor", "Admin"])
        paymentId = path.split("/")[2]
        pay = DB["payments"].get(paymentId)
        if not pay or (pay.get("deleted") and not parse_bool(q, "include_deleted", False)):
            raise HTTPError(404, "Payment not found")
        return 200, pay

    # PATCH /payments/:paymentId – update status [Admin]
    if method == "PATCH" and path.startswith("/payments/") and path.count("/") == 2:
        require_auth(handler, ["Admin"])
        paymentId = path.split("/")[2]
        pay = DB["payments"].get(paymentId)
        if not pay or pay.get("deleted"):
            raise HTTPError(404, "Payment not found")
        allowed = {"status"}
        for k, v in (body or {}).items():
            if k in allowed:
                pay[k] = v
        pay["updatedDate"] = now_iso()
        return 200, pay

    # DELETE /payments/:paymentId – delete duplicate/test [Admin]
    if method == "DELETE" and path.startswith("/payments/") and path.count("/") == 2:
        require_auth(handler, ["Admin"])
        paymentId = path.split("/")[2]
        pay = DB["payments"].get(paymentId)
        if not pay:
            raise HTTPError(404, "Payment not found")
        pay["deleted"] = True
        pay["updatedDate"] = now_iso()
        return 200, {"deleted": True, "paymentId": paymentId}

    raise HTTPError(404, "Payments route not found")

# ============== Optional demo seeding (disabled by default) ==============

def seed_demo():
    if not SEED_DEMO:
        return
    # Example demo inserts (won't run unless SEED_DEMO=true)
    d1 = {
        "firstName": "Alex", "lastName": "Smith", "specialtyId": "spc_cardio",
        "tier": "Gold", "email": "alex.smith@demo.com", "phone": "555-1111",
        "licenseNumber": "LIC-123", "yearsOfExperience": 12, "ratingAverage": 4.7, "status": "Active"
    }
    doc_id_1 = gen_id("doc_", DB["doctors"])
    DB["doctors"][doc_id_1] = {**d1, "doctorId": doc_id_1, "deleted": False, "createdDate": now_iso(), "updatedDate": now_iso()}

# ============== HTTP Handler & Router ==============

ROUTE_PREFIXES = [
    ("/auth/sessions", route_auth),
    ("/doctors", route_doctors),
    ("/patients", route_patients),
    ("/payments", route_payments),
]

class Handler(BaseHTTPRequestHandler):
    server_version = "TelehealthServer/1.0"

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def _dispatch(self, method: str):
        path, q = get_query(self.path)
        try:
            body = read_json_body(self) if method in ("POST", "PATCH") else {}
            for prefix, handler_fn in ROUTE_PREFIXES:
                if path == prefix or path.startswith(prefix + "/"):
                    code, data = handler_fn(method, path, q, body, self)
                    self._send_ok(code, data)
                    return
            raise HTTPError(404, "Route not found")
        except HTTPError as he:
            self._send_err(he.code, he.message)
        except Exception as ex:
            self._send_err(500, f"Internal Server Error: {ex}")

    def _send_ok(self, code: int, data: Any):
        payload = {"success": True, "data": data}
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(raw)

    def _send_err(self, code: int, message: str):
        if message == "Missing Authorization Header":
            payload = {"msg": "Missing Authorization Header"}
        else:
            payload = {"success": False, "error": {"code": code, "message": message}}
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self): self._dispatch("GET")
    def do_POST(self): self._dispatch("POST")
    def do_PATCH(self): self._dispatch("PATCH")
    def do_DELETE(self): self._dispatch("DELETE")

# ============== Main ==============

def main():
    # Start clean. No preset doctors/patients/payments.
    if SEED_DEMO:
        seed_demo()
    httpd = HTTPServer((HOST, PORT), Handler)
    print(f"Server running at http://{HOST}:{PORT} (SEED_DEMO={SEED_DEMO})")
    httpd.serve_forever()

if __name__ == "__main__":
    main()