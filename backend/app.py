
import hashlib, secrets, sqlite3, threading
from datetime import datetime
from pathlib import Path
from fastapi import Header, HTTPException
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DB_PATH = DATA / "app.db"
FRONTEND = ROOT / "frontend"
SESSIONS: dict[str, str] = {}

# 入站校验与契约变更共用的进程内写锁（抢写排队用）
_write_lock = threading.Lock()
_wait_guard = threading.Lock()
_waiters = 0

def waiter_count() -> int:
    return _waiters

def _acquire_write_slot() -> bool:
    """抢写排队。返回 True 表示本次为后到者，须记一笔“缓存争用”。"""
    global _waiters
    with _wait_guard:
        queued = _write_lock.locked() or _waiters > 0
        _waiters += 1
    _write_lock.acquire()
    with _wait_guard:
        _waiters -= 1
    return queued

def connect():
    DATA.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def sha(p: str) -> str:
    return hashlib.sha256(p.encode("utf-8")).hexdigest()

def now() -> str:
    return datetime.now().isoformat(timespec="seconds")

def parse_fields(raw: str) -> list[str]:
    seen: list[str] = []
    for x in raw.split(","):
        t = x.strip()
        if t and t not in seen:
            seen.append(t)
    return seen

def ensure_users(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY, password_sha TEXT NOT NULL, role TEXT NOT NULL)""")
    if conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        conn.execute("INSERT INTO users VALUES (?,?,?)", ("admin", sha("123456"), "管理员"))
        conn.execute("INSERT INTO users VALUES (?,?,?)", ("viewer", sha("view123"), "只读"))

class LoginIn(BaseModel):
    username: str
    password: str

class ChangeIn(BaseModel):
    subject: str
    version: str
    required_fields: str
    mode: str | None = None

class IngressIn(BaseModel):
    subject: str
    payload_fields: str  # comma fields present

def require_user(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "未登录")
    u = SESSIONS.get(authorization.removeprefix("Bearer ").strip())
    if not u:
        raise HTTPException(401, "登录已失效")
    return u

def require_admin(authorization: str | None) -> str:
    u = require_user(authorization)
    with connect() as c:
        role = c.execute("SELECT role FROM users WHERE username=?", (u,)).fetchone()["role"]
    if role != "管理员":
        raise HTTPException(403, "仅管理员可变更契约")
    return u

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

PRODUCT = "入站契约"
SKELETON = "Schema 契约版本约束入站校验，破坏性变更进缓冲或拒收，并与落库结果对账"
# 缓存失效说明：本站只允许甲路径（变更必填与作废旧校验缓存同一事务），禁止乙路径与两边混用
SELECTED_INVALIDATION_PATH = "甲"

app = FastAPI(title=PRODUCT)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

def init_db():
    with connect() as conn:
        ensure_users(conn)
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS contracts(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          version TEXT UNIQUE NOT NULL,
          subject TEXT NOT NULL,
          mode TEXT NOT NULL,
          track TEXT NOT NULL,
          status TEXT NOT NULL,
          required_fields TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ingress_batches(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          subject TEXT NOT NULL,
          payload_fields TEXT NOT NULL,
          contract_version TEXT,
          result TEXT NOT NULL,
          detail TEXT NOT NULL,
          created_at TEXT NOT NULL,
          applied_required TEXT
        );
        CREATE TABLE IF NOT EXISTS buffers(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          batch_id INTEGER NOT NULL,
          reason TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS validation_rule_cache(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          subject TEXT NOT NULL,
          contract_version TEXT NOT NULL,
          required_fields TEXT NOT NULL,
          status TEXT NOT NULL,
          created_at TEXT NOT NULL,
          invalidated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS cache_events(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          subject TEXT NOT NULL,
          event_type TEXT NOT NULL,
          path TEXT,
          detail TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        """)
        # 旧库补列：批次留痕本次实际据以裁决的必填串
        cols = [r[1] for r in conn.execute("PRAGMA table_info(ingress_batches)").fetchall()]
        if "applied_required" not in cols:
            conn.execute("ALTER TABLE ingress_batches ADD COLUMN applied_required TEXT")
        if conn.execute("SELECT COUNT(*) c FROM contracts").fetchone()["c"] == 0:
            conn.execute("INSERT INTO contracts(version,subject,mode,track,status,required_fields) VALUES (?,?,?,?,?,?)",
                         ("v3","订单入站","严格","正式","启用","order_id,amount,currency"))
            conn.execute("INSERT INTO contracts(version,subject,mode,track,status,required_fields) VALUES (?,?,?,?,?,?)",
                         ("v4-shadow","订单入站","兼容","影子","试跑","order_id,amount,currency,channel"))
            conn.execute("INSERT INTO contracts(version,subject,mode,track,status,required_fields) VALUES (?,?,?,?,?,?)",
                         ("v2","库存入站","严格","正式","停用","sku,qty"))

@app.on_event("startup")
def _s():
    init_db()

@app.get("/api/health")
def health():
    with connect() as c:
        n = c.execute("SELECT COUNT(*) c FROM contracts").fetchone()["c"]
    return {"ok": True, "product": PRODUCT, "skeleton": SKELETON, "contracts": n, "db": str(DB_PATH)}

@app.post("/api/login")
def login(body: LoginIn):
    with connect() as c:
        row = c.execute("SELECT username,role FROM users WHERE username=? AND password_sha=?", (body.username, sha(body.password))).fetchone()
    if not row: raise HTTPException(401, "账号或密码错误")
    tok = secrets.token_hex(16); SESSIONS[tok]=row["username"]
    return {"token": tok, "username": row["username"], "role": row["role"]}

@app.get("/api/contracts")
def contracts(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items":[dict(r) for r in c.execute("SELECT * FROM contracts ORDER BY id").fetchall()]}

def active_formal_contract(c, subject):
    return c.execute(
        "SELECT * FROM contracts WHERE subject=? AND track='正式' AND status='启用' ORDER BY id DESC LIMIT 1",
        (subject,)).fetchone()

@app.post("/api/contracts/change")
def change_contract_endpoint(body: ChangeIn, authorization: str | None = Header(default=None)):
    require_admin(authorization)
    new_fields = parse_fields(body.required_fields)
    if not new_fields:
        raise HTTPException(400, "必填字段不能为空")
    new_required = ",".join(new_fields)
    # 变更与入站抢写须排队；后到者只记缓存争用
    queued = _acquire_write_slot()
    try:
        with connect() as c:
            c.execute("BEGIN IMMEDIATE")
            stamp = now()
            if queued:
                c.execute(
                    "INSERT INTO cache_events(subject,event_type,path,detail,created_at) VALUES (?,?,?,?,?)",
                    (body.subject, "缓存争用", None, "契约变更排队等待写锁后执行", stamp))
            old = active_formal_contract(c, body.subject)
            if not old:
                raise HTTPException(404, "无启用正式契约，不能变更必填")
            if c.execute("SELECT 1 FROM contracts WHERE version=?", (body.version,)).fetchone():
                raise HTTPException(400, "契约版本号已存在")
            # 甲路径（唯一允许的缓存失效方式）：
            # 契约切换、旧校验缓存作废、新缓存写入、失效说明全部在同一事务内
            c.execute("UPDATE contracts SET status='停用' WHERE id=?", (old["id"],))
            cur = c.execute(
                "INSERT INTO contracts(version,subject,mode,track,status,required_fields) VALUES (?,?,?,?,?,?)",
                (body.version, body.subject, body.mode or old["mode"], "正式", "启用", new_required))
            c.execute(
                "UPDATE validation_rule_cache SET status='作废', invalidated_at=? WHERE subject=? AND status='有效'",
                (stamp, body.subject))
            c.execute(
                "INSERT INTO validation_rule_cache(subject,contract_version,required_fields,status,created_at) VALUES (?,?,?,?,?)",
                (body.subject, body.version, new_required, "有效", stamp))
            c.execute(
                "INSERT INTO cache_events(subject,event_type,path,detail,created_at) VALUES (?,?,?,?,?)",
                (body.subject, "失效说明", SELECTED_INVALIDATION_PATH,
                 f"必填变更 {old['version']}->{body.version}，同事务作废旧校验缓存并按新必填重裁", stamp))
            return {"changed": True, "contract_id": cur.lastrowid, "version": body.version,
                    "required_fields": new_required, "cache_invalidated": True,
                    "invalidation_path": SELECTED_INVALIDATION_PATH, "queued": queued}
    finally:
        _write_lock.release()

def validate_ingress(subject: str, payload_fields: str) -> dict:
    fields = set(parse_fields(payload_fields))
    # 入站与变更抢写须排队；后到者只记缓存争用
    queued = _acquire_write_slot()
    try:
        with connect() as c:
            c.execute("BEGIN IMMEDIATE")
            stamp = now()
            if queued:
                c.execute(
                    "INSERT INTO cache_events(subject,event_type,path,detail,created_at) VALUES (?,?,?,?,?)",
                    (subject, "缓存争用", None, "入站校验排队等待写锁后执行", stamp))
            ctr = active_formal_contract(c, subject)
            if not ctr:
                raise HTTPException(404, "无启用正式契约")
            live_required = ctr["required_fields"]
            live_version = ctr["version"]
            cache = c.execute(
                "SELECT * FROM validation_rule_cache WHERE subject=? AND status='有效' ORDER BY id DESC LIMIT 1",
                (subject,)).fetchone()

            if cache is None:
                # 无缓存：按现行契约现场建缓存，不读任何历史快照
                req_raw, ver = live_required, live_version
                c.execute(
                    "INSERT INTO validation_rule_cache(subject,contract_version,required_fields,status,created_at) VALUES (?,?,?,?,?)",
                    (subject, ver, req_raw, "有效", stamp))
            elif cache["required_fields"] != live_required or cache["contract_version"] != live_version:
                # 偏离缓存失效说明（半律更新等）：拦下旧缓存，当场作废并按现行必填现场重算
                c.execute(
                    "UPDATE validation_rule_cache SET status='作废', invalidated_at=? WHERE id=?",
                    (stamp, cache["id"]))
                c.execute(
                    "INSERT INTO cache_events(subject,event_type,path,detail,created_at) VALUES (?,?,?,?,?)",
                    (subject, "缓存偏了", SELECTED_INVALIDATION_PATH,
                     f"有效缓存({cache['contract_version']}:{cache['required_fields']})与现行契约"
                     f"({live_version}:{live_required})不一致，旧缓存作废，按现行必填重裁", stamp))
                c.execute(
                    "INSERT INTO validation_rule_cache(subject,contract_version,required_fields,status,created_at) VALUES (?,?,?,?,?)",
                    (subject, live_version, live_required, "有效", stamp))
                req_raw, ver = live_required, live_version
            else:
                # 缓存与现行契约一致才允许使用——不存在乙路径/快照混用
                req_raw, ver = live_required, live_version

            need = set(parse_fields(req_raw))
            missing = sorted(need - fields)
            if missing:
                if ctr["mode"] == "兼容":
                    cur = c.execute("INSERT INTO ingress_batches(subject,payload_fields,contract_version,result,detail,created_at,applied_required) VALUES (?,?,?,?,?,?,?)",
                                    (subject, payload_fields, ver, "缓冲", "缺字段:"+ ",".join(missing), stamp, req_raw))
                    c.execute("INSERT INTO buffers(batch_id,reason) VALUES (?,?)", (cur.lastrowid, "缺字段进双写缓冲"))
                    return {"result":"缓冲", "version": ver, "missing": missing, "batch_id": cur.lastrowid,
                            "applied_required": req_raw, "queued": queued}
                cur = c.execute("INSERT INTO ingress_batches(subject,payload_fields,contract_version,result,detail,created_at,applied_required) VALUES (?,?,?,?,?,?,?)",
                                (subject, payload_fields, ver, "拒收", "缺字段:"+ ",".join(missing), stamp, req_raw))
                return {"result":"拒收", "version": ver, "missing": missing, "batch_id": cur.lastrowid,
                        "applied_required": req_raw, "queued": queued}
            cur = c.execute("INSERT INTO ingress_batches(subject,payload_fields,contract_version,result,detail,created_at,applied_required) VALUES (?,?,?,?,?,?,?)",
                            (subject, payload_fields, ver, "通过", "字段齐全", stamp, req_raw))
            return {"result":"通过", "version": ver, "batch_id": cur.lastrowid,
                    "applied_required": req_raw, "queued": queued}
    finally:
        _write_lock.release()

@app.post("/api/ingress/validate")
def validate_endpoint(body: IngressIn, authorization: str | None = Header(default=None)):
    require_user(authorization)
    return validate_ingress(body.subject, body.payload_fields)

@app.get("/api/ingress")
def ingress(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items":[dict(r) for r in c.execute("SELECT * FROM ingress_batches ORDER BY id DESC").fetchall()]}

@app.get("/api/ingress/{batch_id}")
def ingress_detail(batch_id: int, authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        row = c.execute("SELECT * FROM ingress_batches WHERE id=?", (batch_id,)).fetchone()
        if not row:
            raise HTTPException(404, "批次不存在")
        return dict(row)

@app.get("/api/buffers")
def buffers(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("""SELECT b.*, i.subject, i.payload_fields FROM buffers b JOIN ingress_batches i ON i.id=b.batch_id ORDER BY b.id DESC""").fetchall()
        return {"items":[dict(r) for r in rows]}

@app.get("/api/cache-policy")
def cache_policy(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        events = [dict(r) for r in c.execute("SELECT * FROM cache_events ORDER BY id DESC LIMIT 50").fetchall()]
        active = c.execute("SELECT COUNT(*) n FROM validation_rule_cache WHERE status='有效'").fetchone()["n"]
        dead = c.execute("SELECT COUNT(*) n FROM validation_rule_cache WHERE status='作废'").fetchone()["n"]
    return {
        "selected_path": SELECTED_INVALIDATION_PATH,
        "rules": [
            "只走甲路径：变更必填与作废旧校验缓存必须同一事务",
            "禁止乙路径（只读快照校验），禁止两边混用缓存",
            "禁止半律更新必填串，禁止继续用旧缓存放行",
            "变更与入站抢写排队，后到只记缓存争用",
            "偏离失效说明即拦下并记缓存偏了",
        ],
        "cache_active": active,
        "cache_invalidated": dead,
        "events": events,
    }

@app.get("/api/reconcile")
def reconcile(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        total = c.execute("SELECT COUNT(*) c FROM ingress_batches").fetchone()["c"]
        passed = c.execute("SELECT COUNT(*) c FROM ingress_batches WHERE result='通过'").fetchone()["c"]
        buffered = c.execute("SELECT COUNT(*) c FROM ingress_batches WHERE result='缓冲'").fetchone()["c"]
        rejected = c.execute("SELECT COUNT(*) c FROM ingress_batches WHERE result='拒收'").fetchone()["c"]
        buf_rows = c.execute("SELECT COUNT(*) c FROM buffers").fetchone()["c"]
        active_cache = c.execute("SELECT COUNT(*) n FROM validation_rule_cache WHERE status='有效'").fetchone()["n"]
        drift = c.execute("""
            SELECT COUNT(*) n FROM validation_rule_cache k
            JOIN contracts t ON t.subject=k.subject AND t.track='正式' AND t.status='启用'
            WHERE k.status='有效' AND (k.required_fields <> t.required_fields OR k.contract_version <> t.version)
        """).fetchone()["n"]
        contention = c.execute("SELECT COUNT(*) n FROM cache_events WHERE event_type='缓存争用'").fetchone()["n"]
        invalidations = c.execute("SELECT COUNT(*) n FROM cache_events WHERE event_type='失效说明'").fetchone()["n"]
    return {"ingress_total": total, "passed": passed, "buffered": buffered, "rejected": rejected,
            "buffer_rows": buf_rows, "aligned": buffered == buf_rows and drift == 0,
            "cache_active": active_cache, "cache_drift": drift,
            "invalidation_events": invalidations, "contention_events": contention}

@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")
app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")
