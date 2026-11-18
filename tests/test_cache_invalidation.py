"""必填缓存失效修复专项：变更后必须按新必填重裁。

口径：
1. 先变更必填，旧缓存不得再放行；
2. 只走甲路径——变更必填与作废旧校验缓存同一事务，并落缓存失效说明；
3. 禁止乙路径/两边混用缓存，禁止半律更新；
4. 偏离失效说明（缓存与现行契约不一致）拦下并记“缓存偏了”；
5. 变更与入站抢写排队，后到只记缓存争用；
6. 只清前端缓存不算修复。
"""
import threading

import pytest
from fastapi.testclient import TestClient

import app as svc
from app import app, init_db


@pytest.fixture(autouse=True)
def _db(tmp_path, monkeypatch):
    monkeypatch.setattr("app.DB_PATH", tmp_path / "t.db")
    init_db()
    yield


@pytest.fixture()
def client():
    return TestClient(app)


def _login(client, username="admin", password="123456"):
    r = client.post("/api/login", json={"username": username, "password": password})
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _change(client, h, version="v5", fields="order_id,amount,currency,buyer_id"):
    return client.post("/api/contracts/change", headers=h,
                       json={"subject": "订单入站", "version": version,
                             "required_fields": fields})


# 1) 复现路径：变更必填后，变更前缓存必须失效，缺新必填按新口径拒收
def test_change_required_then_stale_cache_must_not_pass(client):
    h = _login(client)
    ok = client.post("/api/ingress/validate", headers=h,
                     json={"subject": "订单入站", "payload_fields": "order_id,amount,currency"})
    assert ok.json()["result"] == "通过"

    ch = _change(client, h)
    assert ch.status_code == 200 and ch.json()["cache_invalidated"] is True

    stale = client.post("/api/ingress/validate", headers=h,
                        json={"subject": "订单入站", "payload_fields": "order_id,amount,currency"})
    assert stale.status_code == 200
    assert stale.json()["result"] == "拒收"
    assert "buyer_id" in stale.json()["missing"]
    assert stale.json()["version"] == "v5"
    # 批次留痕：本次裁决实际依据的是新必填串
    assert stale.json()["applied_required"] == "order_id,amount,currency,buyer_id"


# 2) 新必填齐全时按新契约通过，且挂新版本号
def test_complete_new_required_passes(client):
    h = _login(client)
    _change(client, h)
    r = client.post("/api/ingress/validate", headers=h,
                    json={"subject": "订单入站",
                          "payload_fields": "order_id,amount,currency,buyer_id"})
    assert r.json()["result"] == "通过" and r.json()["version"] == "v5"


# 3) 甲路径：变更必填与作废旧缓存同一事务，落失效说明，旧缓存行置作废
def test_invalidation_is_same_transaction_path_jia(client):
    h = _login(client)
    client.post("/api/ingress/validate", headers=h,
                json={"subject": "订单入站", "payload_fields": "order_id,amount,currency"})
    _change(client, h)

    with svc.connect() as c:
        dead = c.execute("SELECT * FROM validation_rule_cache WHERE status='作废'").fetchall()
        live = c.execute("SELECT * FROM validation_rule_cache WHERE status='有效'").fetchall()
        notes = c.execute("SELECT * FROM cache_events WHERE event_type='失效说明'").fetchall()

    assert len(dead) == 1 and dead[0]["invalidated_at"]
    assert len(live) == 1
    assert live[0]["required_fields"] == "order_id,amount,currency,buyer_id"
    assert len(notes) == 1
    note = notes[0]
    assert note["path"] == "甲"
    # 同一事务：失效说明、旧缓存作废、新缓存行与新契约同一时间窗落库
    assert note["created_at"] == live[0]["created_at"] == dead[0]["invalidated_at"]
    with svc.connect() as c:
        ver = c.execute("SELECT * FROM contracts WHERE version='v5'").fetchone()
        assert ver["required_fields"] == live[0]["required_fields"]


# 4) 禁止乙路径、禁止两边混用：全站只认甲，无乙事件，无有效缓存与现行契约打架
def test_only_path_jia_no_mixed_cache(client):
    h = _login(client)
    _change(client, h)
    client.post("/api/ingress/validate", headers=h,
                json={"subject": "订单入站", "payload_fields": "order_id,amount,currency,buyer_id"})

    policy = client.get("/api/cache-policy", headers=h).json()
    assert policy["selected_path"] == "甲"
    assert all(e["path"] != "乙" for e in policy["events"])
    assert not any("快照" in (e["detail"] or "") for e in policy["events"])

    with svc.connect() as c:
        drift = c.execute("""
            SELECT COUNT(*) n FROM validation_rule_cache k
            JOIN contracts t ON t.subject=k.subject AND t.track='正式' AND t.status='启用'
            WHERE k.status='有效' AND (k.required_fields <> t.required_fields
                  OR k.contract_version <> t.version)
        """).fetchone()["n"]
    assert drift == 0
    recon = client.get("/api/reconcile", headers=h).json()
    assert recon["cache_drift"] == 0 and recon["aligned"] is True


# 5) 偏离守卫：绕过变更直接改必填（半律更新），入站须拦下并记“缓存偏了”，现场重算
def test_drift_is_blocked_and_recorded(client):
    h = _login(client)
    client.post("/api/ingress/validate", headers=h,
                json={"subject": "订单入站", "payload_fields": "order_id,amount,currency"})
    # 半律更新：只改契约必填串，不动作废缓存
    with svc.connect() as c:
        c.execute("UPDATE contracts SET required_fields=? WHERE version='v3'",
                  ("order_id,amount,currency,buyer_id",))
        c.commit()

    r = client.post("/api/ingress/validate", headers=h,
                    json={"subject": "订单入站", "payload_fields": "order_id,amount,currency"})
    assert r.json()["result"] == "拒收" and "buyer_id" in r.json()["missing"]

    with svc.connect() as c:
        drift_events = c.execute(
            "SELECT * FROM cache_events WHERE event_type='缓存偏了'").fetchall()
        live = c.execute("SELECT * FROM validation_rule_cache WHERE status='有效'").fetchall()
    assert len(drift_events) == 1
    assert len(live) == 1 and live[0]["required_fields"] == "order_id,amount,currency,buyer_id"


# 6) 并发：变更与入站抢写排队，后到者只记缓存争用，裁决仍正确
def test_concurrent_change_and_ingress_queue_with_contention(client):
    h = _login(client)
    client.post("/api/ingress/validate", headers=h,
                json={"subject": "订单入站", "payload_fields": "order_id,amount,currency"})

    def run_while_locked(fn):
        """占住写锁后让 fn 在线程里排队，确认其进入队列再放行。"""
        held, release = threading.Event(), threading.Event()

        def occupy():
            svc._write_lock.acquire()
            held.set()
            release.wait(timeout=5)
            svc._write_lock.release()

        t = threading.Thread(target=occupy)
        t.start()
        assert held.wait(timeout=5)
        out = {}

        def job():
            out["r"] = fn()

        tj = threading.Thread(target=job)
        tj.start()
        for _ in range(100):
            if svc.waiter_count() >= 1:
                break
            threading.Event().wait(0.02)
        assert svc.waiter_count() >= 1  # 确实在排队，而非直接拿到锁
        release.set()
        tj.join(timeout=5); t.join(timeout=5)
        return out["r"]

    # 第一段：变更排队（争用 1）
    change = run_while_locked(lambda: _change(client, h))
    assert change.status_code == 200 and change.json()["queued"] is True

    # 第二段：入站排队（争用 2），此时变更已提交，必须按新必填现场重裁
    ingress = run_while_locked(lambda: client.post(
        "/api/ingress/validate", headers=h,
        json={"subject": "订单入站", "payload_fields": "order_id,amount,currency"}))
    assert ingress.json()["result"] == "拒收" and "buyer_id" in ingress.json()["missing"]
    assert ingress.json()["queued"] is True

    with svc.connect() as c:
        rows = c.execute(
            "SELECT * FROM cache_events WHERE event_type='缓存争用'").fetchall()
    assert len(rows) == 2
    # 争用只记账，不产生失效/漂移以外的旁路裁决
    assert all(row["path"] is None for row in rows)
    assert {row["subject"] for row in rows} == {"订单入站"}


# 7) 原子性：变更事务失败时契约、缓存、失效说明全部回滚
def test_failed_change_rolls_back_everything(client):
    h = _login(client)
    client.post("/api/ingress/validate", headers=h,
                json={"subject": "订单入站", "payload_fields": "order_id,amount,currency"})
    bad = _change(client, h, version="v3")  # 版本号冲突
    assert bad.status_code == 400

    with svc.connect() as c:
        n_contracts = c.execute("SELECT COUNT(*) n FROM contracts").fetchone()["n"]
        n_live = c.execute(
            "SELECT COUNT(*) n FROM validation_rule_cache WHERE status='有效'").fetchone()["n"]
        n_notes = c.execute(
            "SELECT COUNT(*) n FROM cache_events WHERE event_type='失效说明'").fetchone()["n"]
    assert n_contracts == 3 and n_live == 1 and n_notes == 0


# 8) 只清前端缓存不算修复：全新会话（等同清空前端态重登）仍受服务端缓存约束
def test_clearing_frontend_state_alone_does_not_fix(client):
    h1 = _login(client)
    client.post("/api/ingress/validate", headers=h1,
                json={"subject": "订单入站", "payload_fields": "order_id,amount,currency"})
    h2 = _login(client)  # 新会话：前端 token/本地态全部重新开始
    _change(client, h2)
    h3 = _login(client)
    r = client.post("/api/ingress/validate", headers=h3,
                    json={"subject": "订单入站", "payload_fields": "order_id,amount,currency"})
    assert r.json()["result"] == "拒收" and r.json()["version"] == "v5"


# 9) 权限与留痕：只读账号不能变更；详情接口返回本次据以裁决的必填串
def test_permission_and_detail_trail(client):
    viewer = _login(client, "viewer", "view123")
    assert _change(client, viewer).status_code == 403

    h = _login(client)
    _change(client, h)
    r = client.post("/api/ingress/validate", headers=h,
                    json={"subject": "订单入站",
                          "payload_fields": "order_id,amount,currency,buyer_id"})
    bid = r.json()["batch_id"]
    detail = client.get(f"/api/ingress/{bid}", headers=h).json()
    assert detail["applied_required"] == "order_id,amount,currency,buyer_id"
    assert detail["contract_version"] == "v5"
