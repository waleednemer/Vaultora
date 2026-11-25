import app as app_module

from conftest import b64

BLOB = "QUJDREVGR0hJSktMTU5PUA=="  # أي base64 صالح: السيرفر لا يفك التشفير


def test_vault_starts_uninitialized(client):
    assert client.get("/api/vault").get_json() == {"initialized": False}


def test_setup_then_info_exposes_only_salt_and_iterations(client, setup_body):
    assert client.post("/api/vault", json=setup_body).status_code == 201
    info = client.get("/api/vault").get_json()
    assert info == {"initialized": True, "salt": setup_body["salt"], "iterations": 100_000}


def test_setup_twice_returns_409(client, setup_body):
    client.post("/api/vault", json=setup_body)
    assert client.post("/api/vault", json=setup_body).status_code == 409


def test_setup_invalid_returns_400(client, setup_body):
    assert client.post("/api/vault", json={**setup_body, "salt": "x"}).status_code == 400
    assert client.post("/api/vault", json={**setup_body, "iterations": 10}).status_code == 400


def test_auth_key_is_stored_hashed(client, setup_body):
    client.post("/api/vault", json=setup_body)
    row = app_module.query("SELECT auth_hash FROM vault", fetch="one")
    assert row["auth_hash"] != setup_body["auth_key"]
    assert setup_body["auth_key"] not in row["auth_hash"]


def test_login_before_setup_returns_404(client):
    assert client.post("/api/login", json={"auth_key": b64(32)}).status_code == 404


def test_login_wrong_key_returns_401(client, setup_body):
    client.post("/api/vault", json=setup_body)
    assert client.post("/api/login", json={"auth_key": b64(32)}).status_code == 401


def test_login_throttled_after_repeated_failures(client, setup_body):
    client.post("/api/vault", json=setup_body)
    for _ in range(app_module.LOGIN_MAX_FAILS):
        assert client.post("/api/login", json={"auth_key": b64(32)}).status_code == 401
    # حتى المفتاح الصحيح يُرفض أثناء الحظر
    assert client.post("/api/login", json={"auth_key": setup_body["auth_key"]}).status_code == 429


def test_entries_require_token(client):
    assert client.get("/api/entries").status_code == 401
    assert client.get("/api/entries", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.post("/api/entries", json={"data": BLOB}).status_code == 401


def test_expired_token_rejected(client, auth, monkeypatch):
    monkeypatch.setattr(app_module, "SESSION_SECONDS", -1)
    assert client.get("/api/entries", headers=auth).status_code == 401


def test_create_list_roundtrip_keeps_blob_untouched(client, auth):
    res = client.post("/api/entries", json={"data": BLOB}, headers=auth)
    assert res.status_code == 201 and res.get_json()["data"] == BLOB
    items = client.get("/api/entries", headers=auth).get_json()
    assert [i["data"] for i in items] == [BLOB]


def test_create_invalid_data_returns_400(client, auth):
    for bad in ("", "plain text!", "A" * 20_001):
        assert client.post("/api/entries", json={"data": bad}, headers=auth).status_code == 400


def test_update_entry(client, auth):
    eid = client.post("/api/entries", json={"data": BLOB}, headers=auth).get_json()["id"]
    res = client.put(f"/api/entries/{eid}", json={"data": "QUJD"}, headers=auth)
    assert res.status_code == 200 and res.get_json()["data"] == "QUJD"


def test_update_missing_returns_404(client, auth):
    assert client.put("/api/entries/9999", json={"data": BLOB}, headers=auth).status_code == 404


def test_delete_then_404(client, auth):
    eid = client.post("/api/entries", json={"data": BLOB}, headers=auth).get_json()["id"]
    assert client.delete(f"/api/entries/{eid}", headers=auth).status_code == 204
    assert client.delete(f"/api/entries/{eid}", headers=auth).status_code == 404


def test_newest_entry_first(client, auth):
    first = client.post("/api/entries", json={"data": "QQ=="}, headers=auth).get_json()["id"]
    second = client.post("/api/entries", json={"data": "Qg=="}, headers=auth).get_json()["id"]
    ids = [i["id"] for i in client.get("/api/entries", headers=auth).get_json()]
    assert ids == [second, first]


def test_responses_are_not_cacheable(client):
    assert client.get("/api/health").headers["Cache-Control"] == "no-store"
