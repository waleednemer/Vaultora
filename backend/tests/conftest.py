import base64
import os
import pathlib
import sys
from contextlib import closing

import psycopg2
import pytest

os.environ.setdefault("SECRET_KEY", "test-secret")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import app as app_module  # noqa: E402

INIT_SQL = pathlib.Path(__file__).resolve().parents[2] / "database" / "init.sql"


def b64(n):
    return base64.b64encode(os.urandom(n)).decode()


@pytest.fixture(scope="session")
def _schema():
    try:
        conn = app_module.connect()
    except psycopg2.OperationalError as e:
        # في CI نريد الفشل لا التخطي، حتى لا ينجح البناء بدون اختبار فعلي
        if os.getenv("CI"):
            pytest.fail(f"PostgreSQL not available in CI: {e}")
        pytest.skip(f"PostgreSQL not available: {e}")
    with conn, conn.cursor() as cur:
        cur.execute(INIT_SQL.read_text())
    conn.close()


@pytest.fixture
def client(_schema):
    with closing(app_module.connect()) as conn, conn, conn.cursor() as cur:
        cur.execute("TRUNCATE entries RESTART IDENTITY; TRUNCATE vault")
    app_module._fails.clear()
    return app_module.app.test_client()


@pytest.fixture
def setup_body():
    return {"salt": b64(16), "auth_key": b64(32), "iterations": 100_000}


@pytest.fixture
def auth(client, setup_body):
    """Vault created and logged in; returns Authorization headers."""
    assert client.post("/api/vault", json=setup_body).status_code == 201
    token = client.post("/api/login", json={"auth_key": setup_body["auth_key"]}).get_json()["token"]
    return {"Authorization": f"Bearer {token}"}
