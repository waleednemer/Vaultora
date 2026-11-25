import app as app_module

from conftest import b64

clean_setup = app_module.clean_setup
clean_entry = app_module.clean_entry


def good():
    return {"salt": b64(16), "auth_key": b64(32), "iterations": 600_000}


def test_valid_setup_accepted():
    data, err = clean_setup(good())
    assert err is None and data["iterations"] == 600_000


def test_salt_must_be_16_bytes():
    body = {**good(), "salt": b64(8)}
    assert clean_setup(body)[1] == "salt غير صالح"


def test_auth_key_must_be_32_bytes():
    body = {**good(), "auth_key": b64(16)}
    assert clean_setup(body)[1] == "auth_key غير صالح"


def test_iterations_bounds_and_type():
    for bad in (99_999, 10_000_001, "600000", True, None):
        assert clean_setup({**good(), "iterations": bad})[1] == "عدد التكرارات غير صالح"


def test_entry_must_be_base64_string():
    assert clean_entry({"data": "QUJD"})[1] is None
    for bad in ("", "not base64!", None, 123, "A" * 20_001):
        assert clean_entry({"data": bad})[1] == "بيانات غير صالحة"


def test_login_throttle_window(monkeypatch):
    app_module._fails.clear()
    for _ in range(app_module.LOGIN_MAX_FAILS):
        app_module._fails["1.2.3.4"].append(0)
    monkeypatch.setattr(app_module.time, "monotonic", lambda: 1)
    assert app_module.too_many_fails("1.2.3.4") is True
    monkeypatch.setattr(app_module.time, "monotonic", lambda: app_module.LOGIN_WINDOW + 5)
    assert app_module.too_many_fails("1.2.3.4") is False
