"""Startup/shutdown paths, entry points and small CLIs."""
import asyncio
import json
import runpy

import bcrypt
import pytest
import uvicorn
from fastapi.testclient import TestClient

import app.main as api_main
import armour_config
from app import db
from app.models import Base
from app.policy_store import STORE
from proxy import armour_addon as addon
from proxy.tokenization import StreamRestorer
from tests.conftest import make_env


# ------------------------------------------------------------------ API lifespan

def test_lifespan_with_a_migrated_database(tmp_path, monkeypatch, capsys):
    url = f"sqlite:///{tmp_path / 'a.db'}"
    db.configure(url)
    Base.metadata.create_all(db.engine())
    monkeypatch.setattr(armour_config, "env", make_env(database_url=url))
    with TestClient(api_main.app) as client:
        assert client.get("/health").json() == {"status": "ok"}
    out = capsys.readouterr().out
    assert "database ready - policies loaded (17 seeded" in out
    assert STORE.current.action_for("EMAIL") == "tokenize"


def test_lifespan_without_schema_falls_back_to_config(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(armour_config, "env", make_env(database_url=f"sqlite:///{tmp_path / 'empty.db'}"))
    with TestClient(api_main.app) as client:
        assert client.post("/scan", json={"text": "mail rahul@acme.com"}).json()["action"] == "tokenize"
    assert "run `alembic upgrade head`" in capsys.readouterr().out


def test_lifespan_without_database(capsys):
    with TestClient(api_main.app) as client:
        assert client.get("/health").status_code == 200
    assert "DATABASE_URL not set" in capsys.readouterr().out


def test_policy_refresher_reloads_from_the_table(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'p.db'}"
    db.configure(url)
    Base.metadata.create_all(db.engine())
    with db.session_factory()() as session:
        STORE.seed(session)
    from app.models import Policy
    with db.session_factory()() as session:
        session.get(Policy, "EMAIL").action = "block"
        session.commit()
    sleeps = []

    async def fake_sleep(_):
        sleeps.append(1)
        if len(sleeps) > 1:
            raise asyncio.CancelledError

    monkeypatch.setattr(api_main.asyncio, "sleep", fake_sleep)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(api_main._refresh_policies_forever())
    assert STORE.current.action_for("EMAIL") == "block"


# ------------------------------------------------------------------ entry points

def test_entry_points_use_configured_ports(monkeypatch):
    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append(kw))
    runpy.run_module("app.main", run_name="__main__")
    runpy.run_module("mock_llm", run_name="__main__")
    s = armour_config.settings
    assert calls == [{"host": s.scanner.host, "port": s.scanner.port},
                     {"host": s.demo.upstream_host, "port": s.demo.upstream_port}]


def test_run_proxy_defaults_to_no_flow_output(monkeypatch):
    import mitmproxy.tools.main as mitm_main
    seen = []
    monkeypatch.setattr(mitm_main, "mitmdump", lambda args: seen.append(args))
    monkeypatch.setattr("sys.argv", ["run_proxy.py", "-v"])
    runpy.run_path(str(armour_config.ROOT / "run_proxy.py"), run_name="__main__")
    (args,) = seen
    assert args[args.index("--listen-port") + 1] == str(armour_config.settings.proxy.port)
    assert "flow_detail=0" in args and args[-1] == "-v"


def test_run_proxy_respects_a_user_flow_detail():
    # mitmproxy rejects an option given twice - the default must step aside
    import importlib.util
    spec = importlib.util.spec_from_file_location("run_proxy", armour_config.ROOT / "run_proxy.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    args = module.build_args(["--set", "flow_detail=2"])
    assert [a for a in args if a.startswith("flow_detail=")] == ["flow_detail=2"]


def test_latency_services_are_stopped_if_one_fails_to_start(monkeypatch, tmp_path):
    from eval import run_latency
    started = []

    class FakeProc:
        def __init__(self, *a, **k):
            self.terminated = False
            started.append(self)

        def terminate(self):
            self.terminated = True

        def wait(self, timeout):
            return 0

    monkeypatch.setattr(run_latency.subprocess, "Popen", FakeProc)
    monkeypatch.setattr(run_latency, "wait_port", lambda port: (_ for _ in ()).throw(SystemExit("no port")))
    with pytest.raises(SystemExit):
        run_latency.start_services(tmp_path, tmp_path / "t.jsonl")
    assert len(started) == 4 and all(p.terminated for p in started)


# ------------------------------------------------------------------ hash_password CLI

@pytest.mark.parametrize("answers,code", [
    (["short"], 1),
    (["x" * 80], 1),
    (["a-long-admin-password", "different-password"], 1),
])
def test_hash_password_rejects(monkeypatch, answers, code):
    from app import hash_password
    it = iter(answers)
    monkeypatch.setattr(hash_password.getpass, "getpass", lambda prompt: next(it))
    assert hash_password.main() == code


def test_hash_password_prints_only_the_hash_line(monkeypatch, capsys):
    from app import hash_password
    monkeypatch.setattr(hash_password.getpass, "getpass", lambda prompt: "a-long-admin-password")
    assert hash_password.main() == 0
    line = capsys.readouterr().out.strip()
    assert line.startswith("ADMIN_PASSWORD_HASH='$2b$") and "a-long-admin-password" not in line
    assert bcrypt.checkpw(b"a-long-admin-password", line.split("'")[1].encode())


# ------------------------------------------------------------------ proxy lifecycle

def test_running_starts_background_tasks_and_done_cancels(monkeypatch, capsys):
    monkeypatch.setattr(addon, "DEMO", armour_config.DemoSettings(enabled=True, upstream_host="h", upstream_port=1))

    async def scenario():
        await addon.running()
        started = len(addon._background)
        await addon.done()
        await asyncio.sleep(0)
        return started

    assert asyncio.run(scenario()) >= 2
    out = capsys.readouterr().out
    assert "EVENTS_SHARED_SECRET not set" in out and "DEMO MODE" in out


def test_policy_poll_loop_keeps_polling(monkeypatch):
    polls = []

    async def fake_refresh():
        polls.append(1)
        return False

    async def fake_sleep(_):
        if len(polls) >= 2:
            raise asyncio.CancelledError

    monkeypatch.setattr(addon, "refresh_policy", fake_refresh)
    monkeypatch.setattr(addon.asyncio, "sleep", fake_sleep)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(addon._poll_policy_forever())
    assert len(polls) == 2


def test_refresh_policy_without_secret_is_a_no_op():
    assert asyncio.run(addon.refresh_policy()) is False


# ------------------------------------------------------------------ stream restorer crash

def test_stream_restorer_crash_forwards_raw_bytes_exactly_once(monkeypatch):
    mapping = {"PA_EMAIL_0123ABCD": "rahul@acme.com"}
    events = [json.dumps({"choices": [{"delta": {"content": t}}]}) for t in ("Mail PA_EM", "AIL_0123ABCD ok")]
    raw = "".join(f"data: {e}\n\n" for e in events).encode()
    restorer = StreamRestorer(mapping)
    first = restorer(raw[:30])                           # incomplete event: buffered, nothing out yet
    assert first == b""

    def explode(self, event):
        raise ValueError("message containing rahul@acme.com")

    monkeypatch.setattr(StreamRestorer, "_process", explode)
    out = restorer(raw[30:]) + restorer(b"")
    assert first + out == raw                            # every byte forwarded once, unrestored
    assert restorer.error == "ValueError" and restorer.passthrough
    assert b"rahul@acme.com" not in out and restorer(b"more") == b"more"
