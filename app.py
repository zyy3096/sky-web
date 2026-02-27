import json
import os
import re
import threading
import time
from dataclasses import dataclass, asdict
from functools import wraps
from typing import Dict, List, Optional, Tuple

import requests
from flask import Flask, Response, flash, jsonify, redirect, render_template, request, url_for

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(APP_DIR, "config.json")

# =========================
# Web 访问验证（BasicAuth）
# =========================
ADMIN_USER = os.getenv("ADMIN_USER", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
FLASK_SECRET = os.getenv("FLASK_SECRET", "")

ALLOW_DEFAULT_AUTH = os.getenv("ALLOW_DEFAULT_AUTH", "") == "1"


def _check_basic_auth(auth) -> bool:
    return bool(auth and auth.username == ADMIN_USER and auth.password == ADMIN_PASSWORD)


def require_basic_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not ADMIN_USER or not ADMIN_PASSWORD:
            return Response(
                "ADMIN_USER / ADMIN_PASSWORD not set. Configure environment and restart service.",
                500,
            )
        auth = request.authorization
        if not _check_basic_auth(auth):
            return Response(
                "Authentication required",
                401,
                {"WWW-Authenticate": 'Basic realm="sky-web"'},
            )
        return fn(*args, **kwargs)

    return wrapper


# =========================
# 输入校验
# =========================
HOST_RE = re.compile(r"^[a-zA-Z0-9:\.\-]+$")


def _is_valid_host(host: str) -> bool:
    # 禁止协议/路径，降低 SSRF 风险
    return bool(
        host
        and len(host) <= 255
        and HOST_RE.match(host)
        and "/" not in host
        and "@" not in host
    )


def _is_valid_scheme(s: str) -> bool:
    return s in ("http", "https")


def _parse_int(name: str, v: str, min_v: int, max_v: int) -> Tuple[Optional[int], Optional[str]]:
    try:
        iv = int(str(v).strip())
    except Exception:
        return None, f"{name} 必须是整数"
    if iv < min_v or iv > max_v:
        return None, f"{name} 必须在 {min_v}~{max_v} 之间"
    return iv, None


def _parse_bool(form: dict, key: str) -> bool:
    return form.get(key) == "on"


def _split_tags(tags: str) -> List[str]:
    if not tags:
        return []
    return [t.strip() for t in str(tags).split(",") if t.strip()]


def _join_hashes(hs: List[str]) -> str:
    return "|".join(hs) if hs else ""


def _is_paused_state(state: str) -> bool:
    s = (state or "").strip().lower()
    return ("paused" in s) or (s in ("stopped", "stoppedup", "stoppeddl"))


def _new_key() -> str:
    return os.urandom(6).hex()


@dataclass
class Endpoint:
    key: str
    enabled: bool = True
    name: str = "qb"
    scheme: str = "http"
    host: str = ""
    port: int = 8080
    username: str = ""
    password: str = ""  # ⚠️ 明文存储：仅建议内网/VPN
    verify_ssl: bool = True
    category: str = "sky"

    # 规则（每个 qb 可不同）
    mode: str = "pause_resume"  # limit | pause_resume
    delay_minutes: int = 45

    # limit 模式
    up_limit_kib: int = 10
    down_limit_kib: int = 0
    clear_after: bool = True

    # pause/resume 模式
    pause_before_delay: bool = False
    resume_only_when_paused: bool = True
    resume_requires_tag: bool = False
    pause_tag: str = "SKY_DELAYED"
    done_tag: str = "SKY_RESUMED"
    use_done_tag: bool = True


@dataclass
class AppConfig:
    poll_seconds: int = 60
    endpoints: List[Endpoint] = None  # type: ignore


def _default_config() -> AppConfig:
    return AppConfig(
        poll_seconds=60,
        endpoints=[
            Endpoint(
                key=_new_key(),
                enabled=True,
                name="qb-1",
                scheme="http",
                host="",
                port=8080,
                username="",
                password="",
                verify_ssl=True,
                category="sky",
                mode="pause_resume",
                delay_minutes=45,
            )
        ],
    )


def load_config() -> AppConfig:
    if not os.path.exists(CONFIG_PATH):
        cfg = _default_config()
        save_config(cfg)
        return cfg

    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        d = json.load(f)

    endpoints = []
    for e in d.get("endpoints", []) or []:
        endpoints.append(Endpoint(**e))
    return AppConfig(
        poll_seconds=int(d.get("poll_seconds", 60)),
        endpoints=endpoints,
    )


def save_config(cfg: AppConfig) -> None:
    payload = {
        "poll_seconds": cfg.poll_seconds,
        "endpoints": [asdict(e) for e in (cfg.endpoints or [])],
    }
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


# =========================
# qB API（兼容 v4/v5）
# =========================
class QB:
    def __init__(self, ep: Endpoint):
        self.ep = ep
        self.base = f"{ep.scheme}://{ep.host}:{ep.port}"
        self.sess = requests.Session()

    def login(self) -> None:
        url = f"{self.base}/api/v2/auth/login"
        r = self.sess.post(
            url,
            data={"username": self.ep.username, "password": self.ep.password},
            timeout=10,
            verify=self.ep.verify_ssl,
        )
        r.raise_for_status()
        if "Ok" not in r.text:
            raise RuntimeError(f"qB login failed: {r.text.strip()}")

    def torrents_by_category(self) -> List[Dict]:
        url = f"{self.base}/api/v2/torrents/info"
        r = self.sess.get(
            url,
            params={"category": self.ep.category},
            timeout=15,
            verify=self.ep.verify_ssl,
        )
        r.raise_for_status()
        return r.json()

    def set_up_limit(self, hashes: str, limit_bps: int):
        url = f"{self.base}/api/v2/torrents/setUploadLimit"
        r = self.sess.post(url, data={"hashes": hashes, "limit": limit_bps}, timeout=15, verify=self.ep.verify_ssl)
        r.raise_for_status()

    def set_down_limit(self, hashes: str, limit_bps: int):
        url = f"{self.base}/api/v2/torrents/setDownloadLimit"
        r = self.sess.post(url, data={"hashes": hashes, "limit": limit_bps}, timeout=15, verify=self.ep.verify_ssl)
        r.raise_for_status()

    def pause(self, hashes: str):
        # qB v5: stop; v4: pause
        for path in ("/api/v2/torrents/stop", "/api/v2/torrents/pause"):
            url = f"{self.base}{path}"
            r = self.sess.post(url, data={"hashes": hashes}, timeout=15, verify=self.ep.verify_ssl)
            if r.status_code == 404:
                continue
            r.raise_for_status()
            return
        raise RuntimeError("pause/stop API not found (check WebUI base url/port).")

    def resume(self, hashes: str):
        # qB v5: start; v4: resume
        for path in ("/api/v2/torrents/start", "/api/v2/torrents/resume"):
            url = f"{self.base}{path}"
            r = self.sess.post(url, data={"hashes": hashes}, timeout=15, verify=self.ep.verify_ssl)
            if r.status_code == 404:
                continue
            r.raise_for_status()
            return
        raise RuntimeError("resume/start API not found (check WebUI base url/port).")

    def add_tags(self, hashes: str, tags: str):
        url = f"{self.base}/api/v2/torrents/addTags"
        r = self.sess.post(url, data={"hashes": hashes, "tags": tags}, timeout=15, verify=self.ep.verify_ssl)
        r.raise_for_status()

    def remove_tags(self, hashes: str, tags: str):
        url = f"{self.base}/api/v2/torrents/removeTags"
        r = self.sess.post(url, data={"hashes": hashes, "tags": tags}, timeout=15, verify=self.ep.verify_ssl)
        r.raise_for_status()


def apply_once_endpoint(ep: Endpoint) -> str:
    if not ep.enabled:
        return f"[{ep.name}] disabled"

    if not _is_valid_scheme(ep.scheme) or not _is_valid_host(ep.host) or not (1 <= int(ep.port) <= 65535):
        return f"[{ep.name}] invalid host/scheme/port"
    if not ep.username or not ep.password:
        return f"[{ep.name}] missing qb username/password"

    qb = QB(ep)
    qb.login()
    torrents = qb.torrents_by_category()

    now = int(time.time())
    delay_seconds = int(ep.delay_minutes) * 60

    to_limit: List[str] = []
    to_clear: List[str] = []

    to_pause: List[str] = []
    to_resume: List[str] = []
    to_tag_pause: List[str] = []
    to_tag_done: List[str] = []
    to_untag_pause: List[str] = []

    for t in torrents:
        h = t.get("hash")
        added_on = int(t.get("added_on") or 0)
        if not h or not added_on:
            continue

        age = now - added_on
        state = str(t.get("state") or "")
        tags = _split_tags(str(t.get("tags") or ""))

        has_pause_tag = ep.pause_tag in tags if ep.pause_tag else False
        has_done_tag = ep.done_tag in tags if ep.done_tag else False

        if ep.mode == "limit":
            if age < delay_seconds:
                to_limit.append(h)
            else:
                if ep.clear_after:
                    to_clear.append(h)
            continue

        if age < delay_seconds:
            if ep.pause_before_delay:
                to_pause.append(h)
                if ep.pause_tag and (not has_pause_tag):
                    to_tag_pause.append(h)
            continue

        if ep.use_done_tag and has_done_tag:
            continue
        if ep.resume_requires_tag and (not has_pause_tag):
            continue
        if ep.resume_only_when_paused and (not _is_paused_state(state)):
            continue

        to_resume.append(h)
        if ep.use_done_tag and ep.done_tag and (not has_done_tag):
            to_tag_done.append(h)
        if ep.resume_requires_tag and ep.pause_tag and has_pause_tag:
            to_untag_pause.append(h)

    msgs: List[str] = []

    if ep.mode == "limit":
        up_bps = int(ep.up_limit_kib) * 1024
        down_bps = int(ep.down_limit_kib) * 1024

        if to_limit:
            qb.set_up_limit(_join_hashes(to_limit), up_bps)
            msgs.append(f"limit {len(to_limit)} UP={ep.up_limit_kib}KiB/s")
            if ep.down_limit_kib > 0:
                qb.set_down_limit(_join_hashes(to_limit), down_bps)
                msgs.append(f"DOWN={ep.down_limit_kib}KiB/s")

        if to_clear:
            qb.set_up_limit(_join_hashes(to_clear), -1)
            if ep.down_limit_kib > 0:
                qb.set_down_limit(_join_hashes(to_clear), -1)
            msgs.append(f"clear {len(to_clear)}")

    else:
        if to_pause:
            qb.pause(_join_hashes(to_pause))
            msgs.append(f"pause {len(to_pause)}")

        if to_tag_pause:
            qb.add_tags(_join_hashes(to_tag_pause), ep.pause_tag)
            msgs.append(f"tag_pause {len(to_tag_pause)}")

        if to_resume:
            qb.resume(_join_hashes(to_resume))
            msgs.append(f"resume {len(to_resume)}")

        if to_tag_done:
            qb.add_tags(_join_hashes(to_tag_done), ep.done_tag)
            msgs.append(f"tag_done {len(to_tag_done)}")

        if to_untag_pause:
            qb.remove_tags(_join_hashes(to_untag_pause), ep.pause_tag)
            msgs.append(f"untag_pause {len(to_untag_pause)}")

    if not msgs:
        return f"[{ep.name}] no-op"
    return f"[{ep.name}] " + " | ".join(msgs)


worker_thread: Optional[threading.Thread] = None
worker_stop = threading.Event()
worker_status = {"running": False, "last_run": None, "last_error": None, "last_action": None}


def worker_loop():
    worker_status["running"] = True
    worker_status["last_error"] = None

    while not worker_stop.is_set():
        try:
            cfg = load_config()
            actions = []
            for ep in (cfg.endpoints or []):
                actions.append(apply_once_endpoint(ep))
            worker_status["last_run"] = int(time.time())
            worker_status["last_action"] = " / ".join(actions)
            worker_status["last_error"] = None
        except Exception as e:
            worker_status["last_run"] = int(time.time())
            worker_status["last_error"] = str(e)

        try:
            sleep_s = int(load_config().poll_seconds)
        except Exception:
            sleep_s = 60
        worker_stop.wait(max(5, sleep_s))

    worker_status["running"] = False


app = Flask(__name__)
app.secret_key = FLASK_SECRET or os.urandom(16)


def _find_ep(cfg: AppConfig, key: str) -> Optional[Endpoint]:
    for ep in (cfg.endpoints or []):
        if ep.key == key:
            return ep
    return None


@app.get("/")
@require_basic_auth
def index():
    cfg = load_config()
    return render_template("index.html", cfg=cfg, status=worker_status)


@app.post("/save")
@require_basic_auth
def save():
    cfg = load_config()

    poll_seconds, e = _parse_int("poll_seconds", request.form.get("poll_seconds", "60"), 5, 3600)
    if e:
        flash(e, "error")
        return redirect(url_for("index"))
    cfg.poll_seconds = int(poll_seconds)

    for ep in (cfg.endpoints or []):
        p = f"ep_{ep.key}_"

        ep.enabled = request.form.get(p + "enabled") == "on"
        ep.name = (request.form.get(p + "name") or ep.name).strip() or ep.name

        scheme = (request.form.get(p + "scheme") or ep.scheme).strip()
        host = (request.form.get(p + "host") or ep.host).strip()
        port_s = (request.form.get(p + "port") or str(ep.port)).strip()
        username = (request.form.get(p + "username") or ep.username).strip()
        password = request.form.get(p + "password") or ""
        category = (request.form.get(p + "category") or ep.category).strip()
        verify_ssl = request.form.get(p + "verify_ssl") == "on"
        mode = (request.form.get(p + "mode") or ep.mode).strip()

        delay_minutes, _ = _parse_int("delay_minutes", request.form.get(p + "delay_minutes", str(ep.delay_minutes)), 1, 10_000_000)
        up_limit_kib, _ = _parse_int("up_limit_kib", request.form.get(p + "up_limit_kib", str(ep.up_limit_kib)), 0, 10_000_000)
        down_limit_kib, _ = _parse_int("down_limit_kib", request.form.get(p + "down_limit_kib", str(ep.down_limit_kib)), 0, 10_000_000)

        clear_after = request.form.get(p + "clear_after") == "on"
        pause_before_delay = request.form.get(p + "pause_before_delay") == "on"
        resume_only_when_paused = request.form.get(p + "resume_only_when_paused") == "on"
        resume_requires_tag = request.form.get(p + "resume_requires_tag") == "on"
        pause_tag = (request.form.get(p + "pause_tag") or ep.pause_tag).strip() or ep.pause_tag
        done_tag = (request.form.get(p + "done_tag") or ep.done_tag).strip() or ep.done_tag
        use_done_tag = request.form.get(p + "use_done_tag") == "on"

        if scheme and not _is_valid_scheme(scheme):
            flash(f"[{ep.name}] scheme 仅支持 http/https", "error")
        if host and not _is_valid_host(host):
            flash(f"[{ep.name}] host 不合法（只能域名/IP）", "error")

        ep.scheme = scheme
        ep.host = host
        try:
            ep.port = int(port_s)
        except Exception:
            flash(f"[{ep.name}] port 非法", "error")
        ep.username = username
        if password.strip():
            ep.password = password
        ep.category = category
        ep.verify_ssl = verify_ssl

        if mode in ("limit", "pause_resume"):
            ep.mode = mode

        ep.delay_minutes = int(delay_minutes or ep.delay_minutes)
        ep.up_limit_kib = int(up_limit_kib or ep.up_limit_kib)
        ep.down_limit_kib = int(down_limit_kib or ep.down_limit_kib)
        ep.clear_after = clear_after

        ep.pause_before_delay = pause_before_delay
        ep.resume_only_when_paused = resume_only_when_paused
        ep.resume_requires_tag = resume_requires_tag
        ep.pause_tag = pause_tag
        ep.done_tag = done_tag
        ep.use_done_tag = use_done_tag

    save_config(cfg)
    flash("保存成功", "ok")
    return redirect(url_for("index"))


@app.post("/endpoint/add")
@require_basic_auth
def endpoint_add():
    cfg = load_config()
    cfg.endpoints = cfg.endpoints or []
    cfg.endpoints.append(Endpoint(key=_new_key(), name=f"qb-{len(cfg.endpoints)+1}"))
    save_config(cfg)
    flash("已添加一个 qB 配置", "ok")
    return redirect(url_for("index"))


@app.post("/endpoint/delete/<key>")
@require_basic_auth
def endpoint_delete(key: str):
    cfg = load_config()
    cfg.endpoints = [e for e in (cfg.endpoints or []) if e.key != key]
    save_config(cfg)
    flash("已删除该 qB 配置", "ok")
    return redirect(url_for("index"))


@app.post("/endpoint/test/<key>")
@require_basic_auth
def endpoint_test(key: str):
    cfg = load_config()
    ep = _find_ep(cfg, key)
    if not ep:
        return jsonify({"ok": False, "msg": "endpoint not found"}), 404
    try:
        qb = QB(ep)
        qb.login()
        return jsonify({"ok": True, "msg": "登录成功"}), 200
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 500


@app.post("/endpoint/run-once/<key>")
@require_basic_auth
def endpoint_run_once(key: str):
    cfg = load_config()
    ep = _find_ep(cfg, key)
    if not ep:
        flash("endpoint not found", "error")
        return redirect(url_for("index"))
    try:
        msg = apply_once_endpoint(ep)
        flash(f"执行完成：{msg}", "ok")
    except Exception as e:
        flash(f"执行失败：{e}", "error")
    return redirect(url_for("index"))


@app.post("/run-once-all")
@require_basic_auth
def run_once_all():
    cfg = load_config()
    try:
        msgs = [apply_once_endpoint(ep) for ep in (cfg.endpoints or [])]
        flash("执行完成：" + " / ".join(msgs), "ok")
    except Exception as e:
        flash(f"执行失败：{e}", "error")
    return redirect(url_for("index"))


@app.post("/start")
@require_basic_auth
def start_worker():
    global worker_thread
    if worker_thread and worker_thread.is_alive():
        flash("已在运行", "ok")
        return redirect(url_for("index"))
    worker_stop.clear()
    worker_thread = threading.Thread(target=worker_loop, daemon=True)
    worker_thread.start()
    flash("已启动后台轮询", "ok")
    return redirect(url_for("index"))


@app.post("/stop")
@require_basic_auth
def stop_worker():
    worker_stop.set()
    flash("已请求停止（下一轮轮询退出）", "ok")
    return redirect(url_for("index"))


@app.get("/status")
@require_basic_auth
def status():
    return jsonify(worker_status)


if __name__ == "__main__":
    if not ALLOW_DEFAULT_AUTH and (not ADMIN_USER or not ADMIN_PASSWORD):
        raise SystemExit("ERROR: ADMIN_USER/ADMIN_PASSWORD not set. Set them via env (systemd EnvironmentFile).")

    bind_host = os.getenv("BIND_HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "9876"))
    app.run(host=bind_host, port=port, debug=False)
