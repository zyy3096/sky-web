import json
import os
import re
import threading
import time
from dataclasses import dataclass, asdict
from functools import wraps
from typing import Optional, Tuple, List, Dict

import requests
from flask import (
    Flask,
    Response,
    flash,
    redirect,
    render_template,
    request,
    url_for,
    jsonify,
)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(APP_DIR, "config.json")

# =========================
# Web 访问验证（BasicAuth）
# =========================
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change-me")  # !!! 请务必修改
FLASK_SECRET = os.getenv("FLASK_SECRET", "dev-secret-change-me")


def _check_basic_auth(auth) -> bool:
    return bool(auth and auth.username == ADMIN_USER and auth.password == ADMIN_PASSWORD)


def require_basic_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
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
# 配置与校验
# =========================
# 仅允许 hostname / IPv4 / 简单 IPv6 字符；不允许协议/路径，降低 SSRF 风险
HOST_RE = re.compile(r"^[a-zA-Z0-9:\.\-]+$")


def _is_valid_host(host: str) -> bool:
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


def _is_valid_mode(m: str) -> bool:
    return m in ("limit", "pause_resume")


def _parse_bool(form: dict, key: str) -> bool:
    return form.get(key) == "on"


def _split_tags(tags: str) -> List[str]:
    if not tags:
        return []
    return [t.strip() for t in str(tags).split(",") if t.strip()]


@dataclass
class Config:
    # qB 连接信息
    qb_scheme: str = "http"
    qb_host: str = "127.0.0.1"
    qb_port: int = 8080
    qb_username: str = "admin"
    qb_password: str = ""  # ⚠️ 明文保存到 config.json（仅建议内网/VPN/SSH 隧道）
    qb_category: str = "sky"

    # 模式：limit / pause_resume
    mode: str = "pause_resume"

    # 通用：前 N 分钟执行“限速/暂停”，到点后执行“清除限速/恢复”
    delay_minutes: int = 45
    poll_seconds: int = 60
    verify_ssl: bool = True  # https 自签证书可关

    # --------- 限速模式参数 ---------
    up_limit_kib: int = 10
    down_limit_kib: int = 0  # 0=不设置下载限速
    clear_after: bool = True  # 到点后清除限速（-1）

    # --------- 暂停/恢复参数 ---------
    # 如果 RSS 已设置“进种自动暂停”，建议：
    #   pause_before_delay = False（不强制 pause）
    #   resume_requires_tag = False（无需 tag，直接到点恢复）
    pause_before_delay: bool = False
    resume_only_when_paused: bool = True  # 仅当 state=paused*/stopped 才恢复
    resume_requires_tag: bool = False  # 恢复时是否必须包含 pause_tag
    pause_tag: str = "SKY_DELAYED"  # pause_before_delay=True 时会打该 tag
    done_tag: str = "SKY_RESUMED"  # 恢复后打该 tag，避免重复恢复
    use_done_tag: bool = True


def load_config() -> Config:
    if not os.path.exists(CONFIG_PATH):
        cfg = Config()
        save_config(cfg)
        return cfg
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        d = json.load(f)
    return Config(**d)


def save_config(cfg: Config) -> None:
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(asdict(cfg), f, ensure_ascii=False, indent=2)


def validate_form(form: dict) -> Tuple[Optional[Config], list]:
    errors = []

    qb_scheme = (form.get("qb_scheme") or "").strip()
    qb_host = (form.get("qb_host") or "").strip()
    qb_username = (form.get("qb_username") or "").strip()
    qb_password = (form.get("qb_password") or "")
    qb_category = (form.get("qb_category") or "sky").strip()

    mode = (form.get("mode") or "").strip()

    if not _is_valid_scheme(qb_scheme):
        errors.append("qb_scheme 必须是 http 或 https")
    if not _is_valid_host(qb_host):
        errors.append("qb_host 不合法（只能填域名/IP，不要带 http://、端口、路径）")
    if not qb_username:
        errors.append("qb_username 不能为空")
    if qb_category == "":
        errors.append("qb_category 不能为空")
    if not _is_valid_mode(mode):
        errors.append("mode 必须是 limit 或 pause_resume")

    qb_port, e = _parse_int("qb_port", form.get("qb_port", ""), 1, 65535)
    if e:
        errors.append(e)

    delay_minutes, e = _parse_int("delay_minutes", form.get("delay_minutes", ""), 1, 10_000_000)
    if e:
        errors.append(e)

    poll_seconds, e = _parse_int("poll_seconds", form.get("poll_seconds", ""), 5, 3600)
    if e:
        errors.append(e)

    up_limit_kib, e = _parse_int("up_limit_kib", form.get("up_limit_kib", "0") or "0", 0, 10_000_000)
    if e:
        errors.append(e)

    down_limit_kib, e = _parse_int(
        "down_limit_kib", form.get("down_limit_kib", "0") or "0", 0, 10_000_000
    )
    if e:
        errors.append(e)

    pause_tag = (form.get("pause_tag") or "SKY_DELAYED").strip()
    done_tag = (form.get("done_tag") or "SKY_RESUMED").strip()

    verify_ssl = _parse_bool(form, "verify_ssl")
    clear_after = _parse_bool(form, "clear_after")
    pause_before_delay = _parse_bool(form, "pause_before_delay")
    resume_only_when_paused = _parse_bool(form, "resume_only_when_paused")
    resume_requires_tag = _parse_bool(form, "resume_requires_tag")
    use_done_tag = _parse_bool(form, "use_done_tag")

    if mode == "pause_resume":
        if pause_before_delay and not pause_tag:
            errors.append("pause_before_delay 开启时，pause_tag 不能为空")
        if use_done_tag and not done_tag:
            errors.append("use_done_tag 开启时，done_tag 不能为空")

    if errors:
        return None, errors

    cfg = Config(
        qb_scheme=qb_scheme,
        qb_host=qb_host,
        qb_port=qb_port,
        qb_username=qb_username,
        qb_password=qb_password,
        qb_category=qb_category,
        mode=mode,
        delay_minutes=delay_minutes,
        poll_seconds=poll_seconds,
        verify_ssl=verify_ssl,
        up_limit_kib=up_limit_kib,
        down_limit_kib=down_limit_kib,
        clear_after=clear_after,
        pause_before_delay=pause_before_delay,
        resume_only_when_paused=resume_only_when_paused,
        resume_requires_tag=resume_requires_tag,
        pause_tag=pause_tag,
        done_tag=done_tag,
        use_done_tag=use_done_tag,
    )
    return cfg, []


# =========================
# qB API 封装
# =========================
class QB:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.base = f"{cfg.qb_scheme}://{cfg.qb_host}:{cfg.qb_port}"
        self.sess = requests.Session()

    def login(self) -> None:
        url = f"{self.base}/api/v2/auth/login"
        r = self.sess.post(
            url,
            data={"username": self.cfg.qb_username, "password": self.cfg.qb_password},
            timeout=10,
            verify=self.cfg.verify_ssl,
        )
        r.raise_for_status()
        if "Ok" not in r.text:
            raise RuntimeError(f"qB login failed: {r.text.strip()}")

    def torrents_by_category(self) -> List[Dict]:
        url = f"{self.base}/api/v2/torrents/info"
        r = self.sess.get(
            url,
            params={"category": self.cfg.qb_category},
            timeout=15,
            verify=self.cfg.verify_ssl,
        )
        r.raise_for_status()
        return r.json()

    def set_up_limit(self, hashes: str, limit_bps: int):
        url = f"{self.base}/api/v2/torrents/setUploadLimit"
        r = self.sess.post(
            url, data={"hashes": hashes, "limit": limit_bps}, timeout=15, verify=self.cfg.verify_ssl
        )
        r.raise_for_status()

    def set_down_limit(self, hashes: str, limit_bps: int):
        url = f"{self.base}/api/v2/torrents/setDownloadLimit"
        r = self.sess.post(
            url, data={"hashes": hashes, "limit": limit_bps}, timeout=15, verify=self.cfg.verify_ssl
        )
        r.raise_for_status()
    def pause(self, hashes: str):
        # qB v5: stop；qB v4: pause
        for path in ("/api/v2/torrents/stop", "/api/v2/torrents/pause"):
            url = f"{self.base}{path}"
            r = self.sess.post(url, data={"hashes": hashes}, timeout=15, verify=self.cfg.verify_ssl)
            if r.status_code == 404:
                continue
            r.raise_for_status()
            return
        raise RuntimeError("Neither /torrents/stop nor /torrents/pause exists (check WebUI base url/port).")

    def resume(self, hashes: str):
        # qB v5: start；qB v4: resume
        for path in ("/api/v2/torrents/start", "/api/v2/torrents/resume"):
            url = f"{self.base}{path}"
            r = self.sess.post(url, data={"hashes": hashes}, timeout=15, verify=self.cfg.verify_ssl)
            if r.status_code == 404:
                continue
            r.raise_for_status()
            return
        raise RuntimeError("Neither /torrents/start nor /torrents/resume exists (check WebUI base url/port).")


    def add_tags(self, hashes: str, tags: str):
        url = f"{self.base}/api/v2/torrents/addTags"
        r = self.sess.post(
            url, data={"hashes": hashes, "tags": tags}, timeout=15, verify=self.cfg.verify_ssl
        )
        r.raise_for_status()

    def remove_tags(self, hashes: str, tags: str):
        url = f"{self.base}/api/v2/torrents/removeTags"
        r = self.sess.post(
            url, data={"hashes": hashes, "tags": tags}, timeout=15, verify=self.cfg.verify_ssl
        )
        r.raise_for_status()


# =========================
# Worker：轮询执行
# =========================
worker_thread: Optional[threading.Thread] = None
worker_stop = threading.Event()
worker_last_status = {"running": False, "last_run": None, "last_error": None, "last_action": None}


def _join_hashes(hs: List[str]) -> str:
    return "|".join(hs) if hs else ""


def _is_paused_state(state: str) -> bool:
    s = (state or "").strip().lower()
    if "paused" in s:
        return True
    if s in ("stopped", "stoppedup", "stoppeddl"):
        return True
    return False


def apply_once(cfg: Config) -> str:
    qb = QB(cfg)
    qb.login()
    torrents = qb.torrents_by_category()

    now = int(time.time())
    delay_seconds = cfg.delay_minutes * 60

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

        has_pause_tag = cfg.pause_tag in tags if cfg.pause_tag else False
        has_done_tag = cfg.done_tag in tags if cfg.done_tag else False

        # -------- 限速模式 --------
        if cfg.mode == "limit":
            if age < delay_seconds:
                to_limit.append(h)
            else:
                if cfg.clear_after:
                    to_clear.append(h)
            continue

        # -------- 暂停/恢复模式 --------
        if age < delay_seconds:
            if cfg.pause_before_delay:
                to_pause.append(h)
                if cfg.pause_tag and (not has_pause_tag):
                    to_tag_pause.append(h)
            continue

        # 到点后：恢复
        if cfg.use_done_tag and has_done_tag:
            continue

        if cfg.resume_requires_tag and (not has_pause_tag):
            continue

        if cfg.resume_only_when_paused and (not _is_paused_state(state)):
            continue

        to_resume.append(h)
        if cfg.use_done_tag and cfg.done_tag and (not has_done_tag):
            to_tag_done.append(h)
        if cfg.resume_requires_tag and cfg.pause_tag and has_pause_tag:
            to_untag_pause.append(h)

    action_msg: List[str] = []

    if cfg.mode == "limit":
        up_bps = cfg.up_limit_kib * 1024
        down_bps = cfg.down_limit_kib * 1024

        if to_limit:
            qb.set_up_limit(_join_hashes(to_limit), up_bps)
            action_msg.append(f"限速 {len(to_limit)} 个：UP={cfg.up_limit_kib}KiB/s")
            if cfg.down_limit_kib > 0:
                qb.set_down_limit(_join_hashes(to_limit), down_bps)
                action_msg.append(f"同时 DOWN={cfg.down_limit_kib}KiB/s")

        if to_clear:
            qb.set_up_limit(_join_hashes(to_clear), -1)
            if cfg.down_limit_kib > 0:
                qb.set_down_limit(_join_hashes(to_clear), -1)
            action_msg.append(f"清除限速 {len(to_clear)} 个（-1）")

    else:
        if to_pause:
            qb.pause(_join_hashes(to_pause))
            action_msg.append(f"暂停 {len(to_pause)} 个（前{cfg.delay_minutes}分钟）")

        if to_tag_pause:
            qb.add_tags(_join_hashes(to_tag_pause), cfg.pause_tag)
            action_msg.append(f"打标签 {len(to_tag_pause)} 个：{cfg.pause_tag}")

        if to_resume:
            qb.resume(_join_hashes(to_resume))
            action_msg.append(f"恢复 {len(to_resume)} 个（≥{cfg.delay_minutes}分钟）")

        if to_tag_done:
            qb.add_tags(_join_hashes(to_tag_done), cfg.done_tag)
            action_msg.append(f"打标签 {len(to_tag_done)} 个：{cfg.done_tag}")

        if to_untag_pause:
            qb.remove_tags(_join_hashes(to_untag_pause), cfg.pause_tag)
            action_msg.append(f"去标签 {len(to_untag_pause)} 个：{cfg.pause_tag}")

    return "；".join(action_msg) if action_msg else "无操作（没有符合条件的种子）"


def worker_loop():
    worker_last_status["running"] = True
    worker_last_status["last_error"] = None

    while not worker_stop.is_set():
        try:
            cfg = load_config()
            msg = apply_once(cfg)
            worker_last_status["last_run"] = int(time.time())
            worker_last_status["last_action"] = msg
            worker_last_status["last_error"] = None
        except Exception as e:
            worker_last_status["last_run"] = int(time.time())
            worker_last_status["last_error"] = str(e)

        try:
            sleep_s = load_config().poll_seconds
        except Exception:
            sleep_s = 60
        worker_stop.wait(sleep_s)

    worker_last_status["running"] = False


# =========================
# Flask Web
# =========================
app = Flask(__name__)
app.secret_key = FLASK_SECRET


@app.get("/")
@require_basic_auth
def index():
    cfg = load_config()
    return render_template("index.html", cfg=cfg, status=worker_last_status)


@app.post("/save")
@require_basic_auth
def save():
    cfg, errors = validate_form(request.form)
    if errors:
        for e in errors:
            flash(e, "error")
        return redirect(url_for("index"))

    save_config(cfg)
    flash("保存成功", "ok")
    return redirect(url_for("index"))


@app.post("/test")
@require_basic_auth
def test_conn():
    cfg, errors = validate_form(request.form)
    if errors:
        return jsonify({"ok": False, "errors": errors}), 400
    try:
        qb = QB(cfg)
        qb.login()
        return jsonify({"ok": True, "msg": "登录成功"}), 200
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 500


@app.post("/run-once")
@require_basic_auth
def run_once():
    try:
        cfg = load_config()
        msg = apply_once(cfg)
        flash(f"执行完成：{msg}", "ok")
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
    flash("已启动后台控制", "ok")
    return redirect(url_for("index"))


@app.post("/stop")
@require_basic_auth
def stop_worker():
    worker_stop.set()
    flash("已请求停止（下一轮轮询会退出）", "ok")
    return redirect(url_for("index"))


@app.get("/status")
@require_basic_auth
def status():
    return jsonify(worker_last_status)


if __name__ == "__main__":
    bind_host = os.getenv("BIND_HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "9876"))
    app.run(host=bind_host, port=port, debug=False)