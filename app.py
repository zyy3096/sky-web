import json
import os
import re
import threading
import time
from dataclasses import dataclass, asdict
from functools import wraps
from typing import Optional, Tuple

import requests
from flask import Flask, Response, flash, redirect, render_template, request, url_for

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(APP_DIR, "config.json")

# -----------------------
# Web 登录（BasicAuth）
# -----------------------
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change-me")  # 请务必改
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
        {"WWW-Authenticate": 'Basic realm="qb-limit-web"'},
      )
    return fn(*args, **kwargs)
  return wrapper

# -----------------------
# 配置与校验
# -----------------------
HOST_RE = re.compile(r"^[a-zA-Z0-9.\-]+$")  # 只允许 hostname / IP（不带协议/路径）

def _is_valid_host(host: str) -> bool:
  return bool(host and len(host) <= 255 and HOST_RE.match(host))

def _is_valid_scheme(s: str) -> bool:
  return s in ("http", "https")

def _parse_int(name: str, v: str, min_v: int, max_v: int) -> Tuple[Optional[int], Optional[str]]:
  try:
    iv = int(v)
  except Exception:
    return None, f"{name} 必须是整数"
  if iv < min_v or iv > max_v:
    return None, f"{name} 必须在 {min_v}~{max_v} 之间"
  return iv, None

def _is_valid_mode(m: str) -> bool:
  return m in ("limit", "pause_resume")

@dataclass
class Config:
  qb_scheme: str = "http"
  qb_host: str = "127.0.0.1"
  qb_port: int = 8080
  qb_username: str = "admin"
  qb_password: str = ""              # ⚠️ 明文保存到 config.json（只建议内网）
  qb_category: str = "sky"

  mode: str = "pause_resume"         # ✅ limit / pause_resume

  # 限速模式参数
  up_limit_kib: int = 10             # KiB/s
  down_limit_kib: int = 0            # KiB/s（0=不设置下载限速）
  clear_after: bool = True           # 到时后清除限速（-1）

  # 暂停/恢复模式参数
  pause_tag: str = "SKY_DELAYED"     # 暂停时打这个 tag，恢复时只恢复带这个 tag 的
  resume_only_when_paused: bool = True  # 仅当 state=paused* 才恢复（更稳）

  # 通用参数
  delay_minutes: int = 45            # 前 N 分钟执行“限速/暂停”
  poll_seconds: int = 30             # 轮询间隔
  verify_ssl: bool = True            # https 自签证书可关

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

  pause_tag = (form.get("pause_tag") or "SKY_DELAYED").strip()

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
  if mode == "pause_resume" and not pause_tag:
    errors.append("pause_tag 不能为空（用于避免误恢复）")

  qb_port, e = _parse_int("qb_port", form.get("qb_port", ""), 1, 65535)
  if e: errors.append(e)

  delay_minutes, e = _parse_int("delay_minutes", form.get("delay_minutes", ""), 1, 10_000_000)
  if e: errors.append(e)

  poll_seconds, e = _parse_int("poll_seconds", form.get("poll_seconds", ""), 5, 3600)
  if e: errors.append(e)

  up_limit_kib, e = _parse_int("up_limit_kib", form.get("up_limit_kib", "0") or "0", 0, 10_000_000)
  if e: errors.append(e)

  down_limit_kib, e = _parse_int("down_limit_kib", form.get("down_limit_kib", "0") or "0", 0, 10_000_000)
  if e: errors.append(e)

  verify_ssl = form.get("verify_ssl") == "on"
  clear_after = form.get("clear_after") == "on"
  resume_only_when_paused = form.get("resume_only_when_paused") == "on"

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
    up_limit_kib=up_limit_kib,
    down_limit_kib=down_limit_kib,
    clear_after=clear_after,
    pause_tag=pause_tag,
    resume_only_when_paused=resume_only_when_paused,
    delay_minutes=delay_minutes,
    poll_seconds=poll_seconds,
    verify_ssl=verify_ssl,
  )
  return cfg, []

# -----------------------
# qB API 封装
# -----------------------
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

  def torrents_by_category(self):
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
    r = self.sess.post(url, data={"hashes": hashes, "limit": limit_bps}, timeout=15, verify=self.cfg.verify_ssl)
    r.raise_for_status()

  def set_down_limit(self, hashes: str, limit_bps: int):
    url = f"{self.base}/api/v2/torrents/setDownloadLimit"
    r = self.sess.post(url, data={"hashes": hashes, "limit": limit_bps}, timeout=15, verify=self.cfg.verify_ssl)
    r.raise_for_status()

  def pause(self, hashes: str):
    url = f"{self.base}/api/v2/torrents/pause"
    r = self.sess.post(url, data={"hashes": hashes}, timeout=15, verify=self.cfg.verify_ssl)
    r.raise_for_status()

  def resume(self, hashes: str):
    url = f"{self.base}/api/v2/torrents/resume"
    r = self.sess.post(url, data={"hashes": hashes}, timeout=15, verify=self.cfg.verify_ssl)
    r.raise_for_status()

  def add_tags(self, hashes: str, tags: str):
    url = f"{self.base}/api/v2/torrents/addTags"
    r = self.sess.post(url, data={"hashes": hashes, "tags": tags}, timeout=15, verify=self.cfg.verify_ssl)
    r.raise_for_status()

  def remove_tags(self, hashes: str, tags: str):
    url = f"{self.base}/api/v2/torrents/removeTags"
    r = self.sess.post(url, data={"hashes": hashes, "tags": tags}, timeout=15, verify=self.cfg.verify_ssl)
    r.raise_for_status()

# -----------------------
# Worker
# -----------------------
worker_thread: Optional[threading.Thread] = None
worker_stop = threading.Event()
worker_last_status = {"running": False, "last_run": None, "last_error": None, "last_action": None}

def _split_hashes(hs):
  return "|".join(hs) if hs else ""

def apply_once(cfg: Config) -> str:
  qb = QB(cfg)
  qb.login()
  torrents = qb.torrents_by_category()

  now = int(time.time())
  delay_seconds = cfg.delay_minutes * 60

  # qB torrents/info 常用字段：
  # - added_on: 秒时间戳
  # - hash: 字符串
  # - state: pausedUP/pausedDL/stalledUP/uploading 等
  # - tags: "a, b, c"
  to_limit = []
  to_clear = []
  to_pause = []
  to_resume = []
  to_tag_pause = []
  to_untag = []

  for t in torrents:
    h = t.get("hash")
    added_on = int(t.get("added_on") or 0)
    if not h or not added_on:
      continue

    age = now - added_on
    state = str(t.get("state") or "")
    tags = str(t.get("tags") or "")
    has_pause_tag = cfg.pause_tag in [x.strip() for x in tags.split(",") if x.strip()]

    # ------ 模式 A：限速 ------
    if cfg.mode == "limit":
      if age < delay_seconds:
        to_limit.append(h)
      else:
        if cfg.clear_after:
          to_clear.append(h)
      continue

    # ------ 模式 B：暂停/恢复 ------
    # 规则：前 N 分钟暂停（并打 tag）；>=N 分钟后只恢复带 tag 的（防误恢复）
    if age < delay_seconds:
      # 前 N 分钟：确保暂停 + 打 tag
      # 不强依赖 state 是否 paused：直接 pause 是幂等操作
      to_pause.append(h)
      if not has_pause_tag:
        to_tag_pause.append(h)
    else:
      # 到点后：只恢复脚本暂停过的
      if has_pause_tag:
        if cfg.resume_only_when_paused:
          if "paused" in state.lower() or state in ("Stopped", "stopped"):
            to_resume.append(h)
            to_untag.append(h)
        else:
          to_resume.append(h)
          to_untag.append(h)

  action_msg = []

  if cfg.mode == "limit":
    up_bps = cfg.up_limit_kib * 1024
    down_bps = cfg.down_limit_kib * 1024

    if to_limit:
      qb.set_up_limit(_split_hashes(to_limit), up_bps)
      action_msg.append(f"限速 {len(to_limit)} 个：UP={cfg.up_limit_kib}KiB/s")
      if cfg.down_limit_kib > 0:
        qb.set_down_limit(_split_hashes(to_limit), down_bps)
        action_msg.append(f"同时 DOWN={cfg.down_limit_kib}KiB/s")

    if to_clear:
      qb.set_up_limit(_split_hashes(to_clear), -1)
      if cfg.down_limit_kib > 0:
        qb.set_down_limit(_split_hashes(to_clear), -1)
      action_msg.append(f"清除限速 {len(to_clear)} 个（-1）")

  else:
    # pause/resume 模式
    if to_pause:
      qb.pause(_split_hashes(to_pause))
      action_msg.append(f"暂停 {len(to_pause)} 个（前{cfg.delay_minutes}分钟）")

    if to_tag_pause:
      qb.add_tags(_split_hashes(to_tag_pause), cfg.pause_tag)
      action_msg.append(f"打标签 {len(to_tag_pause)} 个：{cfg.pause_tag}")

    if to_resume:
      qb.resume(_split_hashes(to_resume))
      action_msg.append(f"恢复 {len(to_resume)} 个（≥{cfg.delay_minutes}分钟）")

    if to_untag:
      # 恢复后把 tag 去掉，避免反复恢复
      qb.remove_tags(_split_hashes(to_untag), cfg.pause_tag)
      action_msg.append(f"去标签 {len(to_untag)} 个：{cfg.pause_tag}")

  if not action_msg:
    return "无操作（没有符合条件的种子）"
  return "；".join(action_msg)

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
    worker_stop.wait(load_config().poll_seconds)

  worker_last_status["running"] = False

# -----------------------
# Flask Web
# -----------------------
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
    return {"ok": False, "errors": errors}, 400
  try:
    qb = QB(cfg)
    qb.login()
    return {"ok": True, "msg": "登录成功"}, 200
  except Exception as e:
    return {"ok": False, "msg": str(e)}, 500

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

if __name__ == "__main__":
  app.run(host="127.0.0.1", port=9876, debug=False)
