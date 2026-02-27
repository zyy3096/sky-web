# sky-web

一个小型 Web 面板：控制远程 qBittorrent（按 **added_on 添加时间**）对指定分类执行：

- **限速模式**：前 N 分钟限速，上下行可配；到点后可选清除限速（-1）
- **暂停/恢复模式**：前 N 分钟可选强制暂停；到点后恢复（适合 RSS 进种自动暂停 + 延迟开始上传）

## 安装运行

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export ADMIN_USER=admin
export ADMIN_PASSWORD='改成强密码'
export FLASK_SECRET='改成随机长字符串'

python app.py
```

浏览器访问：`http://127.0.0.1:9876`（BasicAuth）

## 环境变量

- `ADMIN_USER` / `ADMIN_PASSWORD`：Web 登录凭证
- `FLASK_SECRET`：Flask session secret
- `BIND_HOST`：绑定地址（默认 127.0.0.1）
- `PORT`：端口（默认 9876）

## 安全提醒

- `config.json` 会保存远程 qB 的账号密码（明文），请只在内网/VPN/SSH 隧道环境使用。
- 不建议直接暴露到公网。
