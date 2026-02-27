# sky-web (v2)

多 qB 控制面板（按 qB torrents/info 的 **added_on** 添加时间）对指定分类执行：

- **暂停/恢复**：适合 RSS 进种自动暂停 → 到点恢复上传
- **限速/清除限速**：前 N 分钟限速，到点可选清除限速（-1）

## 远程安装

```bash
bash install.sh
```

脚本会提示输入：
- Web 绑定地址（127.0.0.1 / 0.0.0.0）
- Web 端口
- BasicAuth 账号密码

## 安全说明

- qB 密码会以明文保存在 `config.json`（仅建议内网/VPN/SSH 隧道环境使用）
- 不建议直接暴露到公网；如需外网请加反代 + HTTPS + 额外认证 + 防火墙
