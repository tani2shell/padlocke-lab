# padlocke-lab（中文）

正文见 [README.md](README.md)（英文）。要点：

- **类型**：填充预言破解会话 Cookie → 翻一位密文提权 → 裸 pickle RCE → SUID 助手拿 root，四段链一体。
- **启动**：`docker compose up -d --build` → `http://127.0.0.1:18962`
- **重置**：`./RESET.sh`
- **旗子**：两面（容器内 `local.txt` / 仅 root 可读 `proof.txt`）
- **难度**：3.5/5（经 AI 渗透靶手实战标定，见 `DIFFICULTY.md`）
- 题面（零泄底）在 `CHALLENGE.md`，题解在 `SOLUTION.md`。
