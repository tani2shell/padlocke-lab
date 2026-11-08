# padlocke-lab（日本語）

本編は [README.md](README.md)（英語）。要点のみ:

- **ジャンル**: パディングオラクルでセッション Cookie 解読 → 暗号文 1 バイト反転で権限昇格 → 素の pickle で RCE → SUID ヘルパーで root、の四段チェーン。
- **起動**: `docker compose up -d --build` → `http://127.0.0.1:18962`
- **リセット**: `./RESET.sh`
- **フラグ**: 2 枚（容器内 `local.txt` / root 読み取り限定 `proof.txt`）
- **難易度**: 3.5/5（AI ペンテストエージェント実戦較正済み、`DIFFICULTY.md` 参照）
- 問題文（ネタバレなし）は `CHALLENGE.md`、解答は `SOLUTION.md`。
