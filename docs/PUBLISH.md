# 发布到 GitHub

仓库已经满足"可直接上传"的全部条件，只差一个远端地址。

## 现状

- 5 个 commit，工作树干净
- 29 个被跟踪文件，`ctf2arena/` + `tests/` 约 3.5k 行
- 80 个离线测试全过（`python -m unittest discover -s tests`）
- `.gitignore` 已排除 `plays/`、`writeups/`、`memory/`、`skill_drafts/`、`vendor/`
  —— 这些目录里有真实 flag，绝不能进公开仓库

## 一步发布

```bash
# HTTPS（PAT 作密码）
git remote add origin https://<user>/<repo>.git
git push -u origin main

# 或 SSH
git remote add origin git@github.com:<user>/<repo>.git
git push -u origin main
```

## 发布前自检

```bash
# 1. 确认没有 flag 泄漏
git grep -nE '[A-Za-z]{3,}\{[0-9a-f-]{8,}\}' $(git rev-list --all) || echo "clean"

# 2. 确认被跟踪文件里没有 plays/writeups/memory
git ls-files | Select-String -Pattern '^(plays|writeups|memory)/' || echo "clean"

# 3. 测试
python -m unittest discover -s tests

# 4. 出包验证（应能成功生成 tar）
git archive --format=tar HEAD -o /tmp/ctf2arena.tar && echo "archive ok"
```

## 需要人工决定的两点

1. **仓库名与可见性**：建议 `ctf2-agent-arena`，public；MIT 许可证已就位。
2. **作者信息**：当前 commit 使用的是本机 git 配置，如需换成你的 GitHub 身份，
   在推送前 `git config user.name/user.email` 并 `git commit --amend --reset-author`。
