# 第三方依赖

上游源码不提交到本仓库。`sources.lock.json` 记录当前使用的仓库、提交和下载包 SHA-256。

```powershell
python tools/restore_sources.py
python tools/restore_sources.py --check
```

首次恢复需要网络；已有完整文件时不下载。恢复器先校验下载包，再导入固定版本的文本与 Python 源码，不运行第三方安装脚本。恢复后的 `IMPORT_MANIFEST.json` 用于文件完整性检查。

- `bethington/ghidra-mcp`：本地 MCP 桥。使用需配置 Ghidra、插件及项目。
- `zhaoxuya520/reverse-skill`：Skill 文本参考，不自动运行其中的脚本。

各项目的许可证随上游源码恢复；使用与分发时以其许可证为准。本项目未替第三方授予许可。
