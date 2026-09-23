# ReverseAI Lab

面向授权逆向研究的本地 AI 工作台：管理 Case、样本、分析任务、证据与报告，支持主 Agent 自主委派、APK 静态调查和只读 Ghidra MCP 接入。

## 当前功能

- Case 与样本管理、证据人工复核、审计链和报告快照。
- Chat Completions、Responses、Anthropic Messages 三种文本协议。
- 主 Agent 按需创建子任务并汇总，可配置子 Provider、模型、数量、并发及调用/时间预算。
- APK 上传、JADX 反编译、代码与资源读取、受限计算和候选结果验证。
- Ghidra MCP 显式只读调用、完整性校验的 Skill 文本参考。
- 分析任务树、证据图谱、主题切换、可折叠导航和可调宽度 Copilot。

子 Agent 当前分析已有文本与证据，APK worker 仍独立运行；原生模型工具调用、流式输出和 Frida 动态分析尚未接入。详见[架构待办](docs/ARCHITECTURE_TODO.md)。

## 快速启动

基本 API 与界面使用 Python 3.10+ 标准库。完整 APK 功能主要在 Windows / Python 3.12 验证。

```powershell
python tools/restore_sources.py
.\start-server.ps1
```

访问 http://127.0.0.1:8787/ ，也可用 `python server.py` 启动。首次恢复第三方源码需要网络；固定版本与下载包 SHA-256 见 `third_party/sources.lock.json`。

在“API 与模型”配置 Provider；在“子 Agent → 配置委派与预算”开启自动模式，再从 Copilot 的 API 模式发送目标。参见 [Agent 使用说明](docs/AGENT_DELEGATION.md)。

### 可选 APK 环境

安装可运行 JADX 的 Java 环境，然后执行：

```powershell
python -m venv .venv-analysis
.\.venv-analysis\Scripts\python.exe -m pip install -r tools/apk-requirements.txt
python tools/setup_jadx.py
```

网页上传 APK 后填写分析目标和预算，模型留空继承 Provider。[APK 调查说明](docs/APK_INVESTIGATION.md)介绍命令行和证据验证。

### 可选 Ghidra MCP 环境

```powershell
python -m venv .venv-mcp
.\.venv-mcp\Scripts\python.exe -m pip install -r tools/mcp-requirements.lock.txt
.\start-mcp.ps1
```

还需配置对应 Ghidra 插件并打开项目；桥连通不代表项目已连接。

## 项目结构

| 位置 | 用途 |
|---|---|
| server.py | 本地 API、持久化与报告 |
| runtime.py / agent_orchestrator.py | 集成运行时、自主委派、预算与汇总 |
| apk_jobs.py / apk_analysis.py | APK 进程管理和分析循环 |
| index.html / app.js | 工作台页面和控制器 |
| settings-ui.js / layout.js | 配置和布局交互 |
| styles.css / graph.js | 样式与证据连线路由 |
| tests/ | Python、Node 回归与浏览器辅助服务 |
| tools/ | 依赖恢复、MCP 桥及分析工具 |
| docs/ | 使用说明、设计、历史记录 |
| third_party/ | 依赖锁文件；下载源码不提交 |
| datasets/ | 公开题目来源与元数据 |
| data/ | 本地运行数据，不提交 |

## 测试

完整回归需要恢复第三方源码、安装 APK 环境；前端检查需要 Node.js。

```powershell
python tools/restore_sources.py --check
python -m unittest discover -s tests -v
node tests/test_frontend.cjs
node tests/test_routing.cjs
python smoke-test.py
```

测试主要使用临时数据和模拟 Provider，不代表真实模型求解成功。Windows 取消测试需要允许终止测试自身启动的进程。

## 发布范围

提交源码、测试、文档、配置示例和依赖锁文件。排除本地数据、凭据、虚拟环境、第三方下载源码、题目二进制与作者 PDF；本地文件保留不删除。

题目附件见[素材说明](datasets/reverse-challenges/README.md)。`config.example.json` 用于旧执行适配器边界，日常 Provider、MCP 和 Agent 配置通过界面维护。

## 文档与使用边界

- [文档索引](docs/README.md)
- [Agent 自主委派](docs/AGENT_DELEGATION.md)
- [架构与界面待办](docs/ARCHITECTURE_TODO.md)
- [第三方依赖与许可](third_party/README.md)

仅用于明确授权的研究、审计与 CTF。服务默认只监听本机；APK worker 不执行样本，但不是操作系统隔离沙箱。配置外部 Provider 后，分析内容会发送至该服务。

当前未为项目原创代码声明开源许可证；公开仓库不等于授予开源许可。第三方组件遵循各自许可证。
