# Adapter contract v1

## 已实现范围（2026-09-22）

补充：项目提供独立命令行入口 `tools/analyze_apk.py` 和网页任务 worker `tools/web_apk_worker.py`，详见 [APK 调查流程](APK_INVESTIGATION.md)。二者在 UI/API 进程之外运行 JADX 与受限数据运算，尚非本文 Adapter 契约的操作系统隔离沙箱。下文“模型自主工具调用未实现”指原通用运行时接口；APK 入口有明确 allowlist 的 JSON 操作调度。

当前 `runtime.py` 提供文本 Provider、只读 MCP 客户端和有预算的文本子任务；`tools/start_mcp_bridge.py` 单独启动固定版本桥。工具调用要求固定只读清单与用户 allowlist 同时允许，结果进入待复核证据。Skill 只作为版本绑定的参考文本。详情见 [续修记录](REPAIR_2026-09-22.md)。

这些能力不经过旧 `NullAdapter` 执行接口。独立桥进程不是容器沙箱；当前未实现样本执行、进程附加、模型自主工具调用或项目写操作。下文描述这些后续执行 worker 的目标契约，不能作为已实现隔离能力的证明。文本请求包含所选元数据与证据，当前没有通用自动脱敏保证，用户应在发送前检查内容。

## Scope

ReverseAI 的 UI / API / Evidence Store 不直接执行 Ghidra、Frida、脚本或样本。真实工具必须作为独立 worker 接入，并实现 `adapters.py` 中的 `Adapter` 契约。默认 `NullAdapter` fail-closed：调用会返回“未配置”，不会启动进程。

## Request / response boundary

每次适配器调用必须携带：

- `case_id`、`sample_id`、操作者和授权范围；
- 目标对象的固定 SHA-256；
- 任务 ID、工具版本、worker 镜像摘要和 allowlist 工具名；
- 期望的超时、网络策略和输出大小上限。

适配器只能返回结构化证据或“待人工复核提案”，不能直接把写入结果当成已应用。所有输出进入 Evidence Store 前应校验 JSON schema、大小、时间戳、工具版本和输入哈希。

## Ghidra MCP

第一阶段只允许 read-only allowlist，例如函数反编译、调用者 / 被调用者、字符串交叉引用和控制流摘要。重命名、注释、脚本执行和项目写入必须走 proposal → 人工确认 → 独立 worker 应用三步流程。

## Frida

Frida worker 必须一次性、无持久化、默认无网络、无宿主目录挂载，并且只附加到授权沙箱中的测试进程。ReverseAI API 不接受 PID 作为可信授权；PID 只能由 worker 在沙箱内生成并回传。

## LLM

模型只能读取经过脱敏和哈希绑定的证据包。应保存 prompt、工具调用、模型输出、模型版本和人工最终结论。模型不能直接获得写工具 token，也不能绕过人工复核门。

## Rollout checklist

1. 构建并签名 worker 镜像，锁定依赖和 SBOM。
2. 配置 allowlist、超时、资源限制和网络策略。
3. 先在 replay fixture 上测试，不使用真实样本。
4. 开启只读能力并验证审计链，再逐项开放 proposal 能力。
5. 写操作必须由明确的二次确认和可回滚快照保护。
