# APK 静态调查流程

网页与独立命令行入口均支持从真实反编译代码逐步追踪资源变换并验证计算结果。它不再要求答案必须以明文出现在原始字符串中。

## 网页操作

1. 打开本机工作台，在“API 与模型”启用已有 Provider。
2. 导入 `.apk` 或 `.apk.bin`，文件正文保存到本机 `data/web-apk`，服务端校验 SHA-256。上限 100 MB；其他类型仍只登记元数据。此前只登记过元数据的 APK 需要重新导入一次。
3. 在“分析任务”填写分析目标、可选模型 ID（留空继承默认 Provider）和调用预算，点击“启动任务”。使用首个启用 Provider 的地址和加密凭据，不改写它的默认模型。代码及资源片段会发送至该 API。
4. 页面每 2.5 秒刷新，显示反编译与调用进度；证据进入人工复核队列，任务卡可下载证据 JSON、派生 PNG、反编译记录和最终结果。调用失败及预算耗尽会显示失败，不代表解题成功。
5. 排队和运行中的 APK 任务可取消，服务终止该 worker 及子进程，丢弃取消后的输出。正常关闭服务会清理进程；重启会把未结束任务标为中断，不自动重放。异常强制结束服务时，旧 worker 可能继续到自身预算结束，但结果不会自动导入。

同一时间只接受一个活跃 APK 任务。任务在独立 Python 进程中运行固定 JADX 命令和受限数据操作，**不是操作系统隔离沙箱**，不会执行 APK。反编译最多 300 秒，调查默认 900 秒；服务监督总时限。网页不读取参考答案，候选结果始终需要人工复核。当前流程主要针对已有 APK CTF 数据集，尚非通用 Android 逆向求解器。

当前首个支持范围为 APK 的代码/资源读取，以及字符串切片、拼接、CRC32、AES-CBC 解密和 PNG 结果复核。Windows 原生题、通用虚拟机逆向和动态执行尚未接入此流程。

## 启动

```powershell
python -m venv .venv-analysis
.\.venv-analysis\Scripts\python.exe -m pip install -r tools/apk-requirements.txt
python tools/setup_jadx.py
.\.venv-analysis\Scripts\python.exe tools/analyze_apk.py --apk path/to/sample.apk --model gpt-5.6-sol
```

需要 Java。本次已在项目中安装分析虚拟环境及固定版本的 JADX；下载器使用 [JADX 官方发布包](https://github.com/skylot/jadx/releases/tag/v1.5.6)，校验固定 SHA-256，并保留原始压缩包。固定哈希是本项目记录的下载摘要，不表示独立签名认证。

在现有测试素材上运行：

```powershell
.\.venv-analysis\Scripts\python.exe tools/analyze_apk.py --apk data/challenge-runs/static-baseline-20260922/samples/02-itsonfire/ItsOnFire.apk.bin --corpus data/apk-analysis/itsonfire-jadx --model gpt-5.6-sol --max-calls 12 --seconds 900 --reference-id 02-itsonfire
```

`--corpus` 复用 JADX 输出前会核对 APK 哈希；不用该参数则重新反编译。`--reference-id` 只在调查结束后读取参考答案进行评分，不向模型发送题解。`--seed-run` 可从先前运行重新执行只读证据查询；不加载先前模型答案或计算结果。

## 工作方式

1. 将 APK 交给固定的 JADX 命令解析，保存日志、输入哈希及退出状态。反编译有错误时保留 partial 状态，不能声称所有代码可靠恢复。
2. 建立 Manifest、应用源码、资源表和加密 API 索引。模型可以按需调用 `read`、`search`、`resource`、`list_files`，而不是只获得十几条随机命中的字符串。
3. 模型通过 JSON 请求下一步操作。计算请求使用有类型的节点数组，支持 `resource`、`slice`、`concat`、`crc32_decimal`、`repeat`、`aes_cbc_decrypt`，不接受 Python、Shell 或任意代码。
4. 每一步保存证据 ID、文件哈希、行号及工具输出。提示中省略的 import/注解等样板文本有明确标记，完整证据仍保留。原始源码中的文本不作为系统指令。
5. 最终重新运行计算配方，比对源码、资源和产物哈希；验证候选是否出现在派生结果的 OCR 中，再独立核对参考答案。该验证不要求候选存在于原始字符串里。

模型每次必须返回一个 JSON action。DSML/XML 标记等不兼容输出会记为协议错误，不会自动当作命令执行。模型调用次数和调查时间有上限，连续三次 Provider 错误后停止并保存已有结果。时间预算约束调查调度与模型请求，JADX 准备阶段另有 300 秒超时；这不是硬实时沙箱。

## 图像与复核

OCR 保留原图和对比度处理图两份识别文本，并标记需要视觉复核。下划线、数字与字母相似字符可能被识别错，不能按参考答案自动“纠正”模型输出。

阅图后可用独立的 `tools/review_apk_image.py` 保存转录结果、复核者、说明及产物哈希。该操作不暴露为模型工具，也不改写原模型回答。`automatic_model_success` 始终为 false，避免把人工或助手的视觉复核冒充自动解题。

计算重放证明的是配方可复现且证据未变，并非形式化证明配方与所有程序路径等价；算法解释仍保留待复核状态。

## 本轮实测

- ItsOnFire 的应用代码与资源成功提取，JADX 退出码 3，日志记录 189 个错误；使用了可读取的相关应用函数，未忽略这个不完整状态。
- 基于实际 `f/b.java` 与 `f/c.java` 的本地工具验收完成 CRC32 派生和 AES 解密，生成 PNG。产物 SHA-256 为 `2a93f49facd5cd0ed3406c24e70585e1dc78a163274298958365f7e4f513f3ea`。
- 图片由助手查看后转录，答案与官方参考一致。此验收配方由助手从实际代码整理，**不是 GPT-5.6 自动通关**。
- GPT-5.6-sol 的调查曾定位到相关代码与资源，但遇到不合法配方、DSML 输出和连接失败；所有失败轮次均保留。后续连最短生成请求也超时，而模型列表正常，因此未把远端可用性问题标记为已修复。
- 当前配置接口的 GPT-5.6-terra 最短请求返回 OK，但带源码的调查请求也出现连续失败。正式模型配置未更换；不能把最短请求成功当作完整流程成功。
- 44 项 Python 回归全部通过，随后新增的 1 项完整调查调度用例也通过（合计 45 项）。覆盖派生计算、引用与文件篡改、路径/操作限制、连续 Provider 失败停止、状态读写锁；完整调度用例使用明确标记的本地模型与 OCR fixture，不冒充真实 API。Node 前端和图路由测试通过。JADX 安装脚本也已用本地原始包完成哈希校验与安装复测。

[完整派生计算](../data/apk-analysis/verified-tool-validation/evidence/e0004.json) · [独立图片复核](../data/apk-analysis/verified-tool-validation/visual-review.json) · [解密图片](../data/apk-analysis/verified-tool-validation/derived/2a93f49facd5cd0ed3406c24e70585e1dc78a163274298958365f7e4f513f3ea.png)

模型试跑记录：

- [首轮](../data/apk-analysis/run-20260922-173008-3143ae/result.json)
- [加密索引改进轮](../data/apk-analysis/run-20260922-173607-ecf820/result.json)
- [复用只读证据轮](../data/apk-analysis/run-20260922-223933-310716/result.json)
- [Terra 验收轮](../data/apk-analysis/run-20260922-225317-a4f33f/result.json)

## 与工作台的关系

网页“开始分析”对已上传 APK 使用 `/api/apk/jobs` 创建真实静态任务。原有通用 `/api/analysis/jobs` 的未实现类型仍显示 blocked；PE 静态分诊及动态执行尚未接入。Copilot 提示允许根据真实代码证据推导算法。网页接入不代表模型已自动解出全部题目。

分析命令复用已启用 Provider 的地址和凭据，模型覆盖只用于当次运行，不修改正式配置。数据保存于 `data/apk-analysis/`，不改动正式 Case、任务或凭据；不运行 APK，不访问 APK 中的服务器地址，也不执行模型生成的程序。

同时修复 `Store.load/save` 在同一个 Store 实例内的并发读写竞态：读写共用可重入锁，避免 Windows 原子替换文件时读线程出现 PermissionError。多进程共享状态不在本次修复保证范围内。
