# 公开逆向题素材集

Git 仓库仅包含来源清单、元数据和参考说明；题包和作者 PDF 不随仓库提交。运行 python tools/collect_reverse_challenges.py 恢复下载，按需运行 python tools/catalog_reverse_challenges.py 整理题包；需要网络及相应解包依赖。

收集日期：2026-09-22。已将六道题的原始附件、作者题解、参考答案和来源清单归档到项目。后续已开始首轮测试，见 [测试与调试报告](../../docs/CHALLENGE_TEST_2026-09-22.md)；本目录的 manifest 保留收集时快照，测试状态单独记录。

来源：[FLARE-On 官方题库](https://www.flare-on.com/) · [FLARE-On 10 作者题解入口](https://cloud.google.com/blog/topics/threat-intelligence/flareon10-challenge-solutions/)。选用同一届比赛便于保持附件与答案对应，覆盖不同格式和逆向技术。

| 建议顺序 | 题目 | 难度（本项目建议） | 内容 | 原始题包 | 作者完整过程 |
|---|---|---|---|---|---|
| 1 | X | 入门 | .NET、字符串、口令判断 | [X.7z](challenges/01-x/X.7z) | [PDF，3 页](references/01-x/official-solution.pdf) |
| 2 | ItsOnFire | 初级 | APK、资源引用、AES | [ItsOnFire.7z](challenges/02-itsonfire/ItsOnFire.7z) | [PDF，28 页](references/02-itsonfire/official-solution.pdf) |
| 3 | Mypassion | 中高级 | 原生程序、多阶段输入校验 | [mypassion.7z](challenges/03-mypassion/mypassion.7z) | [PDF，9 页](references/03-mypassion/official-solution.pdf) |
| 4 | Aimbot | 高级 | 反调试、环境校验、多阶段载荷 | [aimbot.7z](challenges/04-aimbot/aimbot.7z) | [PDF，4 页](references/04-aimbot/official-solution.pdf) |
| 5 | Where_am_i | 高级 | 自修改代码、反射加载、RC6 | [where_am_i.7z](challenges/05-where-am-i/where_am_i.7z) | [PDF，22 页](references/05-where-am-i/official-solution.pdf) |
| 6 | HVM | 挑战级 | Hyper-V、多位宽代码、加密校验 | [hvm.7z](challenges/12-hvm/hvm.7z) | [PDF，9 页](references/12-hvm/official-solution.pdf) |

难度不是官方评级，也不保证严格线性；官方特别指出第 3 题有明显难度跃升，第 4、5 题各有侧重。HVM 为第 12 题，作为高难度扩展项。

## 本地材料

- `challenges/`：按题分开的官方原始加密题包，以及 `archive-members.json` 文件目录。密码均为 `flare`。原包保留压缩状态；后续测试提取的数据单独存放于项目 `data/challenge-runs/`。
- `references/`：六份完整作者题解 PDF。
- [中文过程导读与答案](references/ANSWERS.md)：单独存放的参考资料，后续盲测不应作为待分析输入。
- [答案 JSON](references/answers.json)：便于后续比对；全部标记为来自作者题解、未在本地复现。
- [manifest.json](manifest.json)：题目索引、平台、建议顺序和状态，不含 flag。
- [downloads.json](downloads.json)：下载 URL、字节数、SHA-256。
- `SHA256SUMS.txt`：本素材目录其余文件的完整性清单；下载哈希是本地计算值，不等于官方公布的校验值。
- `archives/Flare-On10_Challenges.7z`：官方完整原包（43,162,065 字节），还包含另外七题；那七题未纳入本次精选清单，也未配齐题解。

## 后续使用边界

最初的“导入项目”指归档到项目文件目录。后续授权测试使用独立状态完成元数据导入与真实模型调用，未改动正式 `data/state.json`；具体范围与结果以测试报告为准。

后续使用时先选择一道题，在适当的分析环境解包，再根据 `archive-members.json` 选择主程序及依赖。X 需要保留配套框架文件；ItsOnFire 的静态解法见 PDF 第 25–28 页，不需要连接旧比赛服务。动态运行 APK 的原题环境为 Android 11/API 30 及以上；HVM 动态路径涉及 Windows Hypervisor Platform。依赖只记录，未安装。

Aimbot 的作者明确说明题目含挖矿组件、进程注入和仿窃密行为，后续不能直接在日常宿主机运行。此处仅保留官方加密附件。

材料版权归原作者与发布方。公开下载不代表统一开源许可；本目录保留来源用于本地学习和测试准备。
