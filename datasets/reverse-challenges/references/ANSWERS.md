# 中文过程导读与参考答案（含剧透）

以下是对官方作者题解的简短导读，完整步骤、截图与代码见各题 PDF。答案仅从公开题解摘录，**未运行样本，未执行解题代码，未在本地验证**。

## 1. X

从 .NET 游戏主入口定位实际业务程序集及按钮事件，查看两个数字如何组成口令，再找到成功分支的提示字符串。作者给出了字符串检索和反编译两种可替代路径。

- 解锁值：`42`。
- Flag：`glorified_captcha@flare-on.com`。
- [本地题解](01-x/official-solution.pdf)，第 2–3 页；[官方原文](https://services.google.com/fh/files/misc/1-x-flareon10.pdf)。

## 2. ItsOnFire

先从 Manifest 和消息处理类识别入口，再跟踪星期命令与资源 ID；沿 `wednesday` 分支还原资源字符串参与的 CRC32 密钥派生，按 AES 解密流程恢复包含答案的图片。完整静态路线见第 25–28 页。

- Flag：`YOUr3_ON_F1r3_K33P_6O1N6@flare-on.com`。
- [本地题解](02-itsonfire/official-solution.pdf)，答案文字在第 25 页；[官方原文](https://services.google.com/fh/files/misc/2-itsonfire-flareon10.pdf)。

## 3. Mypassion

将输入分段和大型上下文结构对应起来，逐阶段恢复文件、时间、字符串及嵌入代码约束；随后识别置换与加密逻辑，完成最终输入条件。日期相关字符依赖运行当天，不能将题解中的示例命令视为永远有效的固定输入；原 PDF 日期公式与示例存在不一致，后续测试需另行核实，本轮未作推断性修正。

- Flag：`b0rn_t0_5truc7_b4by@flare-on.com`。
- [本地题解](03-mypassion/official-solution.pdf)，答案第 9 页；[官方原文](https://services.google.com/fh/files/misc/3-mypassion-flareon10.pdf)。

## 4. Aimbot

从启动器的资源解密与通信协议进入 DLL，梳理反调试和环境约束，再跟踪串联载荷中使用环境数据派生密钥的流程；最终校验与游戏状态相关。原题有真实系统副作用，收录不代表允许在日常系统直接执行。

- Flag：`computer_ass1sted_ctfing@flare-on.com`。
- [本地题解](04-aimbot/official-solution.pdf)，答案第 4 页；[官方原文](https://services.google.com/fh/files/misc/4-aimbot-flareon10.pdf)。

## 5. Where_am_i

围绕代码在执行过程中的变化还原阶段关系，追踪加载器、命名管道与路径条件；再定位承载加密答案的数据及 RC6 解密参数。作者给出了 WinDbg 时间旅行调试的分析过程与辅助脚本。

- Flag：`WheR3_4m_I_fr0m_0TF@flare-on.com`。
- [本地题解](05-where-am-i/official-solution.pdf)，答案第 19 页；[官方原文](https://services.google.com/fh/files/misc/5-where-am-i-flareon10.pdf)。

## 6. HVM

从 Hypervisor API 调用理解宿主与虚拟机关系，按 16/32/64 位切换划分代码；识别 I/O 导致的虚拟机退出与按函数解密机制，再还原名称和序列号校验。作者最后给出了完整计算脚本及输出，本次仅保存参考输出。

- Name：`FLARE2023FLARE2023FLARE2023FLARE2023`。
- Serial：`zBYpTBUWJvf9MUH4KtcYv7sdUVUPcjOCiU5G5i63bb+LLBZsAmEk9YlNMplv5SiN`。
- Flag：`c4n_i_sh1p_a_vm_as_an_exe_ask1ng_4_a_frnd@flare-on.com`。
- [本地题解](12-hvm/official-solution.pdf)，答案第 9 页；[官方原文](https://services.google.com/fh/files/misc/12-hvm-flareon10.pdf)。
