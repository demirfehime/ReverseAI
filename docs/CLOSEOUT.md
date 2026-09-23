# ReverseAI 本阶段收尾记录

日期：2026-09-21。范围：本地 metadata-only 工作台。

## 本轮完成

- `app.js`：修复新建 Case 沿用其他 Case 样本的问题；为空 MIME 提供默认值；离线时阻止样本登记、任务创建和 Case 假成功提示。
- 复核备注在渲染后保留；输入备注期间暂停定时刷新；隐藏页面暂停轮询，并防止轮询请求重叠。
- 复核进度根据已接受、已拒绝记录占比计算，包含演示记录；不再固定显示 92%。高风险数量按非演示样本计算，不把置信度当成风险。
- 快捷分诊按钮调用实际任务登记接口；适配器未配置时返回 blocked。新建报告按钮可下载 JSON。
- `index.html`：移除报告的虚构文件大小，明确证据图为流程示意，修正登记样本和演示状态文案。
- `server.py`：异常配置返回明确的校验错误，状态加载失败时关闭已绑定的服务端口。
- `smoke-test.py`：默认自动启动隔离服务，测试完成后清理临时数据，避免恢复整个状态文件而覆盖用户操作。
- 增补后端与前端行为回归；新增 `.gitignore`，排除运行数据、本地配置和 Python 缓存。

## 验证

```powershell
python -m unittest discover -s tests -v
node tests/test_frontend.cjs
python smoke-test.py
python -m py_compile server.py adapters.py smoke-test.py tests/test_api.py
node --check app.js
```

结果：17 项后端测试通过，前端行为检查、隔离 API 全流程冒烟、Python 编译和 JavaScript 语法检查通过。本轮未进行真实浏览器视觉验收。工作区演示数据未被测试改写。

## 启动与验收

运行 `./start-server.ps1`，访问 `http://127.0.0.1:8787/`。

建议验收：新建 Case 后上下文为空；登记样本可成功；分诊任务显示阻塞；人工复核输入不被定时刷新清空；报告可下载 JSON / HTML / Markdown。

## 后续范围

真实 Ghidra、Frida、LLM worker 尚未实现，本次没有连接工具或执行样本。静态时间线、工具页代码和证据图仍是标注的演示内容，不能作为分析结果。本项目尚不是完整的生产级逆向平台。

当前目录不是 Git 仓库，本轮未提交代码或发布部署。历史交接文档中的 PID 和“下一步”清单仅供参考，应以当前代码和本记录为准。
