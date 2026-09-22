# Driplite Studio

基于 Driplite 3.3 原包恢复的可构建工程，将启动器、本地调参面板和配置管理整合为一个 Windows 应用，支持 nice、123 两套预设。

**目前只还原了部分调参能力，尚未恢复原版全部参数。** 面板现有 44 个模块、99 个字段：41 个模块开关、34 个快捷键、15 个数值参数、8 个条件开关和 1 个模式选择。这个数量不代表所有模块都能完整调参，具体支持项以面板“字段支持情况”和 `catalog.json` 为准。

## 项目组成

| 位置 | 作用 |
| --- | --- |
| `restored_crk/src/launcher.py`、`desktop.py` | 统一入口、预设选择、单实例、本地服务及启动器生命周期 |
| `restored_crk/src/replay.py`、`mock_bootstrap.py` | 从原 Python 字节码恢复的启动流程、资源准备和本地通信 |
| `restored_crk/src/panel_server.py`、`src/panel/` | 网页界面、参数校验、字段目录、修改与撤销 |
| `restored_crk/src/runtime_discovery.py`、`process_memory.py`、`src/panel/writer.js` | 识别运行实例、校验组件身份、应用覆盖并读回 |
| `restored_crk/src/config_store.py`、`hotkeys.py` | 本地配置保存、导入导出与游戏前台快捷键 |
| `restored_crk/tools/prepare_assets.py`、`build.py`、`build.ps1` | 从原包静态提取资源并构建单文件 EXE |
| `restored_crk/tests/`、`tools/verify_studio.py` | 配置逻辑测试和打包应用的本地 HTTP 验证 |

恢复为源码的是 Python 启动器和调参工程；原生 `Drip.exe`、DLL 仍作为原包二进制依赖使用，没有还原其 C++ 源码。源码仓库不跟踪原包、提取资源、会话数据和构建产物；可执行程序通过 Releases 发布。

## 如何使用

直接使用可从 [Releases](https://github.com/NotAlley233/Drip-3.3-cracked/releases) 下载 `Driplite-Studio.exe`，无需安装 Python。下面是自行构建的方法。

构建环境：Windows x64、64 位 Python。已验证 Python 3.14.2。以下命令均在仓库根目录执行。

1. 准备原始资源。把以下两个文件放在同一目录，保持文件名不变；构建时会核对 SHA-256。

   | 文件 | SHA-256 |
   | --- | --- |
   | `Driplite 3.3cracked with nice cfg.exe` | `56908706c64f4a5c80b6d84dbb885bab6ab0e253b5f228c41870424fe6189bad` |
   | `Driplite 3.3cracked with 123 cfg.exe` | `aee4852fdd1ff6203aeec44a0f560b0eb316f842bbc7a57dd5e1aacb26d30f27` |

2. 构建。若原包位于仓库根目录，直接运行：

   ```powershell
   .\restored_crk\build.ps1
   ```

   若原包位于其他目录，通过 `-InputDir` 指定；只构建一套预设时可加 `-Variant nice` 或 `-Variant 123`。

   ```powershell
   .\restored_crk\build.ps1 -InputDir 'D:\Driplite-originals'
   ```

   脚本会创建独立 `.venv`、安装固定版本依赖、提取资源、打包并自检。默认输出 `restored_crk/dist/Driplite-Studio.exe`，包含两套预设；单预设构建输出 `Driplite-Studio-nice.exe` 或 `Driplite-Studio-123.exe`。

3. 启动 Minecraft，再运行 `Driplite-Studio.exe` 并接受 Windows 提权提示。程序默认选择 nice，启动本地面板并等待游戏连接。使用 123、演示模式或自检：

   ```powershell
   .\restored_crk\dist\Driplite-Studio.exe --variant 123
   .\restored_crk\dist\Driplite-Studio.exe --demo
   .\restored_crk\dist\Driplite-Studio.exe --self-test
   ```

4. 在面板中选择模块、调整已支持的参数或绑定快捷键，查看读回状态。修改自动保存，也可撤销、恢复原配置、保存命名方案或导入导出 JSON。切换预设前，在“界面设置”中选择“断开并关闭本地服务”，再以另一预设启动；仅关闭浏览器标签页不会退出程序。

面板默认使用 `http://127.0.0.1:8770`，端口占用时自动尝试后续端口。`--no-browser` 可关闭自动打开浏览器，`--no-inject` 可仅连接现有运行实例，`--data` 可指定配置目录。

nice 的数据保存在 `%LOCALAPPDATA%\DriplitePanel`，123 保存在其 `123` 子目录；演示与实际运行分别使用 `demo`、`live` 子目录。演示模式只操作本地副本。

开发时可在资源准备完成后直接运行源码或测试：

```powershell
.\restored_crk\.venv\Scripts\python.exe .\restored_crk\src\launcher.py --demo
.\restored_crk\.venv\Scripts\python.exe -m unittest discover -s .\restored_crk\tests -v
.\restored_crk\.venv\Scripts\python.exe .\restored_crk\tools\verify_studio.py
```

## 原理

构建工具静态读取原包的 PyInstaller 归档，核对原包哈希后提取原生程序、DLL、脚本和预设。恢复的 Python 源码与这些资源一起重新打包；启动时运行工程自身的启动器入口。

调参面板通过仅监听本机的 HTTP 服务与 Python 控制器通信。字段目录记录已确认字段的类型、偏移和范围，控制器检查输入，并通过 Frida 在加载器配置拷贝时应用覆盖；随后读回状态供页面显示。原始配置作为基线保存，撤销、暂停同步和恢复原配置都围绕覆盖值工作。

用户修改以 JSON 原子写入本地，重启后重新载入。自定义快捷键由面板统一处理，只在目标游戏位于前台时切换对应模块；原生同名按键会在输出副本中停用，避免重复切换。

尚未完成映射的参数不会作为可调字段开放。当前已验证构建、自检、配置往返及本地 HTTP 流程；尚未完成真实游戏内的端到端验证。

## 鸣谢

原包来源：**x3z**。按原说明顺序，感谢 **gangjiaomi105、skateboardpig、fm8964、X3z、不语**。

工程使用了 [Python](https://www.python.org/)、[PyInstaller](https://pyinstaller.org/)、[Frida](https://frida.re/)、[PyNaCl](https://pynacl.readthedocs.io/)、[cffi](https://cffi.readthedocs.io/) 和 [xdis](https://github.com/rocky/python-xdis)。本仓库中的恢复实现并非原作者发布的完整源码。
