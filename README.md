# Chiiki

**注意：本项目为纯 Vibe Coding 项目**

为在中文 Windows 上运行日语（或其他 CJK）游戏而设计的区域模拟注入工具。

通过 [Microsoft Detours](https://github.com/microsoft/Detours) 内联钩子拦截 Windows 区域相关 API，使目标进程误认为系统处于指定的语言环境，从而解决乱码、字体缺失等问题，而无需修改系统区域设置。

## 构建

**环境要求**

- Windows 10/11 x64
- Visual Studio 2022（含 MSVC 工具链）
- CMake 3.15+（VS 自带）

**一键构建**

```bat
build.bat
```

产物输出到 `build\Release\`（`chiiki.exe` + `chiiki.dll`）。

**手动构建**

```bat
cmake -Bbuild -H. -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

## 用法

```
chiiki.exe [--cp=XXXX] [游戏路径\Game.exe] [额外参数...]
```

| 参数 | 说明 |
|---|---|
| `--cp=932` | 日语 Shift-JIS（**默认**） |
| `--cp=950` | 繁体中文 Big5 |
| `--cp=936` | 简体中文 GBK |
| `--cp=949` | 韩语 EUC-KR |

- `chiiki.exe` 和 `chiiki.dll` **必须放在同一目录**。

### 示例

```bat
chiiki.exe

:: 指定路径
chiiki.exe "C:\Games\SomeGame.exe"

:: 繁体中文游戏
chiiki.exe --cp=950 "C:\Games\SomeGame.exe"

:: 透传额外参数给游戏
chiiki.exe --cp=936 "C:\Games\SomeGame.exe" -port 8484
```

## 致谢

- https://github.com/InWILL/Locale_Remulator
