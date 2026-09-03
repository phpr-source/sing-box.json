# 🚀 sing-box 自動編譯系統

> 自動檢測並編譯 [reF1nd/sing-box](https://github.com/reF1nd/sing-box) 的 Stable 和 Testing 分支。

## 📦 最新版本狀態 (2026-09-03 10:31 UTC+8)


---

## 📥 快速安裝 (Linux)

使用動態路由自動安裝最新版對應架構：
```bash
bash <(curl -sSL https://github.com/phpr-source/sing-box.json/releases/download/sing-box-stable/install-linux.sh)
```

若要安裝 Testing 版本，請指定參數：
```bash
bash <(curl -sSL https://github.com/phpr-source/sing-box.json/releases/download/sing-box-testing/install-linux.sh) testing
```

## 📱 Android SFA 下載

SFA APK 已附在 Release Assets 中，請直接前往：

- Stable：[sing-box-stable Release](https://github.com/phpr-source/sing-box.json/releases/tag/sing-box-stable)
- Testing：[sing-box-testing Release](https://github.com/phpr-source/sing-box.json/releases/tag/sing-box-testing)

在 Assets 區塊中選擇符合你裝置架構的 APK：

| 架構 | 建議 |
|---|---|
| `arm64-v8a` | 近五年主流 Android 手機 |
| `armeabi-v7a` | 較舊 32-bit 手機 |
| `x86_64` / `x86` | 模擬器或 Intel Android 裝置 |
| `universal` | 全架構通用包，體積最大 |
| `legacy-android-5-*` | Android 5.x 舊系統專用 |

## 📦 文件命名規則

- **打包版本** (`xxx.tar.gz` / `xxx.zip`): 包含 LICENSE 的標準發行版
- **UPX 壓縮版** (`xxx-upx.tar.gz`): 經 UPX 壓縮的精簡版，適合小閃存設備

## 🛠️ 支持的版本與特性

| 版本 | 分支 | 平台支持 | Release 標籤 |
|------|------|---------|-------------|
| reF1nd Stable | reF1nd-stable | Linux/Windows/macOS/Android | `sing-box-stable` (Latest) |
| reF1nd Testing | reF1nd-testing | Linux/Windows/macOS/Android | `sing-box-testing` (Pre-release) |

## 🔔 Telegram 通知配置
若需啟用 Telegram 推送，請在倉庫 Secrets 中配置：
- `TELEGRAM_BOT_TOKEN`, `CHAT_ID`, `API_ID`, `API_HASH`

[🔗 前往 Releases 下載](https://github.com/phpr-source/sing-box.json/releases)

![Build Status](https://img.shields.io/github/actions/workflow/status/phpr-source/sing-box.json/build-sing-box.yml?branch=main)
