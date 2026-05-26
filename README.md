# 🚀 sing-box 自動編譯系統

> 自動檢測並編譯 [reF1nd/sing-box](https://github.com/reF1nd/sing-box) 的 Stable 和 Testing 分支。

## 📦 最新版本狀態 (2026-05-26 10:39 UTC+8)



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

## 📦 文件命名規則

- **打包版本** (`xxx.tar.gz` / `xxx.zip`): 包含 LICENSE 的標準發行版
- **獨立二進制** (`xxx.upx` / `xxx`): 可直接替換執行檔，方便軟路由使用

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
