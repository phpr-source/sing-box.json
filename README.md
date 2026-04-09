# 🚀 sing-box 自動編譯系統

> 自動檢測並編譯 [reF1nd/sing-box](https://github.com/reF1nd/sing-box) 的 Stable 和 Testing 分支。

## 📦 最新版本狀態 (2026-04-10 00:54 UTC+8)

- ✨ 更新 **[reF1nd_Stable](https://github.com/reF1nd/sing-box/tree/reF1nd-stable)** 至 `v1.13.6-reF1nd`，發佈於 2026-04-09 [reF1nd_Stable v1.13.6-reF1nd]
- ✨ 更新 **[reF1nd_Testing](https://github.com/reF1nd/sing-box/tree/reF1nd-testing)** 至 `v1.14.0-alpha.9-reF1nd`，發佈於 2026-04-09 [reF1nd_Testing v1.14.0-alpha.9-reF1nd]

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

- **默認版本** (`xxx.tar.gz` / `xxx.zip`): UPX壓縮版（體積小）
- **原始版本** (`xxx-original.tar.gz` / `xxx-original.zip`): 未壓縮版（兼容性好）
- MIPS/ARMv5/v6: 僅提供原始版本（UPX不支持這些架構）

## 🛠️ 支持的版本與特性

| 版本 | 分支 | 平台支持 | Release 標籤 |
|------|------|---------|-------------|
| reF1nd Stable | reF1nd-stable | Linux/Windows/Android | `sing-box-stable` (Latest) |
| reF1nd Testing | reF1nd-testing | Linux/Windows/Android | `sing-box-testing` (Pre-release) |

## 🔔 Telegram 通知配置
若需啟用 Telegram 推送，請在倉庫 Secrets 中配置：
- `TELEGRAM_BOT_TOKEN`, `CHAT_ID`, `API_ID`, `API_HASH`

[🔗 前往 Releases 下載](https://github.com/phpr-source/sing-box.json/releases)

![Build Status](https://img.shields.io/github/actions/workflow/status/phpr-source/sing-box.json/build-sing-box.yml?branch=main)
