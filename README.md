# 🚀 sing-box 自動編譯系統

> 自動檢測並編譯 [SagerNet/sing-box](https://github.com/SagerNet/sing-box)、[reF1nd/sing-box](https://github.com/reF1nd/sing-box) 和 [PuerNya/sing-box](https://github.com/PuerNya/sing-box)

## 📦 最新版本狀態 (2026-04-07 04:52 UTC+8)

- ✨ 更新 **[SagerNet_Oldstable](https://github.com/SagerNet/sing-box/tree/oldstable)** 至 `v1.13.6`，發佈於 2026-03-24 [SagerNet_Oldstable v1.13.6]
- ✨ 更新 **[SagerNet_Stable](https://github.com/SagerNet/sing-box/tree/stable)** 至 `v1.13.6`，發佈於 2026-04-06 [SagerNet_Stable v1.13.6]
- ✨ 更新 **[SagerNet_Testing](https://github.com/SagerNet/sing-box/tree/testing)** 至 `v1.14.0-alpha.9`，發佈於 2026-04-06 [SagerNet_Testing v1.14.0-alpha.9]
- ✨ 更新 **[reF1nd_Oldstable](https://github.com/reF1nd/sing-box/tree/reF1nd-oldstable)** 至 `v1.13.5-reF1nd`，發佈於 2026-04-01 [reF1nd_Oldstable v1.13.5-reF1nd]
- ✨ 更新 **[reF1nd_Stable](https://github.com/reF1nd/sing-box/tree/reF1nd-stable)** 至 `v1.13.5-reF1nd`，發佈於 2026-04-01 [reF1nd_Stable v1.13.5-reF1nd]
- ✨ 更新 **[reF1nd_Testing](https://github.com/reF1nd/sing-box/tree/reF1nd-testing)** 至 `v1.14.0-alpha.8-reF1nd`，發佈於 2026-04-01 [reF1nd_Testing v1.14.0-alpha.8-reF1nd]
- ✨ 更新 **[PuerNya_Building](https://github.com/PuerNya/sing-box/tree/building)** 至 `v1.10.0-alpha.29-067c81a7`，發佈於 2024-08-16 [PuerNya_Building v1.10.0-alpha.29-067c81a7]

---

## 📥 快速安裝 (Linux)

使用動態路由自動安裝最新版對應架構：
```bash
bash <(curl -sSL https://github.com/phpr-source/sing-box.json/releases/download/sing-box/install-linux.sh)
```

## 📦 文件命名規則

- **默認版本** (`xxx.tar.gz` / `xxx.zip`): UPX壓縮版（體積小）
- **原始版本** (`xxx-original.tar.gz` / `xxx-original.zip`): 未壓縮版（兼容性好）
- MIPS/ARMv5/v6: 僅提供原始版本（UPX不支持這些架構）

## 🛠️ 支持的版本與特性

| 版本 | 分支 | 平台支持 |
|------|------|---------|
| SagerNet OldStable | oldstable | Linux/Windows/Android (arm64) |
| SagerNet Stable | stable | Linux/Windows/Android (arm64) |
| SagerNet Testing | testing | Linux/Windows/Android (arm64) |
| reF1nd OldStable | reF1nd-oldstable | Linux/Windows/Android (arm64) |
| reF1nd Stable | reF1nd-stable | Linux/Windows/Android (arm64) |
| reF1nd Testing | reF1nd-testing | Linux/Windows/Android (arm64) |
| PuerNya Building | building | Linux/Windows |

## 🔔 Telegram 通知配置
若需啟用 Telegram 推送，請在倉庫 Secrets 中配置：
- `TELEGRAM_BOT_TOKEN`, `CHAT_ID`, `API_ID`, `API_HASH`

[🔗 前往 Releases 下載](https://github.com/phpr-source/sing-box.json/releases/tag/sing-box)

![Build Status](https://img.shields.io/github/actions/workflow/status/phpr-source/sing-box.json/build.yml?branch=main)
