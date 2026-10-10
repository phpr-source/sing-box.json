# 🚀 sing-box 自動編譯系統

> 自動檢測並編譯 [reF1nd/sing-box](https://github.com/reF1nd/sing-box) 的 Stable 和 Testing 分支。

## 📦 最新版本狀態 (2026-10-10 14:23 UTC+8)

- ✨ 更新 **[reF1nd_Stable](https://github.com/reF1nd/sing-box/tree/reF1nd-stable)** 至 `v1.14.3-reF1nd`，發佈於 2026-10-10 [reF1nd_Stable v1.14.3-reF1nd]
- ✨ 更新 **[reF1nd_Testing](https://github.com/reF1nd/sing-box/tree/reF1nd-testing)** 至 `v1.15.0-alpha.11-reF1nd`，發佈於 2026-10-09 [reF1nd_Testing v1.15.0-alpha.11-reF1nd]
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

`sing-box-<版本>-<系統>-<架構>[-變體][-upx].<副檔名>`

- **變體（僅 Linux）**：`glibc`（動態鏈接，兼容性最好）/ `musl`（靜態鏈接，適合 OpenWrt 等嵌入式）/
  `purego`（純 Go 無 CGO，隨包附 `libcronet.so`，naive 可用）
- **架構後綴**：`amd64v3` 要求 AVX2（N100/新酷睿/Zen+）；無後綴 amd64 兼容老設備；
  `legacy-macos-10.13` 為 macOS 10.13 High Sierra 專用
- **打包版本** (`xxx.tar.gz` / `xxx.zip`): 包含 LICENSE 的標準發行版
- **UPX 壓縮版** (`xxx-upx.tar.gz`): 經 UPX 壓縮的精簡版，適合小閃存設備
  （啟動稍慢，個別殺軟可能誤報，常規使用請選標準版；`install-linux.sh` 自動選標準版）

## 🔐 完整性校驗

每個 Release 提供三份校驗單（均為平鋪檔案名，可直接 `sha256sum -c`）：

| 檔案 | 覆蓋範圍 |
|---|---|
| `SHA256SUMS.txt` | 全部 tar.gz / zip 歸檔 + install-linux.sh 所屬歸檔 |
| `SHA256SUMS-SFA-<target>.txt` | 全部 SFA APK 與元數據 |
| `SHA256SUMS-Apple-<target>.txt` | SFI .tipa 與 SFM .zip |

校驗示例：

```bash
sha256sum -c SHA256SUMS-SFA-reF1nd_Stable.txt
```

## 🍎 Apple 客戶端（SFI / SFM）

- **SFI** (`SFI-<版本>.tipa`)：iOS 客戶端，TrollStore 或越獄環境安裝（ldid 簽名，非 App Store 分發）
- **SFM** (`SFM-<版本>.zip`)：macOS 客戶端（.app 打包 zip，解壓後拖入「應用程式」）

> Apple 客戶端為本倉附加構建（上游官方不發布）；Testing 渠道因 libbox API era 檢查可能自動跳過。

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
