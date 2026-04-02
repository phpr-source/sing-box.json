# 🚀 sing-box 自動編譯系統

> 自動檢測並編譯 [SagerNet/sing-box](https://github.com/SagerNet/sing-box)、[reF1nd/sing-box](https://github.com/reF1nd/sing-box) 和 [PuerNya/sing-box](https://github.com/PuerNya/sing-box)

## 🛠️ 支持的版本與特性

| 版本 | 分支 | 平台支持 |
|------|------|---------|
| SagerNet OldStable | oldstable | Linux/Windows |
| SagerNet Stable | stable | Linux/Windows/Android |
| SagerNet Testing | testing (main) | Linux/Windows/Android |
| reF1nd OldStable | reF1nd-oldstable | Linux/Windows/Android |
| reF1nd Stable | reF1nd-stable | Linux/Windows/Android |
| reF1nd Testing | reF1nd-testing | Linux/Windows/Android |
| PuerNya Building | building | Linux/Windows |

- 架构支持完善 (amd64, arm, mips)
- SFA Android 客戶端同步編譯 (自帶包名偽裝與在線更新劫持)
- 自動動態拉取最新 Tag，使用時間戳控制 Android 版本升級覆蓋
- CGO 環境動態適配，舊工作流自動清理
- 核心二進制文件自動壓縮（Linux 使用 .tar.gz，Windows 使用 .zip，排除 MIPS 架構 UPX 崩潰）

## 🏗️ 编译标签 (Tags)
\`\`\`text
Common: badlinkname,tfogo_checklinkname0,with_gvisor,with_quic,with_dhcp,with_utls,with_wireguard,with_clash_api,with_ech
Android Extra: with_conntrack
\`\`\`

[🔗 前往 Releases 页面下载](https://github.com/phpr-source/sing-box.json/releases/tag/sing-box)
