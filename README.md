# 🚀 sing-box 自動編譯系統

> 自動檢測並編譯 [SagerNet/sing-box](https://github.com/SagerNet/sing-box)、[reF1nd/sing-box](https://github.com/reF1nd/sing-box) 和 [PuerNya/sing-box](https://github.com/PuerNya/sing-box)

## 📦 最新版本狀態 (2026-04-02 15:54 UTC)


- ✨ 更新 **[SagerNet_Oldstable](https://github.com/SagerNet/sing-box/tree/oldstable)** 至 `v1.12.25-11077fd3`，發佈於 2026-03-24
- ✨ 更新 **[SagerNet_Stable](https://github.com/SagerNet/sing-box/tree/stable)** 至 `v1.13.5-354b4b04`，發佈於 2026-04-01
- ✨ 更新 **[SagerNet_Testing](https://github.com/SagerNet/sing-box/tree/testing)** 至 `v1.13.5-e52c0320`，發佈於 2026-04-01
- ✨ 更新 **[reF1nd_Oldstable](https://github.com/reF1nd/sing-box/tree/reF1nd-oldstable)** 至 `v1.12.25-a1f520de`，發佈於 2026-04-01
- ✨ 更新 **[reF1nd_Stable](https://github.com/reF1nd/sing-box/tree/reF1nd-stable)** 至 `v1.13.5-09d02469`，發佈於 2026-04-01
- ✨ 更新 **[reF1nd_Testing](https://github.com/reF1nd/sing-box/tree/reF1nd-testing)** 至 `v1.14.0-alpha.8-52df4634`，發佈於 2026-04-01
- ✨ 更新 **[PuerNya_Building](https://github.com/PuerNya/sing-box/tree/building)** 至 `v1.10.0-alpha.29-067c81a7`，發佈於 2024-08-16

---

## 📥 快速安裝 (Linux AMD64)

```bash
# 獲取 SagerNet_Stable 示例
curl -LO https://github.com/phpr-source/sing-box.json/releases/download/sing-box/sing-box-SagerNet_Stable-linux-amd64-v3.tar.gz
tar -xzf sing-box-SagerNet_Stable-linux-amd64-v3.tar.gz
chmod +x sing-box
sudo mv sing-box /usr/local/bin/
```

## 📦 文件命名規則

- **默認版本** (`xxx.tar.gz` / `xxx.zip`): 
- 大多數架構: 經過 UPX 壓縮，體積小，推薦大多數用戶使用。
- MIPS/ARMv5/v6: 原始二進制（因 UPX 不支持這些架構）。
- **完整原始版** (`xxx-original.tar.gz` / `xxx-original.zip`): 未經壓縮的原始二進制，適合殺毒軟件誤報或特殊環境（僅非 MIPS 架構提供）。

## 🛠️ 支持的版本與特性

| 版本 | 分支 | 平台支持 |
|------|------|---------|
| SagerNet OldStable | oldstable | Linux/Windows/Android |
| SagerNet Stable | stable | Linux/Windows/Android |
| SagerNet Testing | testing | Linux/Windows/Android |
| reF1nd OldStable | reF1nd-oldstable | Linux/Windows/Android |
| reF1nd Stable | reF1nd-stable | Linux/Windows/Android |
| reF1nd Testing | reF1nd-testing | Linux/Windows/Android |
| PuerNya Building | building | Linux/Windows |

- 架构支持完善 (amd64, arm, mips)
- SFA Android 客戶端同步編譯 (自帶包名偽裝與在線更新劫持)
- 自動動態拉取最新 Tag，使用時間戳控制 Android 版本升級覆蓋
- CGO 環境動態適配，舊工作流自動清理
- 智能雙版本構建策略，動態提供壓縮與未壓縮核心

## 🔔 Telegram 通知配置
若需啟用 Telegram 推送，請在倉庫的 Secrets 中配置以下內容：
- `TELEGRAM_BOT_TOKEN`: 你的 Bot Token (由 @BotFather 獲取)
- `CHAT_ID`: 接收消息的用戶或頻道 ID
- `API_ID` & `API_HASH`: (必須) 請在 [my.telegram.org](https://my.telegram.org) 申請獲取

## 🏗️ 编译标签 (Tags)
```text
SagerNet: with_gvisor,with_quic,with_dhcp,with_utls,with_clash_api,with_wireguard
reF1nd: with_gvisor,with_quic,with_dhcp,with_utls,with_clash_api
PuerNya: with_quic,with_dhcp,with_wireguard,with_shadowsocksr,with_ech,with_utls,with_clash_api,with_gvisor
Android Extra: with_conntrack
```

[🔗 前往 Releases 页面下载](https://github.com/phpr-source/sing-box.json/releases/tag/sing-box)
