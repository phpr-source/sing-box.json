# sing-box 自动编译

自动检测并编译 [SagerNet/sing-box](https://github.com/SagerNet/sing-box) 和 [reF1nd/sing-box](https://github.com/reF1nd/sing-box) 的多个版本。

## 支持平台与特性
- 架构支持完善 (amd64, arm, mips)
- SFA Android 客戶端同步編譯
- 自動動態拉取最新 Tag (取代脆弱的 API 檢測)
- reF1nd 分支默認合併防中斷與日誌優化補丁

## 编译标签
```text
with_gvisor,with_quic,with_dhcp,with_utls,with_wireguard,with_clash_api,with_ech
```

[前往 Releases 页面下载](https://github.com/phpr-source/sing-box.json/releases/tag/sing-box)
