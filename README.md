# sing-box 自动编译

自动检测并编译 [SagerNet/sing-box](https://github.com/SagerNet/sing-box) 和 [reF1nd/sing-box](https://github.com/reF1nd/sing-box) 的多个版本。

## 支持平台与特性
- 架构支持完善 (amd64, arm, mips)
- SFA Android 客戶端同步編譯 (自帶包名偽裝與在線更新劫持)
- 自動動態拉取最新 Tag，使用時間戳控制 Android 版本升級覆蓋
- CGO 環境動態適配，舊工作流自動清理

## 编译标签
```text
with_gvisor,with_quic,with_dhcp,with_utls,with_wireguard,with_clash_api,with_ech
```

[前往 Releases 页面下载](https://github.com/phpr-source/sing-box.json/releases/tag/sing-box)
