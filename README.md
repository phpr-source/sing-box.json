# 🚀 sing-box 自动编译 (2026 V4)

> 基于 [SagerNet/sing-box](https://github.com/SagerNet/sing-box) 和 [reF1nd/sing-box](https://github.com/reF1nd/sing-box) 的自动化编译

## 📥 快速下载

### SagerNet/sing-box

\`\`\`bash
# Stable (amd64-v3, 推荐)
wget https://github.com/phpr-source/sing-box.json/releases/download/sing-box/sing-box-stable-linux-amd64-v3.tar.gz
tar -xzf sing-box-stable-linux-amd64-v3.tar.gz

# Testing (amd64-v3)
wget https://github.com/phpr-source/sing-box.json/releases/download/sing-box/sing-box-testing-linux-amd64-v3.tar.gz
tar -xzf sing-box-testing-linux-amd64-v3.tar.gz
\`\`\`

### reF1nd/sing-box

\`\`\`bash
# Stable (amd64-v3)
wget https://github.com/phpr-source/sing-box.json/releases/download/sing-box/sing-box-ref1nd-stable-linux-amd64-v3.tar.gz
tar -xzf sing-box-ref1nd-stable-linux-amd64-v3.tar.gz

# Testing (amd64-v3)
wget https://github.com/phpr-source/sing-box.json/releases/download/sing-box/sing-box-ref1nd-testing-linux-amd64-v3.tar.gz
tar -xzf sing-box-ref1nd-testing-linux-amd64-v3.tar.gz
\`\`\`

## 📋 支持的架构

**桌面端:**
- Linux: amd64-v1, amd64-v3, arm64, armv5, armv6, armv7, mips, mipsle
- Windows: amd64-v1, amd64-v3, arm64

**移动端:**
- Android: arm64-v8a (来自 reF1nd-sing-box-for-android)

## ⚙️ 配置详情

- **Go版本:** ~1.25.8
- **Android NDK:** r29
- **Build Tags:** badlinkname, tfogo_checklinkname0, with_clash_api, with_gvisor, with_quic, with_utls, with_wireguard
- **Android Extra Tags:** with_conntrack
- **压缩:** UPX (Linux) + tar.gz

## 🔄 更新频率

每 6 小时自动检查更新

---

*由 GitHub Actions 自动维护 | 最后更新: $(date -u '+%Y-%m-%d %H:%M UTC')*
