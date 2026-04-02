# sing-box 自动编译

基于 [SagerNet/sing-box](https://github.com/SagerNet/sing-box) 和 [reF1nd/sing-box](https://github.com/reF1nd/sing-box)

## 快速下载

\`\`\`bash
# SagerNet Stable (amd64-v3)
wget https://github.com/phpr-source/sing-box.json/releases/download/sing-box/sing-box-stable-linux-amd64-v3.tar.gz
tar -xzf sing-box-stable-linux-amd64-v3.tar.gz

# reF1nd Stable (amd64-v3)
wget https://github.com/phpr-source/sing-box.json/releases/download/sing-box/sing-box-ref1nd-stable-linux-amd64-v3.tar.gz
tar -xzf sing-box-ref1nd-stable-linux-amd64-v3.tar.gz
\`\`\`

## 支持架构

**桌面端:** Linux (amd64-v1/v3, arm64, armv7, mips, mipsle), Windows (amd64-v1/v3, arm64)
**移动端:** Android arm64-v8a (reF1nd版本)

## 配置

- Go: ~1.25.8 | NDK: r29 | Tags: clash_api, gvisor, quic, utls, wireguard
- 压缩: UPX (--best --lzma) + tar.gz
- 更新频率: 每6小时

---
*由 GitHub Actions 维护 | $(date -u '+%Y-%m-%d %H:%M UTC')*
